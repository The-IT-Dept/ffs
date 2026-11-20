// Package exposure derives, per workload owner, how it is exposed to the internet, how privileged
// its pods are, and what its service account may do. It reads from the manager cache.
package exposure

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/inventory"
	"github.com/the-it-dept/ffs/internal/model"
)

// Resolver implements inventory.ContextResolver.
type Resolver struct {
	c   client.Reader
	cfg config.ExposureConfig

	// kinds are the Gateway API kinds Register set up, each at the version the cluster serves; nil
	// before Register, when every kind and version is tried.
	kinds atomic.Pointer[gatewayKinds]

	mu         sync.Mutex      // serialises discovery
	registered map[string]bool // Gateway API kinds with change handlers
	routes     [][]routeKind   // the route kinds registered, one version each
	grant      *grantKind      // the ReferenceGrant version registered; nil while none is
	grantsHeld bool            // ReferenceGrants are served but ffs may not read them (logged once)
}

// gatewayKinds are the route and ReferenceGrant kinds Context reads.
type gatewayKinds struct {
	routes [][]routeKind
	grants []grantKind
}

var _ inventory.ContextResolver = (*Resolver)(nil)

// New returns a Resolver reading from c (the manager cache).
func New(c client.Reader, cfg config.ExposureConfig) *Resolver {
	return &Resolver{c: c, cfg: cfg, registered: map[string]bool{}}
}

// readKinds returns the route kinds (per kind, the versions to try) and the ReferenceGrant versions
// Context reads: the ones Register set up, or before Register every one.
func (r *Resolver) readKinds() ([][]routeKind, []grantKind) {
	if k := r.kinds.Load(); k != nil {
		return k.routes, k.grants
	}
	return routeKinds, grantKinds
}

// Context composes exposure, privilege and service-account power for w. Exposure lists every way in,
// internal entry points included; Exposed and ExposurePaths count only the ones not marked internal.
func (r *Resolver) Context(ctx context.Context, w *inventory.Workload) (model.WorkloadContext, error) {
	raw, err := r.exposureEdges(ctx, w)
	if err != nil {
		return model.WorkloadContext{}, err
	}
	edges := sortEdges(raw)
	paths := pathsOf(edges)
	priv := privilegeReasons(podSpecs(w))
	sa, err := r.serviceAccountPower(ctx, w.Ref.Namespace, w.ServiceAccount)
	if err != nil {
		return model.WorkloadContext{}, err
	}
	return model.WorkloadContext{
		Exposed: len(paths) > 0, ExposurePaths: paths,
		Privileged: len(priv) > 0, PrivilegeReasons: priv,
		PowerfulSA: len(sa) > 0, SAReasons: sa,
		Exposure: edges,
	}, nil
}

// informerSource is the part of the manager's cache Register uses.
type informerSource interface {
	GetInformer(ctx context.Context, obj client.Object, opts ...cache.InformerGetOption) (cache.Informer, error)
	IndexField(ctx context.Context, obj client.Object, field string, extractValue client.IndexerFunc) error
}

// discovery is what Register sets up with: the manager's cache, its REST mapper, an uncached reader
// for the ReferenceGrant access check, and the owners' change callback.
type discovery struct {
	cache    informerSource
	mapper   meta.RESTMapper
	reader   client.Reader
	onChange func(namespace string)
}

// rediscoverEvery is how often the served Gateway API kinds are checked again, so kinds installed
// after ffs started get change handlers without a restart.
const rediscoverEvery = 5 * time.Minute

// Register adds change handlers to the informers the resolver reads. A change queues the owners of
// the object's namespace through onChange; cluster-scoped objects (IngressClass, Gateway,
// GatewayClass, ClusterRole, ClusterRoleBinding) queue "" (every owner), and a route also queues the
// namespaces of its backend Services. Gateway API kinds the cluster does not serve are skipped, and
// checked for again every rediscoverEvery while the manager runs; a kind found later gets its handlers
// then, and its existing objects queue their owners as they enter the cache. ReferenceGrants are read
// only when ffs is allowed to list them.
func (r *Resolver) Register(ctx context.Context, mgr manager.Manager, onChange func(namespace string)) error {
	d := discovery{cache: mgr.GetCache(), mapper: mgr.GetRESTMapper(), reader: mgr.GetAPIReader(), onChange: onChange}
	if err := r.register(ctx, d); err != nil {
		return err
	}
	return mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		r.rediscover(ctx, d, rediscoverEvery)
		return nil
	}))
}

// rediscover runs discover every interval until ctx is done; a failure is logged and retried at the
// next interval.
func (r *Resolver) rediscover(ctx context.Context, d discovery, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := r.discover(ctx, d); err != nil && ctx.Err() == nil {
				logf.FromContext(ctx).WithName("exposure").Error(err, "checking for Gateway API kinds installed since start failed")
			}
		}
	}
}

func (r *Resolver) register(ctx context.Context, d discovery) error {
	for _, o := range []struct {
		obj     client.Object
		cluster bool
	}{
		{&corev1.Service{}, false}, {&networkingv1.Ingress{}, false}, {&networkingv1.IngressClass{}, true},
		{&rbacv1.Role{}, false}, {&rbacv1.ClusterRole{}, true},
		{&rbacv1.RoleBinding{}, false}, {&rbacv1.ClusterRoleBinding{}, true},
	} {
		if err := addHandler(ctx, d.cache, o.obj, objectHandler(d.onChange, o.cluster)); err != nil {
			return err
		}
	}
	return r.discover(ctx, d)
}

// discover sets up the Gateway API kinds the cluster serves that have no handlers yet: Gateway and
// GatewayClass; each route kind at the first version served, with its RouteBackendIndex; and
// ReferenceGrants at the first version served, once ffs may list them. It then publishes the route
// and ReferenceGrant kinds for Context.
func (r *Resolver) discover(ctx context.Context, d discovery) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	served := func(kind, version string) bool {
		_, err := d.mapper.RESTMapping(schema.GroupKind{Group: gatewayGroup, Kind: kind}, version)
		return err == nil || !meta.IsNoMatchError(err)
	}
	defer r.publish()
	for _, o := range []struct {
		kind string
		obj  client.Object
	}{{"Gateway", &gatewayv1.Gateway{}}, {"GatewayClass", &gatewayv1.GatewayClass{}}} {
		if r.registered[o.kind] || !served(o.kind, "v1") {
			continue
		}
		if err := addHandler(ctx, d.cache, o.obj, objectHandler(d.onChange, true)); err != nil {
			return err
		}
		r.registered[o.kind] = true
	}
	for _, versions := range routeKinds {
		name := versions[0].name
		if r.registered[name] {
			continue
		}
		for _, k := range versions {
			if !served(k.name, k.version) {
				continue
			}
			if err := d.cache.IndexField(ctx, k.newObj(), RouteBackendIndex, k.index); err != nil {
				return fmt.Errorf("exposure: index %s %s: %w", k.name, k.version, err)
			}
			if err := addHandler(ctx, d.cache, k.newObj(), routeHandler(d.onChange, k.index)); err != nil {
				return err
			}
			r.registered[name] = true
			r.routes = append(r.routes, []routeKind{k})
			break
		}
	}
	if r.grant == nil {
		return r.discoverGrants(ctx, d, served)
	}
	return nil
}

// discoverGrants sets up ReferenceGrants at the first version the cluster serves, once an uncached
// list shows that ffs may read them; until then routes from other namespaces are not counted, and a
// later discovery tries again.
func (r *Resolver) discoverGrants(ctx context.Context, d discovery, served func(kind, version string) bool) error {
	log := logf.FromContext(ctx).WithName("exposure")
	for i := range grantKinds {
		k := grantKinds[i]
		if !served("ReferenceGrant", k.version) {
			continue
		}
		if err := k.probe(ctx, d.reader); err != nil {
			switch {
			case !apierrors.IsForbidden(err):
				log.Error(err, "listing ReferenceGrants failed; routes to a Service from another namespace are not counted as exposure yet")
			case !r.grantsHeld:
				r.grantsHeld = true
				log.Info("ffs may not list ReferenceGrants; routes to a Service from another namespace are not counted as " +
					"exposure until it may")
			}
			return nil
		}
		if err := addHandler(ctx, d.cache, k.newObj(), objectHandler(d.onChange, false)); err != nil {
			return err
		}
		r.grant, r.grantsHeld = &k, false
		return nil
	}
	return nil
}

// publish makes the registered route and ReferenceGrant kinds the ones Context reads; r.mu is held.
func (r *Resolver) publish() {
	k := &gatewayKinds{routes: append([][]routeKind(nil), r.routes...)}
	if r.grant != nil {
		k.grants = []grantKind{*r.grant}
	}
	r.kinds.Store(k)
}

func addHandler(ctx context.Context, c informerSource, obj client.Object, h toolscache.ResourceEventHandler) error {
	inf, err := c.GetInformer(ctx, obj)
	if err != nil {
		return fmt.Errorf("exposure: informer %T: %w", obj, err)
	}
	_, err = inf.AddEventHandler(h)
	return err
}

// objectOf unwraps a deleted object's final state.
func objectOf(obj any) (client.Object, bool) {
	if t, ok := obj.(toolscache.DeletedFinalStateUnknown); ok {
		obj = t.Obj
	}
	o, ok := obj.(client.Object)
	return o, ok
}

// objectHandler queues the owners of the object's namespace, or every owner for a cluster-scoped kind.
func objectHandler(onChange func(string), clusterScoped bool) toolscache.ResourceEventHandler {
	fire := func(obj any) {
		o, ok := objectOf(obj)
		if !ok {
			return
		}
		if clusterScoped {
			onChange("")
			return
		}
		onChange(o.GetNamespace())
	}
	return toolscache.ResourceEventHandlerFuncs{AddFunc: fire, UpdateFunc: func(_, n any) { fire(n) }, DeleteFunc: fire}
}

// routeHandler queues the owners of a route's namespace and of its backend Services' namespaces,
// before and after an update.
func routeHandler(onChange func(string), backends client.IndexerFunc) toolscache.ResourceEventHandler {
	fire := func(objs ...any) {
		seen := map[string]bool{}
		for _, obj := range objs {
			o, ok := objectOf(obj)
			if !ok {
				continue
			}
			for _, ns := range append([]string{o.GetNamespace()}, backends(o)...) {
				if !seen[ns] {
					seen[ns] = true
					onChange(ns)
				}
			}
		}
	}
	return toolscache.ResourceEventHandlerFuncs{
		AddFunc:    func(o any) { fire(o) },
		UpdateFunc: func(o, n any) { fire(o, n) },
		DeleteFunc: func(o any) { fire(o) },
	}
}
