// Package exposure derives, per workload owner, how it is exposed to the internet, how privileged
// its pods are, and what its service account may do. It reads from the manager cache.
package exposure

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/inventory"
	"github.com/the-it-dept/ffs/internal/model"
)

// Resolver implements inventory.ContextResolver.
type Resolver struct {
	c   client.Reader
	cfg config.ExposureConfig
}

var _ inventory.ContextResolver = (*Resolver)(nil)

// New returns a Resolver reading from c (the manager cache).
func New(c client.Reader, cfg config.ExposureConfig) *Resolver { return &Resolver{c: c, cfg: cfg} }

// Context composes exposure, privilege and service-account power for w.
func (r *Resolver) Context(ctx context.Context, w *inventory.Workload) (model.WorkloadContext, error) {
	paths, err := r.exposurePaths(ctx, w)
	if err != nil {
		return model.WorkloadContext{}, err
	}
	priv := privilegeReasons(podSpecs(w))
	sa, err := r.serviceAccountPower(ctx, w.Ref.Namespace, w.ServiceAccount)
	if err != nil {
		return model.WorkloadContext{}, err
	}
	return model.WorkloadContext{
		Exposed: len(paths) > 0, ExposurePaths: paths,
		Privileged: len(priv) > 0, PrivilegeReasons: priv,
		PowerfulSA: len(sa) > 0, SAReasons: sa,
	}, nil
}

// Register adds change handlers to the informers the resolver reads. A change queues the owners of
// the object's namespace through onChange; cluster-scoped objects (IngressClass, Gateway,
// GatewayClass, ClusterRole, ClusterRoleBinding) queue "" (every owner). Gateway API kinds the
// cluster does not serve are skipped.
func (r *Resolver) Register(ctx context.Context, mgr manager.Manager, onChange func(namespace string)) error {
	h := func(clusterScoped bool) toolscache.ResourceEventHandler {
		fire := func(obj any) {
			if t, ok := obj.(toolscache.DeletedFinalStateUnknown); ok {
				obj = t.Obj
			}
			o, ok := obj.(metav1.Object)
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
	add := func(obj client.Object, clusterScoped bool) error {
		inf, err := mgr.GetCache().GetInformer(ctx, obj)
		if err != nil {
			return fmt.Errorf("exposure: informer %T: %w", obj, err)
		}
		_, err = inf.AddEventHandler(h(clusterScoped))
		return err
	}
	for _, o := range []struct {
		obj     client.Object
		cluster bool
	}{
		{&corev1.Service{}, false}, {&networkingv1.Ingress{}, false}, {&networkingv1.IngressClass{}, true},
		{&rbacv1.Role{}, false}, {&rbacv1.ClusterRole{}, true},
		{&rbacv1.RoleBinding{}, false}, {&rbacv1.ClusterRoleBinding{}, true},
	} {
		if err := add(o.obj, o.cluster); err != nil {
			return err
		}
	}

	served := func(kind, version string) bool {
		_, err := mgr.GetRESTMapper().RESTMapping(schema.GroupKind{Group: gatewayGroup, Kind: kind}, version)
		return err == nil || !meta.IsNoMatchError(err)
	}
	for _, o := range []struct {
		kind    string
		v1      client.Object
		alpha   client.Object // v1alpha2 fallback, nil when the kind is v1 only
		cluster bool
	}{
		{"Gateway", &gatewayv1.Gateway{}, nil, true},
		{"GatewayClass", &gatewayv1.GatewayClass{}, nil, true},
		{"HTTPRoute", &gatewayv1.HTTPRoute{}, nil, false},
		{"GRPCRoute", &gatewayv1.GRPCRoute{}, nil, false},
		{"TLSRoute", &gatewayv1.TLSRoute{}, &gatewayv1alpha2.TLSRoute{}, false},
		{"TCPRoute", &gatewayv1.TCPRoute{}, &gatewayv1alpha2.TCPRoute{}, false},
		{"UDPRoute", &gatewayv1.UDPRoute{}, &gatewayv1alpha2.UDPRoute{}, false},
	} {
		switch {
		case served(o.kind, "v1"):
			if err := add(o.v1, o.cluster); err != nil {
				return err
			}
		case o.alpha != nil && served(o.kind, "v1alpha2"):
			if err := add(o.alpha, o.cluster); err != nil {
				return err
			}
		}
	}
	return nil
}
