package exposure

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/cache/informertest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllertest"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/the-it-dept/ffs/internal/config"
)

// changes records the namespaces a resolver's handlers queue.
type changes struct {
	mu  sync.Mutex
	got []string
}

func (c *changes) on(ns string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.got = append(c.got, ns)
}

// take returns the namespaces queued since the last take, sorted.
func (c *changes) take() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.got
	c.got = nil
	slices.Sort(out)
	return out
}

func gwKind(version, kind string) schema.GroupVersionKind {
	return schema.GroupVersionKind{Group: gatewayGroup, Version: version, Kind: kind}
}

// servedMapper is a REST mapper that serves the given Gateway API kinds at their versions.
func servedMapper(kinds ...schema.GroupVersionKind) *meta.DefaultRESTMapper {
	m := meta.NewDefaultRESTMapper(nil)
	for _, k := range kinds {
		m.Add(k, meta.RESTScopeNamespace)
	}
	return m
}

// forbidden is an uncached reader whose every list is refused, as when the RBAC lacks the kind.
type forbidden struct{ client.Reader }

func (forbidden) List(context.Context, client.ObjectList, ...client.ListOption) error {
	return apierrors.NewForbidden(schema.GroupResource{Group: gatewayGroup, Resource: "referencegrants"}, "", nil)
}

func informer(t *testing.T, fi *informertest.FakeInformers, obj client.Object) *controllertest.FakeInformer {
	t.Helper()
	i, err := fi.FakeInformerFor(context.Background(), obj)
	require.NoError(t, err)
	return i
}

// routeVersions names the route kinds Context reads, as "Kind/version".
func routeVersions(r *Resolver) []string {
	kinds, _ := r.readKinds()
	var out []string
	for _, versions := range kinds {
		for _, k := range versions {
			out = append(out, k.name+"/"+k.version)
		}
	}
	slices.Sort(out)
	return out
}

// TestRegister_QueuesNamespaces covers the change handlers: namespaced objects queue their namespace,
// cluster-scoped ones every owner, a route its own namespace and its backends', and a ReferenceGrant
// its namespace. Gateway API kinds the cluster does not serve get no informer, and Context reads only
// the route kinds set up, each at the version served.
func TestRegister_QueuesNamespaces(t *testing.T) {
	ctx := context.Background()
	s := testScheme(t, true)
	fi := &informertest.FakeInformers{Scheme: s}
	mapper := servedMapper(gwKind("v1", "Gateway"), gwKind("v1", "HTTPRoute"),
		gwKind("v1alpha2", "TLSRoute"), gwKind("v1", "ReferenceGrant"))
	var ch changes
	r := New(nil, config.ExposureConfig{})
	require.NoError(t, r.register(ctx, discovery{cache: fi, mapper: mapper, reader: newClient(t, s), onChange: ch.on}))

	informer(t, fi, &corev1.Service{}).Add(svc(corev1.ServiceTypeClusterIP, appNetbox))
	informer(t, fi, &networkingv1.Ingress{}).Add(ing(str("nginx"), ""))
	require.Equal(t, []string{"netbox", "netbox"}, ch.take())
	informer(t, fi, &rbacv1.ClusterRole{}).Add(clusterRole("r"))
	informer(t, fi, &networkingv1.IngressClass{}).Add(&networkingv1.IngressClass{ObjectMeta: metav1.ObjectMeta{Name: "nginx"}})
	informer(t, fi, &gatewayv1.Gateway{}).Add(gw("public", "edge", "cilium"))
	require.Equal(t, []string{"", "", ""}, ch.take())

	pub := parent("public", "edge")
	informer(t, fi, &gatewayv1.HTTPRoute{}).Add(crossRoute(pub))
	require.Equal(t, []string{"edge", "netbox"}, ch.take(), "the route's namespace and its backend's")
	moved := crossRoute(pub)
	other := gatewayv1.Namespace("shop")
	moved.Spec.Rules[0].BackendRefs[0].Namespace = &other
	informer(t, fi, &gatewayv1.HTTPRoute{}).Update(crossRoute(pub), moved)
	require.Equal(t, []string{"edge", "netbox", "shop"}, ch.take(), "the backends before and after the change")
	informer(t, fi, &gatewayv1.ReferenceGrant{}).Add(grant("HTTPRoute", "edge", ""))
	require.Equal(t, []string{"netbox"}, ch.take())

	for _, gvk := range []schema.GroupVersionKind{gwKind("v1", "GatewayClass"),
		gwKind("v1", "GRPCRoute"), gwKind("v1", "TLSRoute"),
		gwKind("v1", "TCPRoute"), gwKind("v1alpha2", "TCPRoute")} {
		require.NotContains(t, fi.InformersByGVK, gvk, "not served")
	}
	require.Equal(t, []string{"HTTPRoute/v1", "TLSRoute/v1alpha2"}, routeVersions(r))
	_, grants := r.readKinds()
	require.Len(t, grants, 1)
	require.Equal(t, "v1", grants[0].version)
}

// TestRegister_ReferenceGrantsNeedAccess: ReferenceGrants ffs may not list are not watched (an informer
// would never sync), so routes from other namespaces do not count; once it may, a later discovery
// sets them up.
func TestRegister_ReferenceGrantsNeedAccess(t *testing.T) {
	ctx := context.Background()
	s := testScheme(t, true)
	fi := &informertest.FakeInformers{Scheme: s}
	mapper := servedMapper(gwKind("v1", "HTTPRoute"), gwKind("v1", "ReferenceGrant"))
	var ch changes
	r := New(nil, config.ExposureConfig{})
	d := discovery{cache: fi, mapper: mapper, reader: forbidden{}, onChange: ch.on}
	require.NoError(t, r.register(ctx, d))
	require.NotContains(t, fi.InformersByGVK, gwKind("v1", "ReferenceGrant"))
	_, grants := r.readKinds()
	require.Empty(t, grants)

	d.reader = newClient(t, s)
	require.NoError(t, r.discover(ctx, d))
	require.Contains(t, fi.InformersByGVK, gwKind("v1", "ReferenceGrant"))
	_, grants = r.readKinds()
	require.Len(t, grants, 1)
	require.Equal(t, []string{"HTTPRoute/v1"}, routeVersions(r), "a kind is set up once")
}

// lockedMapper is a REST mapper whose served kinds may change while discovery reads it.
type lockedMapper struct {
	meta.RESTMapper // only RESTMapping is used
	mu              sync.Mutex
	m               *meta.DefaultRESTMapper
}

func (l *lockedMapper) add(gvk schema.GroupVersionKind) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.m.Add(gvk, meta.RESTScopeNamespace)
}

func (l *lockedMapper) RESTMapping(gk schema.GroupKind, versions ...string) (*meta.RESTMapping, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.m.RESTMapping(gk, versions...)
}

// TestRediscover_LateGatewayKinds (F83): Gateway API kinds installed after ffs started are found by
// the periodic discovery and get their change handlers without a restart.
func TestRediscover_LateGatewayKinds(t *testing.T) {
	s := testScheme(t, true)
	fi := &informertest.FakeInformers{Scheme: s}
	lm := &lockedMapper{m: servedMapper()}
	var ch changes
	r := New(nil, config.ExposureConfig{})
	d := discovery{cache: fi, mapper: lm, reader: newClient(t, s), onChange: ch.on}
	require.NoError(t, r.register(context.Background(), d))
	require.Empty(t, routeVersions(r), "no Gateway API at start")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.rediscover(ctx, d, 10*time.Millisecond)
	}()
	lm.add(gwKind("v1", "Gateway"))
	lm.add(gwKind("v1", "HTTPRoute"))
	require.Eventually(t, func() bool { return slices.Equal(routeVersions(r), []string{"HTTPRoute/v1"}) }, 5*time.Second,
		5*time.Millisecond)
	cancel()
	<-done

	informer(t, fi, &gatewayv1.HTTPRoute{}).Add(crossRoute(parent("public", "edge")))
	require.Equal(t, []string{"edge", "netbox"}, ch.take())
	informer(t, fi, &gatewayv1.Gateway{}).Add(gw("public", "edge", "cilium"))
	require.Equal(t, []string{""}, ch.take())
}
