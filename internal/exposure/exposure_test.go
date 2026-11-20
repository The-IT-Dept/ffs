package exposure

import (
	"context"
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/inventory"
	"github.com/the-it-dept/ffs/internal/model"
)

func testScheme(t *testing.T, gateway bool) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if gateway {
		if err := AddToScheme(s); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

// newClient is a fake reader over objs with RouteBackendIndex on every route kind s knows, as the
// manager's cache has after Register.
func newClient(t *testing.T, s *runtime.Scheme, objs ...client.Object) client.Client {
	t.Helper()
	b := fake.NewClientBuilder().WithScheme(s).WithObjects(objs...)
	for _, versions := range routeKinds {
		for _, k := range versions {
			if obj := k.newObj(); s.Recognizes(gvkOf(t, s, obj)) {
				b = b.WithIndex(obj, RouteBackendIndex, k.index)
			}
		}
	}
	return b.Build()
}

// gvkOf is obj's kind in s, or the zero kind when s does not know it.
func gvkOf(t *testing.T, s *runtime.Scheme, obj client.Object) schema.GroupVersionKind {
	t.Helper()
	gvks, _, err := s.ObjectKinds(obj)
	if err != nil || len(gvks) == 0 {
		return schema.GroupVersionKind{}
	}
	return gvks[0]
}

func objMeta(ns, name string) metav1.ObjectMeta { return metav1.ObjectMeta{Namespace: ns, Name: name} }

var appNetbox = map[string]string{"app": "netbox"}

func svc(typ corev1.ServiceType, sel map[string]string, mod ...func(*corev1.Service)) *corev1.Service {
	s := &corev1.Service{ObjectMeta: objMeta("netbox", "netbox"), Spec: corev1.ServiceSpec{Type: typ, Selector: sel}}
	for _, m := range mod {
		m(s)
	}
	return s
}

func ann(k, v string) func(*corev1.Service) {
	return func(s *corev1.Service) { s.Annotations = map[string]string{k: v} }
}

func ing(class *string, annotation string) *networkingv1.Ingress {
	i := &networkingv1.Ingress{ObjectMeta: objMeta("netbox", "netbox"), Spec: networkingv1.IngressSpec{
		IngressClassName: class,
		Rules: []networkingv1.IngressRule{{IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{
			Paths: []networkingv1.HTTPIngressPath{{Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "netbox"}}}},
		}}}},
	}}
	if annotation != "" {
		i.Annotations = map[string]string{"kubernetes.io/ingress.class": annotation}
	}
	return i
}

func str(s string) *string { return &s }

func gw(ns, name, class string) *gatewayv1.Gateway {
	return &gatewayv1.Gateway{ObjectMeta: objMeta(ns, name), Spec: gatewayv1.GatewaySpec{GatewayClassName: gatewayv1.ObjectName(class)}}
}

func parent(ns, name string) gatewayv1.ParentReference {
	n := gatewayv1.Namespace(ns)
	return gatewayv1.ParentReference{Namespace: &n, Name: gatewayv1.ObjectName(name)}
}

func backend(name string) gatewayv1.BackendRef {
	return gatewayv1.BackendRef{BackendObjectReference: gatewayv1.BackendObjectReference{Name: gatewayv1.ObjectName(name)}}
}

func common(p gatewayv1.ParentReference) gatewayv1.CommonRouteSpec {
	return gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{p}}
}

func httpRoute(p gatewayv1.ParentReference) *gatewayv1.HTTPRoute {
	return &gatewayv1.HTTPRoute{ObjectMeta: objMeta("netbox", "netbox"), Spec: gatewayv1.HTTPRouteSpec{CommonRouteSpec: common(p),
		Rules: []gatewayv1.HTTPRouteRule{{BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: backend("netbox")}}}}}}
}

// crossRoute is an HTTPRoute in namespace edge sending traffic to the Service netbox/netbox.
func crossRoute(p gatewayv1.ParentReference) *gatewayv1.HTTPRoute {
	r := httpRoute(p)
	r.Namespace = "edge"
	ns := gatewayv1.Namespace("netbox")
	r.Spec.Rules[0].BackendRefs[0].Namespace = &ns
	return r
}

// grant is a ReferenceGrant in namespace netbox letting kind routes in namespace from reference the
// Service named svc ("" = every Service).
func grant(kind, from, svc string) *gatewayv1.ReferenceGrant {
	to := gatewayv1.ReferenceGrantTo{Group: "", Kind: "Service"}
	if svc != "" {
		n := gatewayv1.ObjectName(svc)
		to.Name = &n
	}
	return &gatewayv1.ReferenceGrant{ObjectMeta: objMeta("netbox", "allow-"+from), Spec: gatewayv1.ReferenceGrantSpec{
		From: []gatewayv1.ReferenceGrantFrom{{Group: gatewayGroup, Kind: gatewayv1.Kind(kind), Namespace: gatewayv1.Namespace(from)}},
		To:   []gatewayv1.ReferenceGrantTo{to},
	}}
}

func allRoutes(p gatewayv1.ParentReference) []client.Object {
	return []client.Object{
		httpRoute(p),
		&gatewayv1.GRPCRoute{ObjectMeta: objMeta("netbox", "netbox"), Spec: gatewayv1.GRPCRouteSpec{CommonRouteSpec: common(p),
			Rules: []gatewayv1.GRPCRouteRule{{BackendRefs: []gatewayv1.GRPCBackendRef{{BackendRef: backend("netbox")}}}}}},
		&gatewayv1.TCPRoute{ObjectMeta: objMeta("netbox", "netbox"), Spec: gatewayv1.TCPRouteSpec{CommonRouteSpec: common(p),
			Rules: []gatewayv1.TCPRouteRule{{BackendRefs: []gatewayv1.BackendRef{backend("netbox")}}}}},
		&gatewayv1.TLSRoute{ObjectMeta: objMeta("netbox", "netbox"), Spec: gatewayv1.TLSRouteSpec{CommonRouteSpec: common(p),
			Rules: []gatewayv1.TLSRouteRule{{BackendRefs: []gatewayv1.BackendRef{backend("netbox")}}}}},
		&gatewayv1.UDPRoute{ObjectMeta: objMeta("netbox", "netbox"), Spec: gatewayv1.UDPRouteSpec{CommonRouteSpec: common(p),
			Rules: []gatewayv1.UDPRouteRule{{BackendRefs: []gatewayv1.BackendRef{backend("netbox")}}}}},
	}
}

func meshRoute() *gatewayv1.HTTPRoute {
	r := httpRoute(parent("netbox", "netbox"))
	k := gatewayv1.Kind("Service")
	r.Spec.ParentRefs[0].Kind = &k
	g := gatewayv1.Group("")
	r.Spec.ParentRefs[0].Group = &g
	return r
}

func netboxPod(mod ...func(*corev1.Pod)) *corev1.Pod {
	p := &corev1.Pod{ObjectMeta: objMeta("netbox", "netbox-0"), Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}}}}
	p.Labels = appNetbox
	for _, m := range mod {
		m(p)
	}
	return p
}

func workload(pods ...*corev1.Pod) *inventory.Workload {
	return &inventory.Workload{Ref: model.OwnerRef{Kind: "Deployment", Namespace: "netbox", Name: "netbox"}, Pods: pods}
}

func TestExposure(t *testing.T) {
	const route = " netbox/netbox on Gateway public/edge"
	pub := parent("public", "edge")
	lb, np, cip := corev1.ServiceTypeLoadBalancer, corev1.ServiceTypeNodePort, corev1.ServiceTypeClusterIP
	cfg0 := config.ExposureConfig{}
	routeNames := []string{"GRPCRoute" + route, "HTTPRoute" + route, "TCPRoute" + route, "TLSRoute" + route, "UDPRoute" + route}

	cases := []struct {
		name    string
		objs    []client.Object
		pods    []*corev1.Pod
		cfg     config.ExposureConfig
		exposed bool
		paths   []string
	}{
		{"lb", []client.Object{svc(lb, appNetbox)}, nil, cfg0, true, []string{"Service netbox/netbox type LoadBalancer"}},
		{"internal lb annotation", []client.Object{svc(lb, appNetbox, ann("service.beta.kubernetes.io/aws-load-balancer-internal", "true"))}, nil,
			config.ExposureConfig{InternalLBAnnotations: map[string]string{"service.beta.kubernetes.io/aws-load-balancer-internal": "true"}}, false, nil},
		{"lb annotation wildcard value", []client.Object{svc(lb, appNetbox, ann("networking.gke.io/load-balancer-type", "Internal"))}, nil,
			config.ExposureConfig{InternalLBAnnotations: map[string]string{"networking.gke.io/load-balancer-type": "*"}}, false, nil},
		{"lb annotation value differs", []client.Object{svc(lb, appNetbox, ann("k", "public"))}, nil,
			config.ExposureConfig{InternalLBAnnotations: map[string]string{"k": "true"}}, true, []string{"Service netbox/netbox type LoadBalancer"}},
		{"nodeport", []client.Object{svc(np, appNetbox)}, nil, cfg0, true, []string{"Service netbox/netbox type NodePort"}},
		{"externalIPs", []client.Object{svc(cip, appNetbox, func(s *corev1.Service) { s.Spec.ExternalIPs = []string{"203.0.113.10"} })}, nil, cfg0, true,
			[]string{"Service netbox/netbox externalIPs"}},
		{"clusterip only", []client.Object{svc(cip, appNetbox)}, nil, cfg0, false, nil},
		{"no selector", []client.Object{svc(lb, nil)}, nil, cfg0, false, nil},
		{"selector mismatch", []client.Object{svc(lb, map[string]string{"app": "other"})}, nil, cfg0, false, nil},
		{"ingress", []client.Object{svc(cip, appNetbox), ing(str("nginx"), "")}, nil, cfg0, true, []string{"Ingress netbox/netbox"}},
		{"ingress internal class", []client.Object{svc(cip, appNetbox), ing(str("internal-nginx"), "")}, nil,
			config.ExposureConfig{InternalIngressClasses: []string{"internal-nginx"}}, false, nil},
		{"ingress internal class by annotation", []client.Object{svc(cip, appNetbox), ing(nil, "internal-nginx")}, nil,
			config.ExposureConfig{InternalIngressClasses: []string{"internal-nginx"}}, false, nil},
		{"ingress default class internal", []client.Object{svc(cip, appNetbox), ing(nil, ""),
			&networkingv1.IngressClass{ObjectMeta: metav1.ObjectMeta{Name: "internal", Annotations: map[string]string{defaultClassAnnotation: "true"}}}}, nil,
			config.ExposureConfig{InternalIngressClasses: []string{"internal"}}, false, nil},
		{"ingress to other service", []client.Object{svc(cip, appNetbox), func() client.Object {
			i := ing(str("nginx"), "")
			i.Spec.Rules[0].HTTP.Paths[0].Backend.Service.Name = "other"
			return i
		}()}, nil, cfg0, false, nil},
		{"httproute", append([]client.Object{svc(cip, appNetbox), gw("public", "edge", "cilium")}, httpRoute(pub)), nil, cfg0, true,
			[]string{"HTTPRoute" + route}},
		{"route on internal gateway", append([]client.Object{svc(cip, appNetbox), gw("public", "edge", "cilium")}, httpRoute(pub)), nil,
			config.ExposureConfig{InternalGateways: []string{"public/edge"}}, false, nil},
		{"route on internal gatewayclass", append([]client.Object{svc(cip, appNetbox), gw("public", "edge", "cilium")}, httpRoute(pub)), nil,
			config.ExposureConfig{InternalGatewayClasses: []string{"cilium"}}, false, nil},
		{"grpc/tls/tcp/udp routes", append([]client.Object{svc(cip, appNetbox), gw("public", "edge", "cilium")}, allRoutes(pub)...), nil, cfg0, true, routeNames},
		{"route parentRef to Service (mesh)", []client.Object{svc(cip, appNetbox), meshRoute()}, nil, cfg0, false, nil},
		{"route from another namespace without a ReferenceGrant", []client.Object{svc(cip, appNetbox), crossRoute(pub)}, nil, cfg0,
			false, nil},
		{"route from another namespace with a ReferenceGrant", []client.Object{svc(cip, appNetbox), crossRoute(pub),
			grant("HTTPRoute", "edge", "")}, nil, cfg0, true, []string{"HTTPRoute edge/netbox on Gateway public/edge"}},
		{"ReferenceGrant naming the Service", []client.Object{svc(cip, appNetbox), crossRoute(pub),
			grant("HTTPRoute", "edge", "netbox")}, nil, cfg0, true, []string{"HTTPRoute edge/netbox on Gateway public/edge"}},
		{"ReferenceGrant for another Service", []client.Object{svc(cip, appNetbox), crossRoute(pub),
			grant("HTTPRoute", "edge", "other")}, nil, cfg0, false, nil},
		{"ReferenceGrant for another namespace", []client.Object{svc(cip, appNetbox), crossRoute(pub),
			grant("HTTPRoute", "elsewhere", "")}, nil, cfg0, false, nil},
		{"ReferenceGrant for another route kind", []client.Object{svc(cip, appNetbox), crossRoute(pub),
			grant("GRPCRoute", "edge", "")}, nil, cfg0, false, nil},
		{"ReferenceGrant in the route's namespace", []client.Object{svc(cip, appNetbox), crossRoute(pub), func() client.Object {
			g := grant("HTTPRoute", "edge", "")
			g.Namespace = "edge"
			return g
		}()}, nil, cfg0, false, nil},
		{"hostNetwork", nil, []*corev1.Pod{netboxPod(func(p *corev1.Pod) { p.Spec.HostNetwork = true })}, cfg0, true, []string{"hostNetwork"}},
		{"hostPort", nil, []*corev1.Pod{netboxPod(func(p *corev1.Pod) {
			p.Spec.Containers[0].Ports = []corev1.ContainerPort{{ContainerPort: 80, HostPort: 8080, Protocol: corev1.ProtocolTCP}}
		})}, cfg0, true, []string{"hostPort 8080/TCP"}},
		{"hostPort default protocol", nil, []*corev1.Pod{netboxPod(func(p *corev1.Pod) {
			p.Spec.Containers[0].Ports = []corev1.ContainerPort{{ContainerPort: 80, HostPort: 8080}}
		})}, cfg0, true, []string{"hostPort 8080/TCP"}},
		{"not running uses template labels", []client.Object{svc(lb, appNetbox)}, nil, cfg0, true, []string{"Service netbox/netbox type LoadBalancer"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newClient(t, testScheme(t, true), tc.objs...)
			w := workload(tc.pods...)
			if len(tc.pods) == 0 {
				w.Template = &corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: appNetbox}}
			}
			got, err := New(c, tc.cfg).Context(context.Background(), w)
			if err != nil {
				t.Fatal(err)
			}
			if got.Exposed != tc.exposed || !slices.Equal(got.ExposurePaths, tc.paths) {
				t.Fatalf("exposed=%v paths=%q, want exposed=%v paths=%q", got.Exposed, got.ExposurePaths, tc.exposed, tc.paths)
			}
		})
	}
}

func TestExposure_GatewayCRDsAbsent(t *testing.T) {
	c := newClient(t, testScheme(t, false), svc(corev1.ServiceTypeLoadBalancer, appNetbox))
	w := workload(netboxPod())
	got, err := New(c, config.ExposureConfig{InternalGatewayClasses: []string{"cilium"}}).Context(context.Background(), w)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Exposed || !slices.Equal(got.ExposurePaths, []string{"Service netbox/netbox type LoadBalancer"}) {
		t.Fatalf("got %+v", got)
	}
}

func TestRoutesTo_AlphaFallback(t *testing.T) {
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := gatewayv1alpha2.Install(s); err != nil {
		t.Fatal(err)
	}
	p := parent("gws", "edge")
	b := gatewayv1alpha2.BackendRef{BackendObjectReference: gatewayv1alpha2.BackendObjectReference{Name: "netbox"}}
	c := newClient(t, s,
		&gatewayv1alpha2.TLSRoute{ObjectMeta: objMeta("netbox", "t"), Spec: gatewayv1alpha2.TLSRouteSpec{CommonRouteSpec: common(p), Rules: []gatewayv1alpha2.TLSRouteRule{{BackendRefs: []gatewayv1alpha2.BackendRef{b}}}}},
		&gatewayv1alpha2.TCPRoute{ObjectMeta: objMeta("netbox", "c"), Spec: gatewayv1alpha2.TCPRouteSpec{CommonRouteSpec: common(p), Rules: []gatewayv1alpha2.TCPRouteRule{{BackendRefs: []gatewayv1alpha2.BackendRef{b}}}}},
		&gatewayv1alpha2.UDPRoute{ObjectMeta: objMeta("netbox", "u"), Spec: gatewayv1alpha2.UDPRouteSpec{CommonRouteSpec: common(p), Rules: []gatewayv1alpha2.UDPRouteRule{{BackendRefs: []gatewayv1alpha2.BackendRef{b}}}}},
	)
	rs, err := routesTo(context.Background(), c, "netbox", routeKinds)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]bool{}
	for _, r := range rs {
		kinds[r.Kind] = true
		if len(r.Parents) != 1 || r.Parents[0].Namespace != "gws" || r.Parents[0].Name != "edge" ||
			len(r.Backends) != 1 || r.Backends[0].Namespace != "netbox" || r.Backends[0].Name != "netbox" {
			t.Errorf("%s: bad extraction %+v", r.Kind, r)
		}
	}
	if len(rs) != 3 || !kinds["TLSRoute"] || !kinds["TCPRoute"] || !kinds["UDPRoute"] {
		t.Fatalf("want TLS/TCP/UDP alpha routes, got %+v", rs)
	}
}
