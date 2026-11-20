package exposure

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/inventory"
	"github.com/the-it-dept/ffs/internal/model"
)

// ingressRule is an Ingress rule sending host to the Service backend b.
func ingressRule(host string, b networkingv1.IngressServiceBackend) networkingv1.IngressRule {
	return networkingv1.IngressRule{Host: host, IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{
		Paths: []networkingv1.HTTPIngressPath{{Backend: networkingv1.IngressBackend{Service: &b}}},
	}}}
}

func contextOf(t *testing.T, cfg config.ExposureConfig, objs []client.Object, w *inventory.Workload) model.WorkloadContext {
	t.Helper()
	got, err := New(newClient(t, testScheme(t, true), objs...), cfg).Context(context.Background(), w)
	require.NoError(t, err)
	return got
}

func TestExposure_StructuredEdges(t *testing.T) {
	section := gatewayv1.SectionName("https")
	edge := parent("public", "edge")
	edge.SectionName = &section
	port := gatewayv1.PortNumber(8080)
	rt := &gatewayv1.HTTPRoute{ObjectMeta: objMeta("netbox", "netbox"), Spec: gatewayv1.HTTPRouteSpec{
		CommonRouteSpec: gatewayv1.CommonRouteSpec{ParentRefs: []gatewayv1.ParentReference{edge, parent("infra", "internal")}},
		Hostnames:       []gatewayv1.Hostname{"netbox.example.com", "www.example.com"},
		Rules: []gatewayv1.HTTPRouteRule{{BackendRefs: []gatewayv1.HTTPBackendRef{{BackendRef: gatewayv1.BackendRef{
			BackendObjectReference: gatewayv1.BackendObjectReference{Name: "netbox", Port: &port}}}}}},
	}}
	public := &networkingv1.Ingress{ObjectMeta: objMeta("netbox", "netbox"), Spec: networkingv1.IngressSpec{IngressClassName: str("nginx"),
		Rules: []networkingv1.IngressRule{ingressRule("netbox.example.com",
			networkingv1.IngressServiceBackend{Name: "netbox", Port: networkingv1.ServiceBackendPort{Name: "http"}})}}}
	lan := &networkingv1.Ingress{ObjectMeta: objMeta("netbox", "lan"), Spec: networkingv1.IngressSpec{IngressClassName: str("internal-nginx"),
		Rules: []networkingv1.IngressRule{ingressRule("lan.example.com",
			networkingv1.IngressServiceBackend{Name: "netbox", Port: networkingv1.ServiceBackendPort{Number: 80}})}}}
	named := func(name string, s *corev1.Service) *corev1.Service { s.Name = name; return s }
	objs := []client.Object{
		gw("public", "edge", "cilium"), gw("infra", "internal", "internal-gw"), rt, public, lan,
		svc(corev1.ServiceTypeClusterIP, appNetbox),
		named("lb", svc(corev1.ServiceTypeLoadBalancer, appNetbox, ann("k", "true"))),
		named("np", svc(corev1.ServiceTypeNodePort, appNetbox, func(s *corev1.Service) { s.Spec.ExternalIPs = []string{"203.0.113.10"} })),
	}
	hostPort := []corev1.ContainerPort{{ContainerPort: 80, HostPort: 8080, Protocol: corev1.ProtocolTCP}}
	pod := netboxPod(func(p *corev1.Pod) {
		p.Spec.HostNetwork = true
		p.Spec.Containers = []corev1.Container{{Name: "app", Ports: hostPort}, {Name: "sidecar", Ports: hostPort}}
	})
	cfg := config.ExposureConfig{InternalGatewayClasses: []string{"internal-gw"}, InternalIngressClasses: []string{"internal-nginx"},
		InternalLBAnnotations: map[string]string{"k": "true"}}

	got := contextOf(t, cfg, objs, workload(pod))
	route := "HTTPRoute netbox/netbox"
	require.Equal(t, []model.ExposureEdge{
		{Entry: model.EntryExternalIP, EntryName: "netbox/np", Service: "netbox/np", Path: "Service netbox/np externalIPs"},
		{Entry: model.EntryGateway, EntryName: "infra/internal", Hostname: "netbox.example.com", Route: route, Service: "netbox/netbox:8080", Internal: true},
		{Entry: model.EntryGateway, EntryName: "infra/internal", Hostname: "www.example.com", Route: route, Service: "netbox/netbox:8080", Internal: true},
		{Entry: model.EntryGateway, EntryName: "public/edge", Listener: "https", Hostname: "netbox.example.com", Route: route,
			Service: "netbox/netbox:8080", Path: "HTTPRoute netbox/netbox on Gateway public/edge"},
		{Entry: model.EntryGateway, EntryName: "public/edge", Listener: "https", Hostname: "www.example.com", Route: route,
			Service: "netbox/netbox:8080", Path: "HTTPRoute netbox/netbox on Gateway public/edge"},
		{Entry: model.EntryHostNetwork, Path: "hostNetwork"},
		{Entry: model.EntryHostPort, Listener: "8080/TCP", Path: "hostPort 8080/TCP"}, // once, not twice
		{Entry: model.EntryIngress, EntryName: "internal-nginx", Hostname: "lan.example.com", Route: "Ingress netbox/lan",
			Service: "netbox/netbox:80", Internal: true},
		{Entry: model.EntryIngress, EntryName: "nginx", Hostname: "netbox.example.com", Route: "Ingress netbox/netbox",
			Service: "netbox/netbox:http", Path: "Ingress netbox/netbox"},
		{Entry: model.EntryLoadBalancer, EntryName: "netbox/lb", Service: "netbox/lb", Internal: true},
		{Entry: model.EntryNodePort, EntryName: "netbox/np", Service: "netbox/np", Path: "Service netbox/np type NodePort"},
	}, got.Exposure)
	require.Equal(t, []string{"HTTPRoute netbox/netbox on Gateway public/edge", "Ingress netbox/netbox", "Service netbox/np externalIPs",
		"Service netbox/np type NodePort", "hostNetwork", "hostPort 8080/TCP"}, got.ExposurePaths)
	require.True(t, got.Exposed)

	// a second Context call returns an equal Exposure, so inventory's sameOwner does not flap
	again := contextOf(t, cfg, objs, workload(pod))
	require.Equal(t, got.Exposure, again.Exposure)
	require.Equal(t, got, again)
}

func TestExposure_PathsUnchangedByEdges(t *testing.T) {
	const route = " netbox/netbox on Gateway public/edge"
	pub := parent("public", "edge")
	lb, np, cip := corev1.ServiceTypeLoadBalancer, corev1.ServiceTypeNodePort, corev1.ServiceTypeClusterIP
	cfg0 := config.ExposureConfig{}
	edgeGW := gw("public", "edge", "cilium")
	routes := allRoutes(pub) // HTTP, GRPC, TCP, TLS, UDP
	withHosts := func(o client.Object) client.Object {
		hs := []gatewayv1.Hostname{"shop.example.com"}
		switch r := o.(type) {
		case *gatewayv1.HTTPRoute:
			r.Spec.Hostnames = hs
		case *gatewayv1.GRPCRoute:
			r.Spec.Hostnames = hs
		case *gatewayv1.TLSRoute:
			r.Spec.Hostnames = hs
		}
		return o
	}
	routeEdge := func(kind, host string) []model.ExposureEdge {
		return []model.ExposureEdge{{Entry: model.EntryGateway, EntryName: "public/edge", Hostname: host, Route: kind + " netbox/netbox",
			Service: "netbox/netbox", Path: kind + route}}
	}
	defaultBackend := &networkingv1.Ingress{ObjectMeta: objMeta("netbox", "netbox"), Spec: networkingv1.IngressSpec{IngressClassName: str("nginx"),
		DefaultBackend: &networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "netbox"}}}}
	internalAnn := "service.beta.kubernetes.io/aws-load-balancer-internal"

	cases := []struct {
		name  string
		objs  []client.Object
		pods  []*corev1.Pod
		cfg   config.ExposureConfig
		paths []string
		edges []model.ExposureEdge // nil: not checked beyond the path rules
	}{
		{"lb", []client.Object{svc(lb, appNetbox)}, nil, cfg0, []string{"Service netbox/netbox type LoadBalancer"},
			[]model.ExposureEdge{{Entry: model.EntryLoadBalancer, EntryName: "netbox/netbox", Service: "netbox/netbox",
				Path: "Service netbox/netbox type LoadBalancer"}}},
		{"nodeport", []client.Object{svc(np, appNetbox)}, nil, cfg0, []string{"Service netbox/netbox type NodePort"},
			[]model.ExposureEdge{{Entry: model.EntryNodePort, EntryName: "netbox/netbox", Service: "netbox/netbox",
				Path: "Service netbox/netbox type NodePort"}}},
		{"externalIPs", []client.Object{svc(cip, appNetbox, func(s *corev1.Service) { s.Spec.ExternalIPs = []string{"203.0.113.10"} })}, nil, cfg0,
			[]string{"Service netbox/netbox externalIPs"},
			[]model.ExposureEdge{{Entry: model.EntryExternalIP, EntryName: "netbox/netbox", Service: "netbox/netbox",
				Path: "Service netbox/netbox externalIPs"}}},
		{"ingress", []client.Object{svc(cip, appNetbox), ing(str("nginx"), "")}, nil, cfg0, []string{"Ingress netbox/netbox"},
			[]model.ExposureEdge{{Entry: model.EntryIngress, EntryName: "nginx", Route: "Ingress netbox/netbox", Service: "netbox/netbox",
				Path: "Ingress netbox/netbox"}}},
		{"ingress default backend", []client.Object{svc(cip, appNetbox), defaultBackend}, nil, cfg0, []string{"Ingress netbox/netbox"},
			[]model.ExposureEdge{{Entry: model.EntryIngress, EntryName: "nginx", Hostname: "", Route: "Ingress netbox/netbox",
				Service: "netbox/netbox", Path: "Ingress netbox/netbox"}}},
		{"httproute", []client.Object{svc(cip, appNetbox), edgeGW, withHosts(routes[0])}, nil, cfg0, []string{"HTTPRoute" + route},
			routeEdge("HTTPRoute", "shop.example.com")},
		{"grpcroute", []client.Object{svc(cip, appNetbox), edgeGW, withHosts(routes[1])}, nil, cfg0, []string{"GRPCRoute" + route},
			routeEdge("GRPCRoute", "shop.example.com")},
		{"tcproute", []client.Object{svc(cip, appNetbox), edgeGW, routes[2]}, nil, cfg0, []string{"TCPRoute" + route},
			routeEdge("TCPRoute", "")},
		{"tlsroute", []client.Object{svc(cip, appNetbox), edgeGW, withHosts(routes[3])}, nil, cfg0, []string{"TLSRoute" + route},
			routeEdge("TLSRoute", "shop.example.com")},
		{"udproute", []client.Object{svc(cip, appNetbox), edgeGW, routes[4]}, nil, cfg0, []string{"UDPRoute" + route},
			routeEdge("UDPRoute", "")},
		{"hostNetwork", nil, []*corev1.Pod{netboxPod(func(p *corev1.Pod) { p.Spec.HostNetwork = true })}, cfg0, []string{"hostNetwork"},
			[]model.ExposureEdge{{Entry: model.EntryHostNetwork, Path: "hostNetwork"}}},
		{"hostPort default protocol", nil, []*corev1.Pod{netboxPod(func(p *corev1.Pod) {
			p.Spec.Containers[0].Ports = []corev1.ContainerPort{{ContainerPort: 80, HostPort: 8080}}
		})}, cfg0, []string{"hostPort 8080/TCP"},
			[]model.ExposureEdge{{Entry: model.EntryHostPort, Listener: "8080/TCP", Path: "hostPort 8080/TCP"}}},
		{"internal lb annotation", []client.Object{svc(lb, appNetbox, ann(internalAnn, "true"))}, nil,
			config.ExposureConfig{InternalLBAnnotations: map[string]string{internalAnn: "true"}}, nil,
			[]model.ExposureEdge{{Entry: model.EntryLoadBalancer, EntryName: "netbox/netbox", Service: "netbox/netbox", Internal: true}}},
		{"internal ingress class", []client.Object{svc(cip, appNetbox), ing(str("internal-nginx"), "")}, nil,
			config.ExposureConfig{InternalIngressClasses: []string{"internal-nginx"}}, nil,
			[]model.ExposureEdge{{Entry: model.EntryIngress, EntryName: "internal-nginx", Route: "Ingress netbox/netbox",
				Service: "netbox/netbox", Internal: true}}},
		{"internal gateway by name", []client.Object{svc(cip, appNetbox), edgeGW, httpRoute(pub)}, nil,
			config.ExposureConfig{InternalGateways: []string{"public/edge"}}, nil,
			[]model.ExposureEdge{{Entry: model.EntryGateway, EntryName: "public/edge", Route: "HTTPRoute netbox/netbox",
				Service: "netbox/netbox", Internal: true}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := workload(tc.pods...)
			if len(tc.pods) == 0 {
				w.Template = &corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: appNetbox}}
			}
			got := contextOf(t, tc.cfg, tc.objs, w)
			require.Equal(t, tc.paths, got.ExposurePaths)
			require.Equal(t, pathsOf(got.Exposure), got.ExposurePaths)
			require.Equal(t, len(tc.paths) > 0, got.Exposed)
			require.Equal(t, tc.edges, got.Exposure)
			if len(tc.paths) == 0 { // internal only
				require.Nil(t, got.ExposurePaths)
				require.False(t, got.Exposed)
				require.NotEmpty(t, got.Exposure)
				for _, e := range got.Exposure {
					require.True(t, e.Internal, e)
					require.Empty(t, e.Path, e)
				}
			}
		})
	}
}

func TestExposure_SortEdgesDropsDuplicates(t *testing.T) {
	a := model.ExposureEdge{Entry: model.EntryHostNetwork, Path: "hostNetwork"}
	b := model.ExposureEdge{Entry: model.EntryExternalIP, EntryName: "shop/web", Service: "shop/web", Path: "Service shop/web externalIPs"}
	require.Equal(t, []model.ExposureEdge{b, a}, sortEdges([]model.ExposureEdge{a, b, a}))
	require.Nil(t, sortEdges(nil))
	require.Nil(t, sortEdges([]model.ExposureEdge{}))
	require.Nil(t, pathsOf([]model.ExposureEdge{{Entry: model.EntryLoadBalancer, Internal: true}}))
	require.Equal(t, []string{"Service shop/web externalIPs", "hostNetwork"}, pathsOf([]model.ExposureEdge{a, b, a}))
}
