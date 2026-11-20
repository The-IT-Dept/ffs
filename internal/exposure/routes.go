package exposure

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
)

const gatewayGroup = "gateway.networking.k8s.io"

// AddToScheme registers the Gateway API types (apis/v1 and apis/v1alpha2) ffs reads.
func AddToScheme(s *runtime.Scheme) error {
	if err := gatewayv1.Install(s); err != nil {
		return err
	}
	return gatewayv1alpha2.Install(s)
}

// route is the part of a Gateway API route that matters for exposure.
type route struct {
	Kind, Namespace, Name string
	Hostnames             []string       // nil for TCP and UDP routes, which have none
	Parents               []routeParent  // Gateways the route attaches to
	Backends              []routeBackend // Services the route sends traffic to
}

// routeParent is a Gateway a route attaches to, and the listener it names ("" = every listener).
type routeParent struct{ Namespace, Name, SectionName string }

// routeBackend is a Service a route sends traffic to.
type routeBackend struct {
	Namespace, Name string
	Port            int32 // 0 when the ref names none
}

// absent reports whether err means the API kind is not served (or not registered).
func absent(err error) bool {
	return meta.IsNoMatchError(err) || runtime.IsNotRegisteredError(err)
}

// rawRoute is a route reduced to what extraction needs, whatever its API kind or version.
type rawRoute struct {
	Namespace, Name string
	Hostnames       []string
	Parents         []gatewayv1.ParentReference
	Backends        []gatewayv1.BackendObjectReference
}

// routeKind describes how to list and read one route kind at one API version.
type routeKind struct {
	name string
	// list lists the kind in ns; it reports false when the kind is not served.
	list func(ctx context.Context, c client.Reader, ns string) ([]rawRoute, bool, error)
}

// kindOf builds a routeKind from a list object constructor, an items accessor and a converter.
func kindOf[L client.ObjectList, T any](name string, newList func() L, items func(L) []T, conv func(T) rawRoute) routeKind {
	return routeKind{name: name, list: func(ctx context.Context, c client.Reader, ns string) ([]rawRoute, bool, error) {
		l := newList()
		if err := c.List(ctx, l, client.InNamespace(ns)); err != nil {
			if absent(err) {
				return nil, false, nil
			}
			return nil, false, fmt.Errorf("exposure: list %T: %w", l, err)
		}
		var out []rawRoute
		for _, it := range items(l) {
			out = append(out, conv(it))
		}
		return out, true, nil
	}}
}

// backendsOf flattens the backend refs of every rule.
func backendsOf[R, B any](rules []R, refs func(R) []B, obj func(B) gatewayv1.BackendObjectReference) []gatewayv1.BackendObjectReference {
	var out []gatewayv1.BackendObjectReference
	for _, r := range rules {
		for _, b := range refs(r) {
			out = append(out, obj(b))
		}
	}
	return out
}

func plainRef(b gatewayv1.BackendRef) gatewayv1.BackendObjectReference {
	return b.BackendObjectReference
}

// hostnamesOf returns a route's hostnames as strings, or nil when it lists none.
func hostnamesOf(hs []gatewayv1.Hostname) []string {
	if len(hs) == 0 {
		return nil
	}
	out := make([]string, len(hs))
	for i, h := range hs {
		out[i] = string(h)
	}
	return out
}

// routeKinds lists, per route kind, the versions to try in order; the first served one wins.
var routeKinds = [][]routeKind{
	{kindOf("HTTPRoute", func() *gatewayv1.HTTPRouteList { return &gatewayv1.HTTPRouteList{} },
		func(l *gatewayv1.HTTPRouteList) []gatewayv1.HTTPRoute { return l.Items },
		func(o gatewayv1.HTTPRoute) rawRoute {
			return rawRoute{o.Namespace, o.Name, hostnamesOf(o.Spec.Hostnames), o.Spec.ParentRefs, backendsOf(o.Spec.Rules,
				func(r gatewayv1.HTTPRouteRule) []gatewayv1.HTTPBackendRef { return r.BackendRefs },
				func(b gatewayv1.HTTPBackendRef) gatewayv1.BackendObjectReference { return b.BackendObjectReference })}
		})},
	{kindOf("GRPCRoute", func() *gatewayv1.GRPCRouteList { return &gatewayv1.GRPCRouteList{} },
		func(l *gatewayv1.GRPCRouteList) []gatewayv1.GRPCRoute { return l.Items },
		func(o gatewayv1.GRPCRoute) rawRoute {
			return rawRoute{o.Namespace, o.Name, hostnamesOf(o.Spec.Hostnames), o.Spec.ParentRefs, backendsOf(o.Spec.Rules,
				func(r gatewayv1.GRPCRouteRule) []gatewayv1.GRPCBackendRef { return r.BackendRefs },
				func(b gatewayv1.GRPCBackendRef) gatewayv1.BackendObjectReference { return b.BackendObjectReference })}
		})},
	{
		kindOf("TLSRoute", func() *gatewayv1.TLSRouteList { return &gatewayv1.TLSRouteList{} },
			func(l *gatewayv1.TLSRouteList) []gatewayv1.TLSRoute { return l.Items },
			func(o gatewayv1.TLSRoute) rawRoute {
				return rawRoute{o.Namespace, o.Name, hostnamesOf(o.Spec.Hostnames), o.Spec.ParentRefs, backendsOf(o.Spec.Rules,
					func(r gatewayv1.TLSRouteRule) []gatewayv1.BackendRef { return r.BackendRefs }, plainRef)}
			}),
		kindOf("TLSRoute", func() *gatewayv1alpha2.TLSRouteList { return &gatewayv1alpha2.TLSRouteList{} },
			func(l *gatewayv1alpha2.TLSRouteList) []gatewayv1alpha2.TLSRoute { return l.Items },
			func(o gatewayv1alpha2.TLSRoute) rawRoute {
				return rawRoute{o.Namespace, o.Name, hostnamesOf(o.Spec.Hostnames), o.Spec.ParentRefs, backendsOf(o.Spec.Rules,
					func(r gatewayv1alpha2.TLSRouteRule) []gatewayv1.BackendRef { return r.BackendRefs }, plainRef)}
			}),
	},
	{
		kindOf("TCPRoute", func() *gatewayv1.TCPRouteList { return &gatewayv1.TCPRouteList{} },
			func(l *gatewayv1.TCPRouteList) []gatewayv1.TCPRoute { return l.Items },
			func(o gatewayv1.TCPRoute) rawRoute {
				return rawRoute{o.Namespace, o.Name, nil, o.Spec.ParentRefs, backendsOf(o.Spec.Rules,
					func(r gatewayv1.TCPRouteRule) []gatewayv1.BackendRef { return r.BackendRefs }, plainRef)}
			}),
		kindOf("TCPRoute", func() *gatewayv1alpha2.TCPRouteList { return &gatewayv1alpha2.TCPRouteList{} },
			func(l *gatewayv1alpha2.TCPRouteList) []gatewayv1alpha2.TCPRoute { return l.Items },
			func(o gatewayv1alpha2.TCPRoute) rawRoute {
				return rawRoute{o.Namespace, o.Name, nil, o.Spec.ParentRefs, backendsOf(o.Spec.Rules,
					func(r gatewayv1alpha2.TCPRouteRule) []gatewayv1.BackendRef { return r.BackendRefs }, plainRef)}
			}),
	},
	{
		kindOf("UDPRoute", func() *gatewayv1.UDPRouteList { return &gatewayv1.UDPRouteList{} },
			func(l *gatewayv1.UDPRouteList) []gatewayv1.UDPRoute { return l.Items },
			func(o gatewayv1.UDPRoute) rawRoute {
				return rawRoute{o.Namespace, o.Name, nil, o.Spec.ParentRefs, backendsOf(o.Spec.Rules,
					func(r gatewayv1.UDPRouteRule) []gatewayv1.BackendRef { return r.BackendRefs }, plainRef)}
			}),
		kindOf("UDPRoute", func() *gatewayv1alpha2.UDPRouteList { return &gatewayv1alpha2.UDPRouteList{} },
			func(l *gatewayv1alpha2.UDPRouteList) []gatewayv1alpha2.UDPRoute { return l.Items },
			func(o gatewayv1alpha2.UDPRoute) rawRoute {
				return rawRoute{o.Namespace, o.Name, nil, o.Spec.ParentRefs, backendsOf(o.Spec.Rules,
					func(r gatewayv1alpha2.UDPRouteRule) []gatewayv1.BackendRef { return r.BackendRefs }, plainRef)}
			}),
	},
}

// routesIn lists the HTTP, GRPC, TLS, TCP and UDP routes in ns. A kind the cluster does not serve
// is skipped; TLS, TCP and UDP routes fall back to v1alpha2 when v1 is not served.
func routesIn(ctx context.Context, c client.Reader, ns string) ([]route, error) {
	var out []route
	for _, versions := range routeKinds {
		for _, k := range versions {
			raws, ok, err := k.list(ctx, c, ns)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
			for _, raw := range raws {
				out = append(out, toRoute(k.name, raw))
			}
			break
		}
	}
	return out, nil
}

// toRoute keeps only Gateway parents and core Service backends, defaulting namespaces.
func toRoute(kind string, raw rawRoute) route {
	r := route{Kind: kind, Namespace: raw.Namespace, Name: raw.Name, Hostnames: raw.Hostnames}
	for _, p := range raw.Parents {
		if p.Group != nil && string(*p.Group) != gatewayGroup {
			continue
		}
		if p.Kind != nil && string(*p.Kind) != "Gateway" {
			continue
		}
		parent := routeParent{Namespace: refNamespace(p.Namespace, raw.Namespace), Name: string(p.Name)}
		if p.SectionName != nil {
			parent.SectionName = string(*p.SectionName)
		}
		r.Parents = append(r.Parents, parent)
	}
	for _, b := range raw.Backends {
		if b.Group != nil && string(*b.Group) != "" {
			continue
		}
		if b.Kind != nil && string(*b.Kind) != "Service" {
			continue
		}
		back := routeBackend{Namespace: refNamespace(b.Namespace, raw.Namespace), Name: string(b.Name)}
		if b.Port != nil {
			back.Port = *b.Port
		}
		r.Backends = append(r.Backends, back)
	}
	return r
}

func refNamespace(ns *gatewayv1.Namespace, def string) string {
	if ns != nil && *ns != "" {
		return string(*ns)
	}
	return def
}
