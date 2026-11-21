package exposure

import (
	"context"
	"fmt"
	"slices"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

const gatewayGroup = "gateway.networking.k8s.io"

// RouteBackendIndex is the cache index of Gateway API routes by the namespaces of the Services they
// send traffic to, so the routes to a workload's Services are found in any namespace.
const RouteBackendIndex = "ffs.routeBackendNamespaces"

// AddToScheme registers the Gateway API types (apis/v1, apis/v1beta1 and apis/v1alpha2) ffs reads.
func AddToScheme(s *runtime.Scheme) error {
	if err := gatewayv1.Install(s); err != nil {
		return err
	}
	if err := gatewayv1beta1.Install(s); err != nil {
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

// routeKind describes how to list, index and read one route kind at one API version.
type routeKind struct {
	name    string // the route kind, such as "HTTPRoute"
	version string // its API version, such as "v1"
	// newObj returns an empty object of the kind, for its informer and index.
	newObj func() client.Object
	// index is the RouteBackendIndex extractor: the backend Service namespaces of a route.
	index client.IndexerFunc
	// list lists the routes of the kind with a backend Service in ns, through RouteBackendIndex; it
	// reports false when the kind is not served.
	list func(ctx context.Context, c client.Reader, ns string) ([]route, bool, error)
}

// kindOf builds a routeKind from a list object constructor, an items accessor and a converter.
func kindOf[L client.ObjectList, T any, PT interface {
	*T
	client.Object
}](name, version string, newList func() L, items func(L) []T, conv func(*T) rawRoute) routeKind {
	return routeKind{
		name: name, version: version,
		newObj: func() client.Object { return PT(new(T)) },
		index: func(o client.Object) []string {
			p, ok := o.(PT)
			if !ok {
				return nil
			}
			return backendNamespaces(toRoute(name, conv((*T)(p))))
		},
		list: func(ctx context.Context, c client.Reader, ns string) ([]route, bool, error) {
			l := newList()
			if err := c.List(ctx, l, client.MatchingFields{RouteBackendIndex: ns}); err != nil {
				if absent(err) {
					return nil, false, nil
				}
				return nil, false, fmt.Errorf("exposure: list %T: %w", l, err)
			}
			its := items(l)
			out := make([]route, 0, len(its))
			for i := range its {
				out = append(out, toRoute(name, conv(&its[i])))
			}
			return out, true, nil
		},
	}
}

// backendNamespaces returns the distinct namespaces of r's backend Services, sorted.
func backendNamespaces(r route) []string {
	var out []string
	for _, b := range r.Backends {
		out = append(out, b.Namespace)
	}
	slices.Sort(out)
	return slices.Compact(out)
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
	{kindOf("HTTPRoute", "v1", func() *gatewayv1.HTTPRouteList { return &gatewayv1.HTTPRouteList{} },
		func(l *gatewayv1.HTTPRouteList) []gatewayv1.HTTPRoute { return l.Items },
		func(o *gatewayv1.HTTPRoute) rawRoute {
			return rawRoute{o.Namespace, o.Name, hostnamesOf(o.Spec.Hostnames), o.Spec.ParentRefs, backendsOf(o.Spec.Rules,
				func(r gatewayv1.HTTPRouteRule) []gatewayv1.HTTPBackendRef { return r.BackendRefs },
				func(b gatewayv1.HTTPBackendRef) gatewayv1.BackendObjectReference { return b.BackendObjectReference })}
		})},
	{kindOf("GRPCRoute", "v1", func() *gatewayv1.GRPCRouteList { return &gatewayv1.GRPCRouteList{} },
		func(l *gatewayv1.GRPCRouteList) []gatewayv1.GRPCRoute { return l.Items },
		func(o *gatewayv1.GRPCRoute) rawRoute {
			return rawRoute{o.Namespace, o.Name, hostnamesOf(o.Spec.Hostnames), o.Spec.ParentRefs, backendsOf(o.Spec.Rules,
				func(r gatewayv1.GRPCRouteRule) []gatewayv1.GRPCBackendRef { return r.BackendRefs },
				func(b gatewayv1.GRPCBackendRef) gatewayv1.BackendObjectReference { return b.BackendObjectReference })}
		})},
	{
		kindOf("TLSRoute", "v1", func() *gatewayv1.TLSRouteList { return &gatewayv1.TLSRouteList{} },
			func(l *gatewayv1.TLSRouteList) []gatewayv1.TLSRoute { return l.Items },
			func(o *gatewayv1.TLSRoute) rawRoute {
				return rawRoute{o.Namespace, o.Name, hostnamesOf(o.Spec.Hostnames), o.Spec.ParentRefs, backendsOf(o.Spec.Rules,
					func(r gatewayv1.TLSRouteRule) []gatewayv1.BackendRef { return r.BackendRefs }, plainRef)}
			}),
		kindOf("TLSRoute", "v1alpha2", func() *gatewayv1alpha2.TLSRouteList { return &gatewayv1alpha2.TLSRouteList{} },
			func(l *gatewayv1alpha2.TLSRouteList) []gatewayv1alpha2.TLSRoute { return l.Items },
			func(o *gatewayv1alpha2.TLSRoute) rawRoute {
				return rawRoute{o.Namespace, o.Name, hostnamesOf(o.Spec.Hostnames), o.Spec.ParentRefs, backendsOf(o.Spec.Rules,
					func(r gatewayv1alpha2.TLSRouteRule) []gatewayv1.BackendRef { return r.BackendRefs }, plainRef)}
			}),
	},
	{
		kindOf("TCPRoute", "v1", func() *gatewayv1.TCPRouteList { return &gatewayv1.TCPRouteList{} },
			func(l *gatewayv1.TCPRouteList) []gatewayv1.TCPRoute { return l.Items },
			func(o *gatewayv1.TCPRoute) rawRoute {
				return rawRoute{o.Namespace, o.Name, nil, o.Spec.ParentRefs, backendsOf(o.Spec.Rules,
					func(r gatewayv1.TCPRouteRule) []gatewayv1.BackendRef { return r.BackendRefs }, plainRef)}
			}),
		kindOf("TCPRoute", "v1alpha2", func() *gatewayv1alpha2.TCPRouteList { return &gatewayv1alpha2.TCPRouteList{} },
			func(l *gatewayv1alpha2.TCPRouteList) []gatewayv1alpha2.TCPRoute { return l.Items },
			func(o *gatewayv1alpha2.TCPRoute) rawRoute {
				return rawRoute{o.Namespace, o.Name, nil, o.Spec.ParentRefs, backendsOf(o.Spec.Rules,
					func(r gatewayv1alpha2.TCPRouteRule) []gatewayv1.BackendRef { return r.BackendRefs }, plainRef)}
			}),
	},
	{
		kindOf("UDPRoute", "v1", func() *gatewayv1.UDPRouteList { return &gatewayv1.UDPRouteList{} },
			func(l *gatewayv1.UDPRouteList) []gatewayv1.UDPRoute { return l.Items },
			func(o *gatewayv1.UDPRoute) rawRoute {
				return rawRoute{o.Namespace, o.Name, nil, o.Spec.ParentRefs, backendsOf(o.Spec.Rules,
					func(r gatewayv1.UDPRouteRule) []gatewayv1.BackendRef { return r.BackendRefs }, plainRef)}
			}),
		kindOf("UDPRoute", "v1alpha2", func() *gatewayv1alpha2.UDPRouteList { return &gatewayv1alpha2.UDPRouteList{} },
			func(l *gatewayv1alpha2.UDPRouteList) []gatewayv1alpha2.UDPRoute { return l.Items },
			func(o *gatewayv1alpha2.UDPRoute) rawRoute {
				return rawRoute{o.Namespace, o.Name, nil, o.Spec.ParentRefs, backendsOf(o.Spec.Rules,
					func(r gatewayv1alpha2.UDPRouteRule) []gatewayv1.BackendRef { return r.BackendRefs }, plainRef)}
			}),
	},
}

// routesTo lists the HTTP, GRPC, TLS, TCP and UDP routes, in any namespace, with a backend Service in
// ns. kinds holds, per route kind, the versions to try in order: a kind the cluster does not serve is
// skipped, and the first version served is used.
func routesTo(ctx context.Context, c client.Reader, ns string, kinds [][]routeKind) ([]route, error) {
	var out []route
	for _, versions := range kinds {
		for _, k := range versions {
			routes, ok, err := k.list(ctx, c, ns)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
			out = append(out, routes...)
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

// grantKind describes how to list ReferenceGrants at one API version.
type grantKind struct {
	version string
	newObj  func() client.Object
	newList func() client.ObjectList
	// specs returns the grant specs of a list newList made.
	specs func(client.ObjectList) []gatewayv1.ReferenceGrantSpec
}

// list lists the grant specs in ns; it reports false when the kind is not served.
func (k grantKind) list(ctx context.Context, c client.Reader, ns string) ([]gatewayv1.ReferenceGrantSpec, bool, error) {
	l := k.newList()
	if err := c.List(ctx, l, client.InNamespace(ns)); err != nil {
		return grantListErr(err)
	}
	return k.specs(l), true, nil
}

// probe lists at most one ReferenceGrant through c, an uncached reader: it fails when ffs may not
// list them.
func (k grantKind) probe(ctx context.Context, c client.Reader) error {
	return c.List(ctx, k.newList(), client.Limit(1))
}

// grantKinds are the ReferenceGrant versions to try in order: v1, then v1beta1 on clusters with
// older Gateway API CRDs.
var grantKinds = []grantKind{
	{version: "v1", newObj: func() client.Object { return &gatewayv1.ReferenceGrant{} },
		newList: func() client.ObjectList { return &gatewayv1.ReferenceGrantList{} },
		specs: func(l client.ObjectList) []gatewayv1.ReferenceGrantSpec {
			return grantSpecs(l.(*gatewayv1.ReferenceGrantList).Items)
		}},
	{version: "v1beta1", newObj: func() client.Object { return &gatewayv1beta1.ReferenceGrant{} },
		newList: func() client.ObjectList { return &gatewayv1beta1.ReferenceGrantList{} },
		specs: func(l client.ObjectList) []gatewayv1.ReferenceGrantSpec {
			return grantSpecs(l.(*gatewayv1beta1.ReferenceGrantList).Items)
		}},
}

// grantSpecs returns the specs of ReferenceGrants of either version: a v1beta1 ReferenceGrant is a v1
// one under another name.
func grantSpecs[G gatewayv1.ReferenceGrant | gatewayv1beta1.ReferenceGrant](items []G) []gatewayv1.ReferenceGrantSpec {
	out := make([]gatewayv1.ReferenceGrantSpec, len(items))
	for i := range items {
		out[i] = gatewayv1.ReferenceGrant(items[i]).Spec
	}
	return out
}

func grantListErr(err error) ([]gatewayv1.ReferenceGrantSpec, bool, error) {
	if absent(err) {
		return nil, false, nil
	}
	return nil, false, fmt.Errorf("exposure: list referencegrants: %w", err)
}

// grantsIn lists the ReferenceGrants in ns with the first of kinds the cluster serves; none when it
// serves none of them.
func grantsIn(ctx context.Context, c client.Reader, ns string, kinds []grantKind) ([]gatewayv1.ReferenceGrantSpec, error) {
	for _, k := range kinds {
		specs, ok, err := k.list(ctx, c, ns)
		if err != nil || ok {
			return specs, err
		}
	}
	return nil, nil
}

// grantsBackend reports whether one of grants (the ReferenceGrants in the Service's namespace) lets
// a route of kind in namespace from send traffic to the Service named svc, as the Gateway API
// defines it: a grant allows the reference when one of its From entries names the route's group,
// kind and namespace, and one of its To entries names core Services, either all of them or this one.
func grantsBackend(grants []gatewayv1.ReferenceGrantSpec, kind, from, svc string) bool {
	return slices.ContainsFunc(grants, func(g gatewayv1.ReferenceGrantSpec) bool {
		return slices.ContainsFunc(g.From, func(f gatewayv1.ReferenceGrantFrom) bool {
			return string(f.Group) == gatewayGroup && string(f.Kind) == kind && string(f.Namespace) == from
		}) && slices.ContainsFunc(g.To, func(t gatewayv1.ReferenceGrantTo) bool {
			return string(t.Group) == "" && string(t.Kind) == "Service" && (t.Name == nil || *t.Name == "" || string(*t.Name) == svc)
		})
	})
}
