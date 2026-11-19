package exposure

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
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
	Parents               []types.NamespacedName // Gateways the route attaches to
	Backends              []types.NamespacedName // Services the route sends traffic to
}

// absent reports whether err means the API kind is not served (or not registered).
func absent(err error) bool {
	return meta.IsNoMatchError(err) || runtime.IsNotRegisteredError(err)
}

// routesIn lists the HTTP, GRPC, TLS, TCP and UDP routes in ns. A kind the cluster does not serve
// is skipped; TLS, TCP and UDP routes fall back to v1alpha2 when v1 is not served.
func routesIn(ctx context.Context, c client.Reader, ns string) ([]route, error) {
	var out []route
	add := func(kind string, objNS, name string, parents []gatewayv1.ParentReference, backends []gatewayv1.BackendObjectReference) {
		r := route{Kind: kind, Namespace: objNS, Name: name}
		for _, p := range parents {
			if p.Group != nil && string(*p.Group) != gatewayGroup {
				continue
			}
			if p.Kind != nil && string(*p.Kind) != "Gateway" {
				continue
			}
			r.Parents = append(r.Parents, types.NamespacedName{Namespace: refNamespace(p.Namespace, objNS), Name: string(p.Name)})
		}
		for _, b := range backends {
			if b.Group != nil && string(*b.Group) != "" {
				continue
			}
			if b.Kind != nil && string(*b.Kind) != "Service" {
				continue
			}
			r.Backends = append(r.Backends, types.NamespacedName{Namespace: refNamespace(b.Namespace, objNS), Name: string(b.Name)})
		}
		out = append(out, r)
	}
	// list lists one kind; it reports false when the kind is not served.
	list := func(l client.ObjectList) (bool, error) {
		if err := c.List(ctx, l, client.InNamespace(ns)); err != nil {
			if absent(err) {
				return false, nil
			}
			return false, fmt.Errorf("exposure: list %T: %w", l, err)
		}
		return true, nil
	}

	hl := &gatewayv1.HTTPRouteList{}
	if ok, err := list(hl); err != nil {
		return nil, err
	} else if ok {
		for _, o := range hl.Items {
			var bs []gatewayv1.BackendObjectReference
			for _, rule := range o.Spec.Rules {
				for _, b := range rule.BackendRefs {
					bs = append(bs, b.BackendObjectReference)
				}
			}
			add("HTTPRoute", o.Namespace, o.Name, o.Spec.ParentRefs, bs)
		}
	}
	gl := &gatewayv1.GRPCRouteList{}
	if ok, err := list(gl); err != nil {
		return nil, err
	} else if ok {
		for _, o := range gl.Items {
			var bs []gatewayv1.BackendObjectReference
			for _, rule := range o.Spec.Rules {
				for _, b := range rule.BackendRefs {
					bs = append(bs, b.BackendObjectReference)
				}
			}
			add("GRPCRoute", o.Namespace, o.Name, o.Spec.ParentRefs, bs)
		}
	}

	// TLSRoute
	tl := &gatewayv1.TLSRouteList{}
	if ok, err := list(tl); err != nil {
		return nil, err
	} else if ok {
		for _, o := range tl.Items {
			var bs []gatewayv1.BackendObjectReference
			for _, rule := range o.Spec.Rules {
				for _, b := range rule.BackendRefs {
					bs = append(bs, b.BackendObjectReference)
				}
			}
			add("TLSRoute", o.Namespace, o.Name, o.Spec.ParentRefs, bs)
		}
	} else {
		al := &gatewayv1alpha2.TLSRouteList{}
		if ok, err := list(al); err != nil {
			return nil, err
		} else if ok {
			for _, o := range al.Items {
				var bs []gatewayv1.BackendObjectReference
				for _, rule := range o.Spec.Rules {
					for _, b := range rule.BackendRefs {
						bs = append(bs, b.BackendObjectReference)
					}
				}
				add("TLSRoute", o.Namespace, o.Name, o.Spec.ParentRefs, bs)
			}
		}
	}

	// TCPRoute
	cl := &gatewayv1.TCPRouteList{}
	if ok, err := list(cl); err != nil {
		return nil, err
	} else if ok {
		for _, o := range cl.Items {
			var bs []gatewayv1.BackendObjectReference
			for _, rule := range o.Spec.Rules {
				for _, b := range rule.BackendRefs {
					bs = append(bs, b.BackendObjectReference)
				}
			}
			add("TCPRoute", o.Namespace, o.Name, o.Spec.ParentRefs, bs)
		}
	} else {
		al := &gatewayv1alpha2.TCPRouteList{}
		if ok, err := list(al); err != nil {
			return nil, err
		} else if ok {
			for _, o := range al.Items {
				var bs []gatewayv1.BackendObjectReference
				for _, rule := range o.Spec.Rules {
					for _, b := range rule.BackendRefs {
						bs = append(bs, b.BackendObjectReference)
					}
				}
				add("TCPRoute", o.Namespace, o.Name, o.Spec.ParentRefs, bs)
			}
		}
	}

	// UDPRoute
	ul := &gatewayv1.UDPRouteList{}
	if ok, err := list(ul); err != nil {
		return nil, err
	} else if ok {
		for _, o := range ul.Items {
			var bs []gatewayv1.BackendObjectReference
			for _, rule := range o.Spec.Rules {
				for _, b := range rule.BackendRefs {
					bs = append(bs, b.BackendObjectReference)
				}
			}
			add("UDPRoute", o.Namespace, o.Name, o.Spec.ParentRefs, bs)
		}
	} else {
		al := &gatewayv1alpha2.UDPRouteList{}
		if ok, err := list(al); err != nil {
			return nil, err
		} else if ok {
			for _, o := range al.Items {
				var bs []gatewayv1.BackendObjectReference
				for _, rule := range o.Spec.Rules {
					for _, b := range rule.BackendRefs {
						bs = append(bs, b.BackendObjectReference)
					}
				}
				add("UDPRoute", o.Namespace, o.Name, o.Spec.ParentRefs, bs)
			}
		}
	}
	return out, nil
}

func refNamespace(ns *gatewayv1.Namespace, def string) string {
	if ns != nil && *ns != "" {
		return string(*ns)
	}
	return def
}
