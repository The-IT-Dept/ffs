package exposure

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/the-it-dept/ffs/internal/inventory"
	"github.com/the-it-dept/ffs/internal/model"
)

const (
	ingressClassAnnotation = "kubernetes.io/ingress.class"
	defaultClassAnnotation = "ingressclass.kubernetes.io/is-default-class"
)

// podSpecs returns the pod specs to inspect: the live pods', or the template's when none run.
func podSpecs(w *inventory.Workload) []*corev1.PodSpec {
	var out []*corev1.PodSpec
	for _, p := range w.Pods {
		out = append(out, &p.Spec)
	}
	if len(out) == 0 && w.Template != nil {
		out = append(out, &w.Template.Spec)
	}
	return out
}

// podLabelSets returns the label sets of the live pods, or the template's when none run.
func podLabelSets(w *inventory.Workload) []labels.Set {
	var out []labels.Set
	for _, p := range w.Pods {
		out = append(out, p.Labels)
	}
	if len(out) == 0 && w.Template != nil {
		out = append(out, w.Template.Labels)
	}
	return out
}

func selects(selector map[string]string, sets []labels.Set) bool {
	if len(selector) == 0 {
		return false
	}
	sel := labels.SelectorFromSet(selector)
	return slices.ContainsFunc(sets, func(s labels.Set) bool { return sel.Matches(s) })
}

// exposureEdges returns every way in to the workload, internal entry points included, unsorted and
// possibly repeated (Context sorts them). An edge's Path is the exposure path it yields; internal
// edges yield none.
func (r *Resolver) exposureEdges(ctx context.Context, w *inventory.Workload) ([]model.ExposureEdge, error) {
	ns := w.Ref.Namespace
	sets := podLabelSets(w)
	var edges []model.ExposureEdge

	for _, spec := range podSpecs(w) {
		if spec.HostNetwork {
			edges = append(edges, hostNetworkEdge())
		}
		for _, cs := range [][]corev1.Container{spec.Containers, spec.InitContainers} {
			for _, c := range cs {
				for _, p := range c.Ports {
					if p.HostPort != 0 {
						proto := p.Protocol
						if proto == "" {
							proto = corev1.ProtocolTCP
						}
						edges = append(edges, hostPortEdge(p.HostPort, proto))
					}
				}
			}
		}
	}

	var svcs corev1.ServiceList
	if err := r.c.List(ctx, &svcs, client.InNamespace(ns)); err != nil {
		return nil, fmt.Errorf("exposure: list services in %s: %w", ns, err)
	}
	selecting := map[string]bool{} // services in ns that select the pods
	for i := range svcs.Items {
		s := &svcs.Items[i]
		if !selects(s.Spec.Selector, sets) {
			continue
		}
		selecting[s.Name] = true
		ref := s.Namespace + "/" + s.Name
		switch {
		case s.Spec.Type == corev1.ServiceTypeLoadBalancer && r.internalLB(s):
			edges = append(edges, model.ExposureEdge{Entry: model.EntryLoadBalancer, EntryName: ref, Service: ref, Internal: true})
			continue // an internal load balancer contributes nothing else, not even its NodePort
		case s.Spec.Type == corev1.ServiceTypeLoadBalancer:
			edges = append(edges, serviceEdge(model.EntryLoadBalancer, ref, "Service "+ref+" type LoadBalancer"))
		case s.Spec.Type == corev1.ServiceTypeNodePort:
			edges = append(edges, serviceEdge(model.EntryNodePort, ref, "Service "+ref+" type NodePort"))
		}
		if len(s.Spec.ExternalIPs) > 0 {
			edges = append(edges, serviceEdge(model.EntryExternalIP, ref, "Service "+ref+" externalIPs"))
		}
	}

	if len(selecting) > 0 {
		ings, err := r.ingressEdges(ctx, ns, selecting)
		if err != nil {
			return nil, err
		}
		routes, err := r.routeEdges(ctx, ns, selecting)
		if err != nil {
			return nil, err
		}
		edges = append(append(edges, ings...), routes...)
	}
	return edges, nil
}

func (r *Resolver) internalLB(s *corev1.Service) bool {
	for k, want := range r.cfg.InternalLBAnnotations {
		if v, ok := s.Annotations[k]; ok && (want == "*" || v == want) {
			return true
		}
	}
	return false
}

// ingressEdges returns an edge per Ingress rule host and backend Service in selecting, the default
// backend under no host, for the Ingresses in ns.
func (r *Resolver) ingressEdges(ctx context.Context, ns string, selecting map[string]bool) ([]model.ExposureEdge, error) {
	var ings networkingv1.IngressList
	if err := r.c.List(ctx, &ings, client.InNamespace(ns)); err != nil {
		return nil, fmt.Errorf("exposure: list ingresses in %s: %w", ns, err)
	}
	var edges []model.ExposureEdge
	var defaultClass *string // resolved lazily
	for i := range ings.Items {
		ing := &ings.Items[i]
		backends := ingressBackends(ing, selecting)
		if len(backends) == 0 {
			continue
		}
		class := ""
		switch {
		case ing.Spec.IngressClassName != nil:
			class = *ing.Spec.IngressClassName
		case ing.Annotations[ingressClassAnnotation] != "":
			class = ing.Annotations[ingressClassAnnotation]
		default:
			if defaultClass == nil {
				d, err := r.defaultIngressClass(ctx)
				if err != nil {
					return nil, err
				}
				defaultClass = &d
			}
			class = *defaultClass
		}
		internal := class != "" && slices.Contains(r.cfg.InternalIngressClasses, class)
		name := "Ingress " + ing.Namespace + "/" + ing.Name
		for _, b := range backends {
			edges = append(edges, withPath(model.ExposureEdge{Entry: model.EntryIngress, EntryName: class, Hostname: b.host,
				Route: name, Service: b.service, Internal: internal}, name))
		}
	}
	return edges, nil
}

// ingressBackend is a backend Service of an Ingress, "ns/name[:port]", and the rule host it serves.
type ingressBackend struct{ host, service string }

// ingressBackends returns the backends of ing whose Service is in selecting: each rule's paths
// under the rule's host, and the default backend under no host.
func ingressBackends(ing *networkingv1.Ingress, selecting map[string]bool) []ingressBackend {
	var out []ingressBackend
	add := func(host string, b *networkingv1.IngressBackend) {
		if b == nil || b.Service == nil || !selecting[b.Service.Name] {
			return
		}
		port := b.Service.Port.Name
		if port == "" && b.Service.Port.Number != 0 {
			port = strconv.Itoa(int(b.Service.Port.Number))
		}
		out = append(out, ingressBackend{host: host, service: serviceRef(ing.Namespace, b.Service.Name, port)})
	}
	add("", ing.Spec.DefaultBackend)
	for _, rule := range ing.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		for i := range rule.HTTP.Paths {
			add(rule.Host, &rule.HTTP.Paths[i].Backend)
		}
	}
	return out
}

func (r *Resolver) defaultIngressClass(ctx context.Context) (string, error) {
	var classes networkingv1.IngressClassList
	if err := r.c.List(ctx, &classes); err != nil {
		return "", fmt.Errorf("exposure: list ingress classes: %w", err)
	}
	var names []string
	for _, c := range classes.Items {
		if c.Annotations[defaultClassAnnotation] == "true" {
			names = append(names, c.Name)
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return "", nil
	}
	return names[0], nil
}

// routeEdges returns an edge per Gateway parent, hostname ("" when the route lists none) and backend
// Service in selecting (the Services in ns that select the workload), for the Gateway API routes to
// them. A route in another namespace counts only where a ReferenceGrant in ns allows it to reference
// the Service, as for the Gateway itself.
func (r *Resolver) routeEdges(ctx context.Context, ns string, selecting map[string]bool) ([]model.ExposureEdge, error) {
	kinds, grantKinds := r.readKinds()
	routes, err := routesTo(ctx, r.c, ns, kinds)
	if err != nil {
		return nil, err
	}
	var (
		grants     []gatewayv1.ReferenceGrantSpec
		grantsRead bool
	)
	allowed := func(rt route, svc string) (bool, error) {
		if rt.Namespace == ns {
			return true, nil
		}
		if !grantsRead {
			g, gerr := grantsIn(ctx, r.c, ns, grantKinds)
			if gerr != nil {
				return false, gerr
			}
			grants, grantsRead = g, true
		}
		return grantsBackend(grants, rt.Kind, rt.Namespace, svc), nil
	}
	var edges []model.ExposureEdge
	for _, rt := range routes {
		var services []string
		for _, b := range rt.Backends {
			if b.Namespace != ns || !selecting[b.Name] {
				continue
			}
			ok, err := allowed(rt, b.Name)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
			port := ""
			if b.Port != 0 {
				port = strconv.Itoa(int(b.Port))
			}
			services = append(services, serviceRef(b.Namespace, b.Name, port))
		}
		if len(services) == 0 {
			continue
		}
		hosts := rt.Hostnames
		if len(hosts) == 0 {
			hosts = []string{""}
		}
		name := rt.Kind + " " + rt.Namespace + "/" + rt.Name
		for _, gw := range rt.Parents {
			internal, err := r.internalGateway(ctx, gw.Namespace, gw.Name)
			if err != nil {
				return nil, err
			}
			entry := gw.Namespace + "/" + gw.Name
			for _, host := range hosts {
				for _, svc := range services {
					edges = append(edges, withPath(model.ExposureEdge{Entry: model.EntryGateway, EntryName: entry, Listener: gw.SectionName,
						Hostname: host, Route: name, Service: svc, Internal: internal}, name+" on Gateway "+entry))
				}
			}
		}
	}
	return edges, nil
}

// internalGateway reports whether the Gateway is configured as internal, by name or by class. A
// Gateway that cannot be read counts as internet-facing.
func (r *Resolver) internalGateway(ctx context.Context, ns, name string) (bool, error) {
	if slices.Contains(r.cfg.InternalGateways, ns+"/"+name) {
		return true, nil
	}
	if len(r.cfg.InternalGatewayClasses) == 0 {
		return false, nil
	}
	gw := &gatewayv1.Gateway{}
	if err := r.c.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, gw); err != nil {
		if apierrors.IsNotFound(err) || absent(err) {
			return false, nil
		}
		return false, fmt.Errorf("exposure: get gateway %s/%s: %w", ns, name, err)
	}
	return slices.Contains(r.cfg.InternalGatewayClasses, string(gw.Spec.GatewayClassName)), nil
}
