package exposure

import (
	"context"
	"fmt"
	"slices"
	"sort"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/the-it-dept/ffs/internal/inventory"
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

// exposurePaths returns the sorted, de-duplicated paths by which the workload is reachable from
// outside the cluster.
func (r *Resolver) exposurePaths(ctx context.Context, w *inventory.Workload) ([]string, error) {
	ns := w.Ref.Namespace
	sets := podLabelSets(w)
	paths := map[string]struct{}{}

	for _, spec := range podSpecs(w) {
		if spec.HostNetwork {
			paths["hostNetwork"] = struct{}{}
		}
		for _, cs := range [][]corev1.Container{spec.Containers, spec.InitContainers} {
			for _, c := range cs {
				for _, p := range c.Ports {
					if p.HostPort != 0 {
						proto := p.Protocol
						if proto == "" {
							proto = corev1.ProtocolTCP
						}
						paths[fmt.Sprintf("hostPort %d/%s", p.HostPort, proto)] = struct{}{}
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
			continue // an internal load balancer contributes nothing, not even its NodePort
		case s.Spec.Type == corev1.ServiceTypeLoadBalancer:
			paths["Service "+ref+" type LoadBalancer"] = struct{}{}
		case s.Spec.Type == corev1.ServiceTypeNodePort:
			paths["Service "+ref+" type NodePort"] = struct{}{}
		}
		if len(s.Spec.ExternalIPs) > 0 {
			paths["Service "+ref+" externalIPs"] = struct{}{}
		}
	}

	if len(selecting) > 0 {
		if err := r.ingressPaths(ctx, ns, selecting, paths); err != nil {
			return nil, err
		}
		if err := r.routePaths(ctx, ns, selecting, paths); err != nil {
			return nil, err
		}
	}

	out := make([]string, 0, len(paths))
	for p := range paths {
		out = append(out, p)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func (r *Resolver) internalLB(s *corev1.Service) bool {
	for k, want := range r.cfg.InternalLBAnnotations {
		if v, ok := s.Annotations[k]; ok && (want == "*" || v == want) {
			return true
		}
	}
	return false
}

func (r *Resolver) ingressPaths(ctx context.Context, ns string, selecting map[string]bool, paths map[string]struct{}) error {
	var ings networkingv1.IngressList
	if err := r.c.List(ctx, &ings, client.InNamespace(ns)); err != nil {
		return fmt.Errorf("exposure: list ingresses in %s: %w", ns, err)
	}
	var defaultClass *string // resolved lazily
	for i := range ings.Items {
		ing := &ings.Items[i]
		if !ingressUses(ing, selecting) {
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
					return err
				}
				defaultClass = &d
			}
			class = *defaultClass
		}
		if class != "" && slices.Contains(r.cfg.InternalIngressClasses, class) {
			continue
		}
		paths["Ingress "+ing.Namespace+"/"+ing.Name] = struct{}{}
	}
	return nil
}

func ingressUses(ing *networkingv1.Ingress, selecting map[string]bool) bool {
	uses := func(b *networkingv1.IngressBackend) bool {
		return b != nil && b.Service != nil && selecting[b.Service.Name]
	}
	if uses(ing.Spec.DefaultBackend) {
		return true
	}
	for _, rule := range ing.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		for _, p := range rule.HTTP.Paths {
			if uses(&p.Backend) {
				return true
			}
		}
	}
	return false
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

func (r *Resolver) routePaths(ctx context.Context, ns string, selecting map[string]bool, paths map[string]struct{}) error {
	routes, err := routesIn(ctx, r.c, ns)
	if err != nil {
		return err
	}
	for _, rt := range routes {
		backs := slices.ContainsFunc(rt.Backends, func(b types.NamespacedName) bool { return b.Namespace == ns && selecting[b.Name] })
		if !backs {
			continue
		}
		for _, gw := range rt.Parents {
			internal, err := r.internalGateway(ctx, gw.Namespace, gw.Name)
			if err != nil {
				return err
			}
			if internal {
				continue
			}
			paths[fmt.Sprintf("%s %s/%s on Gateway %s/%s", rt.Kind, rt.Namespace, rt.Name, gw.Namespace, gw.Name)] = struct{}{}
		}
	}
	return nil
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
