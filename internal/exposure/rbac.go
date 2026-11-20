package exposure

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const clusterAdmin = "cluster-admin"

// Reason strings for service-account power. Clause grants through a RoleBinding append
// " in namespace <ns>" except the cluster-only ones.
const (
	reasonClusterAdmin = "service account is bound to cluster-admin"
	reasonWildcard     = "service account has wildcard permissions"
	reasonSecrets      = "service account can read secrets cluster-wide"
	reasonPods         = "service account can create pods"
	reasonWorkloads    = "service account can create workloads"
	reasonExec         = "service account can exec into pods"
	reasonNodesProxy   = "service account can proxy to nodes"
	reasonEscalate     = "service account can escalate roles"
	reasonBind         = "service account can bind roles"
	reasonImpersonate  = "service account can impersonate"
)

// serviceAccountPower returns the sorted, de-duplicated reasons the service account (empty means
// "default") is powerful, from the ClusterRoleBindings and the RoleBindings in ns that apply to it.
func (r *Resolver) serviceAccountPower(ctx context.Context, ns, sa string) ([]string, error) {
	if sa == "" {
		sa = "default"
	}
	reasons := map[string]struct{}{}

	var crbs rbacv1.ClusterRoleBindingList
	if err := r.c.List(ctx, &crbs); err != nil {
		return nil, fmt.Errorf("exposure: list clusterrolebindings: %w", err)
	}
	for i := range crbs.Items {
		b := &crbs.Items[i]
		if !appliesTo(b.Subjects, "", ns, sa) {
			continue
		}
		rules, admin, err := r.rulesOf(ctx, "", b.RoleRef)
		if err != nil {
			return nil, err
		}
		for _, s := range bindingReasons(rules, admin, "") {
			reasons[s] = struct{}{}
		}
	}

	var rbs rbacv1.RoleBindingList
	if err := r.c.List(ctx, &rbs, client.InNamespace(ns)); err != nil {
		return nil, fmt.Errorf("exposure: list rolebindings in %s: %w", ns, err)
	}
	for i := range rbs.Items {
		b := &rbs.Items[i]
		if !appliesTo(b.Subjects, b.Namespace, ns, sa) {
			continue
		}
		rules, admin, err := r.rulesOf(ctx, ns, b.RoleRef)
		if err != nil {
			return nil, err
		}
		for _, s := range bindingReasons(rules, admin, ns) {
			reasons[s] = struct{}{}
		}
	}

	if len(reasons) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(reasons))
	for s := range reasons {
		out = append(out, s)
	}
	sort.Strings(out)
	return out, nil
}

// appliesTo reports whether any subject of a binding in bindingNS ("" for a ClusterRoleBinding) is the
// service account sa in ns, as the API server's authorizer matches subjects (appliesToUser in
// k8s.io/kubernetes rbac/validation): a ServiceAccount subject, whose namespace defaults to the
// binding's; the User system:serviceaccount:<ns>:<sa>; or a group the service account belongs to.
func appliesTo(subjects []rbacv1.Subject, bindingNS, ns, sa string) bool {
	for _, s := range subjects {
		switch s.Kind {
		case rbacv1.ServiceAccountKind:
			saNS := s.Namespace
			if saNS == "" {
				saNS = bindingNS
			}
			if saNS != "" && saNS == ns && s.Name == sa {
				return true
			}
		case rbacv1.UserKind:
			if s.Name == "system:serviceaccount:"+ns+":"+sa {
				return true
			}
		case rbacv1.GroupKind:
			switch s.Name {
			case "system:serviceaccounts", "system:serviceaccounts:" + ns, "system:authenticated":
				return true
			}
		}
	}
	return false
}

// rulesOf resolves a roleRef from the cache. admin is true for a ClusterRole named cluster-admin,
// which is evaluated without reading it. A role that does not exist grants nothing.
func (r *Resolver) rulesOf(ctx context.Context, bindingNS string, ref rbacv1.RoleRef) (rules []rbacv1.PolicyRule, admin bool, err error) {
	switch ref.Kind {
	case "ClusterRole":
		if ref.Name == clusterAdmin {
			return nil, true, nil
		}
		cr := &rbacv1.ClusterRole{}
		if err := r.c.Get(ctx, client.ObjectKey{Name: ref.Name}, cr); err != nil {
			return nil, false, ignoreNotFound(err, "clusterrole "+ref.Name)
		}
		return cr.Rules, false, nil
	case "Role":
		ro := &rbacv1.Role{}
		if err := r.c.Get(ctx, client.ObjectKey{Namespace: bindingNS, Name: ref.Name}, ro); err != nil {
			return nil, false, ignoreNotFound(err, "role "+bindingNS+"/"+ref.Name)
		}
		return ro.Rules, false, nil
	}
	return nil, false, nil
}

func ignoreNotFound(err error, what string) error {
	if apierrors.IsNotFound(err) {
		return nil
	}
	return fmt.Errorf("exposure: get %s: %w", what, err)
}

// bindingReasons evaluates one binding's rules. ns is "" for a ClusterRoleBinding. Wildcard and
// cluster-admin suppress the more specific reasons from the same binding.
func bindingReasons(rules []rbacv1.PolicyRule, admin bool, ns string) []string {
	suffix := ""
	if ns != "" {
		suffix = " in namespace " + ns
	}
	if admin {
		if ns == "" {
			return []string{reasonClusterAdmin}
		}
		return []string{reasonWildcard + suffix}
	}
	var out []string
	can := func(verb, group, resource string) bool {
		return slices.ContainsFunc(rules, func(rule rbacv1.PolicyRule) bool {
			return len(rule.ResourceNames) == 0 && verbMatch(rule.Verbs, verb) &&
				groupMatch(rule.APIGroups, group) && resourceMatch(rule.Resources, resource)
		})
	}
	// explicit reports a rule naming the verb itself; "*" does not count (it is the wildcard row).
	explicit := func(verb string) bool {
		return slices.ContainsFunc(rules, func(rule rbacv1.PolicyRule) bool {
			return len(rule.ResourceNames) == 0 && slices.Contains(rule.Verbs, verb)
		})
	}

	if slices.ContainsFunc(rules, func(rule rbacv1.PolicyRule) bool {
		return len(rule.ResourceNames) == 0 && slices.Contains(rule.Verbs, "*") && slices.Contains(rule.Resources, "*")
	}) {
		return []string{reasonWildcard + suffix}
	}

	if ns == "" && (can("get", "", "secrets") || can("list", "", "secrets") || can("watch", "", "secrets")) {
		out = append(out, reasonSecrets)
	}
	if can("create", "", "pods") {
		out = append(out, reasonPods+suffix)
	}
	for _, w := range []struct{ group, resource string }{
		{"apps", "deployments"}, {"apps", "replicasets"}, {"apps", "statefulsets"}, {"apps", "daemonsets"},
		{"batch", "jobs"}, {"batch", "cronjobs"},
	} {
		if can("create", w.group, w.resource) {
			out = append(out, reasonWorkloads+suffix)
			break
		}
	}
	if can("create", "", "pods/exec") || can("get", "", "pods/exec") {
		out = append(out, reasonExec+suffix)
	}
	if ns == "" && can("*", "", "nodes/proxy") {
		out = append(out, reasonNodesProxy)
	}
	if explicit("escalate") {
		out = append(out, reasonEscalate+suffix)
	}
	if explicit("bind") {
		out = append(out, reasonBind+suffix)
	}
	if explicit("impersonate") {
		out = append(out, reasonImpersonate+suffix)
	}
	return out
}

// verbMatch: "*" in the rule matches any verb; verb "*" asks "does any verb apply".
func verbMatch(verbs []string, verb string) bool {
	if verb == "*" {
		return len(verbs) > 0
	}
	return slices.Contains(verbs, verb) || slices.Contains(verbs, "*")
}

func groupMatch(groups []string, group string) bool {
	return slices.Contains(groups, "*") || slices.Contains(groups, group)
}

// resourceMatch accepts "*", the exact name, "*/<subresource>" and "<resource>/*".
func resourceMatch(resources []string, resource string) bool {
	res, sub := resource, ""
	if i := strings.IndexByte(resource, '/'); i >= 0 {
		res, sub = resource[:i], resource[i+1:]
	}
	for _, r := range resources {
		switch {
		case r == "*" || r == resource:
			return true
		case sub != "" && (r == "*/"+sub || r == res+"/*"):
			return true
		}
	}
	return false
}
