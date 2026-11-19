package exposure

import (
	"context"
	"slices"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/the-it-dept/ffs/internal/config"
)

func rule(verbs, groups, resources []string) rbacv1.PolicyRule {
	return rbacv1.PolicyRule{Verbs: verbs, APIGroups: groups, Resources: resources}
}

func saSubject(ns, name string) rbacv1.Subject {
	return rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Namespace: ns, Name: name}
}

func crb(role string, subjects ...rbacv1.Subject) []client.Object {
	return []client.Object{&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "b-" + role}, Subjects: subjects,
		RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: role}}}
}

func clusterRole(name string, rules ...rbacv1.PolicyRule) client.Object {
	return &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: name}, Rules: rules}
}

func rb(role string, subjects ...rbacv1.Subject) []client.Object {
	return []client.Object{&rbacv1.RoleBinding{ObjectMeta: objMeta("apps", "b-"+role), Subjects: subjects,
		RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: role}}}
}

func TestServiceAccountPower(t *testing.T) {
	web := saSubject("apps", "web")
	star := []string{"*"}
	cat := func(parts ...[]client.Object) []client.Object {
		var out []client.Object
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	role := func(r ...rbacv1.PolicyRule) []client.Object { return []client.Object{clusterRole("r", r...)} }
	cases := []struct {
		name string
		objs []client.Object
		want []string
	}{
		{"CRB cluster-admin", crb("cluster-admin", web), []string{"service account is bound to cluster-admin"}},
		{"CRB wildcard", cat(role(rule(star, star, star)), crb("r", web)), []string{"service account has wildcard permissions"}},
		{"RB wildcard", cat(role(rule(star, star, star)), rb("r", web)), []string{"service account has wildcard permissions in namespace apps"}},
		{"RB cluster-admin is namespaced wildcard", rb("cluster-admin", web), []string{"service account has wildcard permissions in namespace apps"}},
		{"wildcard suppresses specifics", cat(role(rule(star, star, star), rule([]string{"create"}, []string{""}, []string{"pods"})), crb("r", web)),
			[]string{"service account has wildcard permissions"}},
		{"CRB get secrets", cat(role(rule([]string{"get"}, []string{""}, []string{"secrets"})), crb("r", web)), []string{"service account can read secrets cluster-wide"}},
		{"RB get secrets", cat(role(rule([]string{"get"}, []string{""}, []string{"secrets"})), rb("r", web)), nil},
		{"RB create pods", cat(role(rule([]string{"create"}, []string{""}, []string{"pods"})), rb("r", web)), []string{"service account can create pods in namespace apps"}},
		{"CRB create deployments", cat(role(rule([]string{"create"}, []string{"apps"}, []string{"deployments"})), crb("r", web)), []string{"service account can create workloads"}},
		{"RB create cronjobs", cat(role(rule([]string{"create"}, []string{"batch"}, []string{"cronjobs"})), rb("r", web)), []string{"service account can create workloads in namespace apps"}},
		{"deployments in wrong group", cat(role(rule([]string{"create"}, []string{"batch"}, []string{"deployments"})), crb("r", web)), nil},
		{"RB create pods/exec", cat(role(rule([]string{"create"}, []string{""}, []string{"pods/exec"})), rb("r", web)), []string{"service account can exec into pods in namespace apps"}},
		{"get */exec", cat(role(rule([]string{"get"}, []string{""}, []string{"*/exec"})), crb("r", web)), []string{"service account can exec into pods"}},
		{"CRB get nodes/proxy", cat(role(rule([]string{"get"}, []string{""}, []string{"nodes/proxy"})), crb("r", web)), []string{"service account can proxy to nodes"}},
		{"escalate bind impersonate", cat(role(rule([]string{"escalate", "bind", "impersonate"}, []string{"rbac.authorization.k8s.io"}, []string{"clusterroles"})), crb("r", web)),
			[]string{"service account can bind roles", "service account can escalate roles", "service account can impersonate"}},
		{"group serviceaccounts:apps", cat(role(rule([]string{"create"}, []string{""}, []string{"pods"})),
			crb("r", rbacv1.Subject{Kind: rbacv1.GroupKind, Name: "system:serviceaccounts:apps"})), []string{"service account can create pods"}},
		{"group serviceaccounts", cat(role(rule([]string{"create"}, []string{""}, []string{"pods"})),
			crb("r", rbacv1.Subject{Kind: rbacv1.GroupKind, Name: "system:serviceaccounts"})), []string{"service account can create pods"}},
		{"group authenticated", cat(role(rule([]string{"create"}, []string{""}, []string{"pods"})),
			crb("r", rbacv1.Subject{Kind: rbacv1.GroupKind, Name: "system:authenticated"})), []string{"service account can create pods"}},
		{"other namespace's serviceaccounts group", cat(role(rule([]string{"create"}, []string{""}, []string{"pods"})),
			crb("r", rbacv1.Subject{Kind: rbacv1.GroupKind, Name: "system:serviceaccounts:other"})), nil},
		{"other service account", cat(role(rule(star, star, star)), crb("r", saSubject("apps", "other"))), nil},
		{"same name other namespace", cat(role(rule(star, star, star)), crb("r", saSubject("elsewhere", "web"))), nil},
		{"missing role", crb("gone", web), nil},
		{"rules limited by resourceNames", cat(role(rbacv1.PolicyRule{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{"one"}}),
			crb("r", web)), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := fake.NewClientBuilder().WithScheme(testScheme(t, false)).WithObjects(tc.objs...).Build()
			w := workload()
			w.Ref.Namespace, w.ServiceAccount = "apps", "web"
			got, err := New(c, config.ExposureConfig{}).Context(context.Background(), w)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got.SAReasons, tc.want) || got.PowerfulSA != (len(tc.want) > 0) {
				t.Fatalf("reasons %q powerful=%v, want %q", got.SAReasons, got.PowerfulSA, tc.want)
			}
		})
	}
}

func TestServiceAccountPower_DefaultName(t *testing.T) {
	objs := crb("cluster-admin", saSubject("apps", "default"))
	c := fake.NewClientBuilder().WithScheme(testScheme(t, false)).WithObjects(objs...).Build()
	w := workload()
	w.Ref.Namespace = "apps"
	got, err := New(c, config.ExposureConfig{}).Context(context.Background(), w)
	if err != nil || !got.PowerfulSA {
		t.Fatalf("got %+v, err %v", got, err)
	}
}
