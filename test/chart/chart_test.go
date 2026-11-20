package chart

import (
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/the-it-dept/ffs/internal/config"
)

func podSpec(t *testing.T, sets ...string) corev1.PodSpec {
	t.Helper()
	return as[appsv1.Deployment](t, render(t, sets...).get(t, "Deployment", "ffs")).Spec.Template.Spec
}

func container(t *testing.T, ps corev1.PodSpec, name string) corev1.Container {
	t.Helper()
	for _, c := range ps.Containers {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("container %q not found", name)
	return corev1.Container{}
}

func mounts(c corev1.Container) map[string]corev1.VolumeMount {
	m := map[string]corev1.VolumeMount{}
	for _, v := range c.VolumeMounts {
		m[v.Name] = v
	}
	return m
}

func volumes(ps corev1.PodSpec) map[string]corev1.Volume {
	m := map[string]corev1.Volume{}
	for _, v := range ps.Volumes {
		m[v.Name] = v
	}
	return m
}

func TestChart_Lint(t *testing.T) {
	requireHelm(t)
	out, err := exec.CommandContext(t.Context(), "helm", "lint", "--strict", "--kube-version", kubeVersion, chartDir).CombinedOutput()
	require.NoError(t, err, string(out))
}

func TestChart_DeploymentShape(t *testing.T) {
	d := as[appsv1.Deployment](t, render(t).get(t, "Deployment", "ffs"))
	require.EqualValues(t, 1, *d.Spec.Replicas)
	require.Equal(t, appsv1.RecreateDeploymentStrategyType, d.Spec.Strategy.Type)
	ps := d.Spec.Template.Spec
	require.Len(t, ps.Containers, 2)
	require.Equal(t, "controller", ps.Containers[0].Name)
	require.Equal(t, "catalog", ps.Containers[1].Name)
	ctl, cat := ps.Containers[0], ps.Containers[1]
	require.Equal(t, ctl.Image, cat.Image)
	require.Equal(t, []string{"controller", "--config=/etc/ffs/config.yaml"}, ctl.Args)
	require.Equal(t, []string{"catalog", "--socket=/run/ffs/catalog.sock", "--scratch=/tmp", "--scratch-limit=19327352832", "--max-concurrent=2"}, cat.Args)

	cm := mounts(ctl)
	require.Equal(t, "/etc/ffs", cm["config"].MountPath)
	require.True(t, cm["config"].ReadOnly)
	require.Equal(t, "/run/ffs", cm["run"].MountPath)
	require.Equal(t, "/var/lib/ffs", cm["data"].MountPath)
	require.Equal(t, "/tmp", cm["tmp"].MountPath)
	am := mounts(cat)
	require.Equal(t, "/run/ffs", am["run"].MountPath)
	require.Equal(t, "/tmp", am["scratch"].MountPath)
	require.NotContains(t, am, "config")
	require.NotContains(t, am, "data")

	v := volumes(ps)
	require.NotNil(t, v["run"].EmptyDir)
	require.Nil(t, v["run"].EmptyDir.SizeLimit)
	require.Equal(t, resource.MustParse("20Gi"), *v["scratch"].EmptyDir.SizeLimit)
	require.Equal(t, resource.MustParse("1Gi"), *v["tmp"].EmptyDir.SizeLimit)
	require.Equal(t, "ffs", v["data"].PersistentVolumeClaim.ClaimName)
	require.Equal(t, "ffs", v["config"].ConfigMap.Name)

	for _, c := range ps.Containers {
		require.Len(t, c.Env, 1, c.Name)
		require.Equal(t, "GOMEMLIMIT", c.Env[0].Name)
	}
	require.Equal(t, "966367641", ctl.Env[0].Value, "90% of the controller's 1Gi limit")
	ref := cat.Env[0].ValueFrom.ResourceFieldRef
	require.Equal(t, "catalog", ref.ContainerName)
	require.Equal(t, "limits.memory", ref.Resource)
	reqs := func(c corev1.Container) (string, string, string, bool) {
		return c.Resources.Requests.Cpu().String(), c.Resources.Requests.Memory().String(),
			c.Resources.Limits.Memory().String(), c.Resources.Limits.Cpu().IsZero()
	}
	cpu, mem, lim, noCPU := reqs(ctl)
	require.Equal(t, []any{"200m", "512Mi", "1Gi", true}, []any{cpu, mem, lim, noCPU})
	cpu, mem, lim, noCPU = reqs(cat)
	require.Equal(t, []any{"100m", "256Mi", "2Gi", true}, []any{cpu, mem, lim, noCPU})

	ports := map[string]int32{}
	for _, p := range ctl.Ports {
		ports[p.Name] = p.ContainerPort
	}
	require.Equal(t, map[string]int32{"http": 8080, "metrics": 8443, "health": 8081, "agent-api": 8444}, ports)
	require.Equal(t, "/healthz", ctl.LivenessProbe.HTTPGet.Path)
	require.EqualValues(t, 8081, ctl.LivenessProbe.HTTPGet.Port.IntVal)
	require.Equal(t, "/readyz", ctl.ReadinessProbe.HTTPGet.Path)
	require.EqualValues(t, 8081, ctl.ReadinessProbe.HTTPGet.Port.IntVal)

	require.Contains(t, d.Spec.Template.Annotations, "checksum/config")
	require.NotNil(t, ps.EnableServiceLinks)
	require.False(t, *ps.EnableServiceLinks)
	for _, c := range ps.Containers {
		for _, e := range c.Env {
			require.NotContains(t, []string{"POD_NAME", "POD_NAMESPACE"}, e.Name)
		}
	}
}

func TestChart_MountsFollowConfig(t *testing.T) {
	ps := podSpec(t, "config.dataDir=/data", "config.storePath=/data/ffs.db", "config.catalog.socket=/sock/c.sock")
	ctl, cat := container(t, ps, "controller"), container(t, ps, "catalog")
	require.Equal(t, "/data", mounts(ctl)["data"].MountPath)
	require.Equal(t, "/sock", mounts(ctl)["run"].MountPath)
	require.Equal(t, "/sock", mounts(cat)["run"].MountPath)
	require.Contains(t, cat.Args, "--socket=/sock/c.sock")

	ps = podSpec(t, "catalog.scratchLimit=1887436800")
	require.Contains(t, container(t, ps, "catalog").Args, "--scratch-limit=1887436800")
}

func TestChart_StorePathMustBeUnderDataDir(t *testing.T) {
	out, err := renderErr(t, "config.dataDir=/data")
	require.Error(t, err)
	require.Contains(t, out, "must be under config.dataDir")

	_, err = renderErr(t, "config.dataDir=/data", "config.storePath=/database/ffs.db")
	require.Error(t, err)
}

func TestChart_SecurityContext(t *testing.T) {
	ps := podSpec(t)
	sc := ps.SecurityContext
	require.True(t, *sc.RunAsNonRoot)
	require.EqualValues(t, 65532, *sc.RunAsUser)
	require.EqualValues(t, 65532, *sc.RunAsGroup)
	require.EqualValues(t, 65532, *sc.FSGroup)
	require.Equal(t, corev1.FSGroupChangeOnRootMismatch, *sc.FSGroupChangePolicy)
	require.Equal(t, corev1.SeccompProfileTypeRuntimeDefault, sc.SeccompProfile.Type)
	require.False(t, ps.HostNetwork)
	require.False(t, ps.HostPID)
	require.False(t, ps.HostIPC)
	for _, c := range ps.Containers {
		s := c.SecurityContext
		require.True(t, *s.ReadOnlyRootFilesystem, c.Name)
		require.False(t, *s.AllowPrivilegeEscalation, c.Name)
		require.Equal(t, []corev1.Capability{"ALL"}, s.Capabilities.Drop, c.Name)
		require.Empty(t, s.Capabilities.Add, c.Name)
		require.True(t, s.Privileged == nil || !*s.Privileged, c.Name)
	}
}

func TestChart_CatalogHasNoAPIToken(t *testing.T) {
	ps := podSpec(t)
	require.NotNil(t, ps.AutomountServiceAccountToken)
	require.False(t, *ps.AutomountServiceAccountToken)
	const dir = "/var/run/secrets/kubernetes.io/serviceaccount"
	m := mounts(container(t, ps, "controller"))["kube-api-access"]
	require.Equal(t, dir, m.MountPath)
	require.True(t, m.ReadOnly)
	p := volumes(ps)["kube-api-access"].Projected
	require.NotNil(t, p)
	require.Len(t, p.Sources, 3)
	tok := p.Sources[0].ServiceAccountToken
	require.Equal(t, "token", tok.Path)
	require.EqualValues(t, 3607, *tok.ExpirationSeconds)
	require.Equal(t, "kube-root-ca.crt", p.Sources[1].ConfigMap.Name)
	require.Equal(t, "ca.crt", p.Sources[1].ConfigMap.Items[0].Key)
	require.Equal(t, "namespace", p.Sources[2].DownwardAPI.Items[0].Path)
	for _, mt := range container(t, ps, "catalog").VolumeMounts {
		require.False(t, strings.HasPrefix(mt.MountPath, "/var/run/secrets"), mt.MountPath)
	}
}

func TestChart_PersistenceExistingClaim(t *testing.T) {
	o := render(t)
	pvc := as[corev1.PersistentVolumeClaim](t, o.get(t, "PersistentVolumeClaim", "ffs"))
	require.Equal(t, resource.MustParse("20Gi"), pvc.Spec.Resources.Requests[corev1.ResourceStorage])
	require.Equal(t, []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}, pvc.Spec.AccessModes)

	o = render(t, "persistence.existingClaim=mine")
	require.False(t, o.has("PersistentVolumeClaim", "ffs"))
	d := as[appsv1.Deployment](t, o.get(t, "Deployment", "ffs"))
	require.Equal(t, "mine", volumes(d.Spec.Template.Spec)["data"].PersistentVolumeClaim.ClaimName)
}

func TestChart_ConfigRoundTrips(t *testing.T) {
	path := writeTemp(t, renderedConfig(t, render(t)))
	got, err := config.Load(path)
	require.NoError(t, err)
	require.Empty(t, cmp.Diff(config.Default(), got, cmpopts.EquateEmpty()))
}

func hasPath(m map[string]any, path string) bool {
	var cur any = m
	for _, k := range strings.Split(path, ".") {
		mm, ok := cur.(map[string]any)
		if !ok {
			return false
		}
		if cur, ok = mm[k]; !ok {
			return false
		}
	}
	return true
}

func TestChart_ConfigCoversEveryField(t *testing.T) {
	var m map[string]any
	require.NoError(t, yaml.Unmarshal([]byte(renderedConfig(t, render(t))), &m))
	for _, p := range config.FieldPaths() {
		require.True(t, hasPath(m, p), "rendered config.yaml lacks %s", p)
	}
}

type rule struct{ group, resource, verb string }

func ruleSet(rules []rbacv1.PolicyRule) map[rule]bool {
	s := map[rule]bool{}
	for _, r := range rules {
		for _, g := range r.APIGroups {
			for _, res := range r.Resources {
				for _, v := range r.Verbs {
					s[rule{g, res, v}] = true
				}
			}
		}
	}
	return s
}

func clusterRole(t *testing.T, o objs, name string) rbacv1.ClusterRole {
	t.Helper()
	return as[rbacv1.ClusterRole](t, o.get(t, "ClusterRole", name))
}

func TestChart_ControllerRBACIsReadMostly(t *testing.T) {
	o := render(t, "config.openReports.wgPolicy=true")
	cr := clusterRole(t, o, "ffs")
	role := as[rbacv1.Role](t, o.get(t, "Role", "ffs"))
	read := map[string]bool{"get": true, "list": true, "watch": true}

	writable := map[string]map[string]bool{
		"ffs.theitdept.au": {"findings": true, "vulnerabilities": true, "findings/status": true, "vulnerabilities/status": true,
			"alerttargets/status": true, "exceptions/status": true},
		"events.k8s.io":       {"events": true},
		"openreports.io":      {"reports": true},
		"wgpolicyk8s.io":      {"policyreports": true},
		"coordination.k8s.io": {"leases": true},
	}
	reads := map[string][]string{}
	for _, pr := range []struct {
		name  string
		rules []rbacv1.PolicyRule
	}{{"ClusterRole", cr.Rules}, {"Role", role.Rules}} {
		for r := range ruleSet(pr.rules) {
			require.NotEqual(t, "*", r.group)
			require.NotEqual(t, "*", r.resource)
			require.NotEqual(t, "*", r.verb)
			require.NotContains(t, []string{"pods/exec", "pods/attach", "pods/portforward", "nodes/proxy", "serviceaccounts/token"}, r.resource)
			if pr.name == "ClusterRole" {
				require.NotEqual(t, "secrets", r.resource)
			}
			if !read[r.verb] {
				require.True(t, writable[r.group][r.resource], "%s may not %s %s/%s", pr.name, r.verb, r.group, r.resource)
				continue
			}
			if pr.name == "ClusterRole" && r.verb == "get" && r.group != "wgpolicyk8s.io" && !strings.Contains(r.resource, "/") {
				reads[r.group] = append(reads[r.group], r.resource)
			}
		}
	}
	// alerttargets and exceptions are read-only; only /status is writable.
	for r := range ruleSet(cr.Rules) {
		if r.group == "ffs.theitdept.au" && (r.resource == "alerttargets" || r.resource == "exceptions") {
			require.True(t, read[r.verb], r)
		}
	}
	for _, v := range reads {
		slices.Sort(v)
	}
	want := map[string][]string{
		"":                            {"pods", "nodes", "namespaces", "services", "serviceaccounts"},
		"discovery.k8s.io":            {"endpointslices"},
		"apps":                        {"deployments", "statefulsets", "daemonsets", "replicasets"},
		"batch":                       {"jobs", "cronjobs"},
		"networking.k8s.io":           {"ingresses", "ingressclasses"},
		"gateway.networking.k8s.io":   {"gateways", "gatewayclasses", "httproutes", "grpcroutes", "tlsroutes", "tcproutes", "udproutes"},
		"rbac.authorization.k8s.io":   {"roles", "clusterroles", "rolebindings", "clusterrolebindings"},
		"helm.toolkit.fluxcd.io":      {"helmreleases"},
		"kustomize.toolkit.fluxcd.io": {"kustomizations"},
		"argoproj.io":                 {"applications"},
		"ffs.theitdept.au":            {"findings", "vulnerabilities", "alerttargets", "exceptions"},
		"openreports.io":              {"reports"},
	}
	for _, v := range want {
		slices.Sort(v)
	}
	require.Equal(t, want, reads)

	// wgpolicyk8s.io only when enabled.
	for _, s := range []string{"false"} {
		cr := clusterRole(t, render(t, "config.openReports.wgPolicy="+s), "ffs")
		for r := range ruleSet(cr.Rules) {
			require.NotEqual(t, "wgpolicyk8s.io", r.group)
		}
	}
	// The Role: leases and secrets get only.
	rs := ruleSet(role.Rules)
	require.True(t, rs[rule{"", "secrets", "get"}])
	for r := range rs {
		if r.resource == "secrets" {
			require.Equal(t, "get", r.verb)
		}
	}
}

func TestChart_PullSecretsToggle(t *testing.T) {
	o := render(t)
	cr := clusterRole(t, o, "ffs-pull-secrets")
	require.Equal(t, []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}}}, cr.Rules)
	crb := as[rbacv1.ClusterRoleBinding](t, o.get(t, "ClusterRoleBinding", "ffs-pull-secrets"))
	require.Equal(t, "ffs-pull-secrets", crb.RoleRef.Name)
	require.Equal(t, []rbacv1.Subject{{Kind: "ServiceAccount", Name: "ffs", Namespace: "ffs"}}, crb.Subjects)
	require.Contains(t, renderedConfig(t, o), "readPullSecrets: true")

	o = render(t, "rbac.readPullSecrets=false")
	require.False(t, o.has("ClusterRole", "ffs-pull-secrets"))
	require.False(t, o.has("ClusterRoleBinding", "ffs-pull-secrets"))
	require.Contains(t, renderedConfig(t, o), "readPullSecrets: false")

	role := as[rbacv1.Role](t, o.get(t, "Role", "ffs"))
	require.Equal(t, "ffs", role.Namespace)
	for r := range ruleSet(role.Rules) {
		if r.resource == "secrets" {
			require.Equal(t, "get", r.verb)
		}
	}
}

func aggregateLabels(cr rbacv1.ClusterRole) []string {
	var l []string
	for k := range cr.Labels {
		if strings.HasPrefix(k, "rbac.authorization.k8s.io/aggregate-to-") {
			l = append(l, k)
		}
	}
	slices.Sort(l)
	return l
}

func verbsOf(cr rbacv1.ClusterRole, resource string) []string {
	var v []string
	for r := range ruleSet(cr.Rules) {
		if r.resource == resource {
			v = append(v, r.verb)
		}
	}
	slices.Sort(v)
	return v
}

func TestChart_UserRoles(t *testing.T) {
	o := render(t)
	rd := []string{"get", "list", "watch"}
	view := clusterRole(t, o, "ffs-view")
	require.Equal(t, "true", view.Labels["rbac.authorization.k8s.io/aggregate-to-view"])
	for _, r := range []string{"findings", "exceptions"} {
		require.Equal(t, rd, verbsOf(view, r))
	}
	require.Len(t, ruleSet(view.Rules), 6)

	edit := clusterRole(t, o, "ffs-edit")
	require.Equal(t, []string{"rbac.authorization.k8s.io/aggregate-to-admin", "rbac.authorization.k8s.io/aggregate-to-edit"}, aggregateLabels(edit))
	require.Equal(t, []string{"create", "delete", "deletecollection", "patch", "update"}, verbsOf(edit, "exceptions"))
	require.Len(t, ruleSet(edit.Rules), 5)

	cr := clusterRole(t, o, "ffs-cluster-reader")
	require.Empty(t, aggregateLabels(cr))
	for _, r := range []string{"findings", "vulnerabilities", "alerttargets", "exceptions"} {
		require.Equal(t, rd, verbsOf(cr, r))
	}
	adm := clusterRole(t, o, "ffs-admin")
	require.Empty(t, aggregateLabels(adm))
	all := []string{"create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"}
	for _, r := range []string{"alerttargets", "exceptions"} {
		require.Equal(t, all, verbsOf(adm, r))
	}
	for _, r := range []string{"findings", "vulnerabilities"} {
		require.Equal(t, rd, verbsOf(adm, r))
	}
	for r := range ruleSet(adm.Rules) {
		require.NotEqual(t, "*", r.verb)
	}
}

func TestChart_OptionalMonitoring(t *testing.T) {
	o := render(t)
	require.False(t, o.has("PrometheusRule", "ffs"))
	require.False(t, o.has("ServiceMonitor", "ffs"))
	require.False(t, o.has("Service", "ffs-metrics"))
	require.False(t, o.has("ConfigMap", "ffs-grafana-dashboard"))

	auth := ruleSet(clusterRole(t, o, "ffs-metrics-auth").Rules)
	require.Equal(t, map[rule]bool{
		{"authentication.k8s.io", "tokenreviews", "create"}:        true,
		{"authorization.k8s.io", "subjectaccessreviews", "create"}: true,
	}, auth)
	crb := as[rbacv1.ClusterRoleBinding](t, o.get(t, "ClusterRoleBinding", "ffs-metrics-auth"))
	require.Equal(t, []rbacv1.Subject{{Kind: "ServiceAccount", Name: "ffs", Namespace: "ffs"}}, crb.Subjects)
	rdr := clusterRole(t, o, "ffs-metrics-reader")
	require.Equal(t, []rbacv1.PolicyRule{{NonResourceURLs: []string{"/metrics"}, Verbs: []string{"get"}}}, rdr.Rules)
	require.False(t, o.has("ClusterRoleBinding", "ffs-metrics-reader"))

	o = render(t, "metrics.serviceMonitor.enabled=true")
	svc := as[corev1.Service](t, o.get(t, "Service", "ffs-metrics"))
	require.Len(t, svc.Spec.Ports, 1)
	require.EqualValues(t, 8443, svc.Spec.Ports[0].Port)
	require.Equal(t, "metrics", svc.Spec.Ports[0].Name)
	sm := o.get(t, "ServiceMonitor", "ffs")
	eps, _, _ := unstructured.NestedSlice(sm.Object, "spec", "endpoints")
	require.Len(t, eps, 1)
	ep := eps[0].(map[string]any)
	require.Equal(t, "metrics", ep["port"])
	require.Equal(t, "https", ep["scheme"])
	require.Equal(t, "/var/run/secrets/kubernetes.io/serviceaccount/token", ep["bearerTokenFile"])
	require.Equal(t, true, ep["tlsConfig"].(map[string]any)["insecureSkipVerify"])
	require.Equal(t, "60s", ep["interval"])

	o = render(t, "prometheusRule.enabled=true")
	groups, ok, _ := unstructured.NestedSlice(o.get(t, "PrometheusRule", "ffs").Object, "spec", "groups")
	require.True(t, ok)
	require.NotEmpty(t, groups)

	o = render(t, "grafanaDashboard.enabled=true", "grafanaDashboard.namespace=monitoring")
	cm := o.get(t, "ConfigMap", "ffs-grafana-dashboard")
	require.Equal(t, "monitoring", cm.GetNamespace())
	require.Equal(t, "1", cm.GetLabels()["grafana_dashboard"])
	data := as[corev1.ConfigMap](t, cm).Data["ffs.json"]
	require.True(t, json.Valid([]byte(data)))
}

func TestChart_WebServiceNeedsNonLoopbackListen(t *testing.T) {
	_, err := renderErr(t, "web.service.enabled=true")
	require.ErrorContains(t, err, "web.service.enabled needs config.listen bound beyond loopback")
	o := render(t, "web.service.enabled=true", "config.listen=0.0.0.0:8080")
	require.True(t, o.has("Service", "ffs-web"))
}

func TestChart_ImageDigestPinned(t *testing.T) {
	dg := "sha256:" + strings.Repeat("a", 64)
	ps := podSpec(t, "image.digest="+dg)
	for _, c := range ps.Containers {
		require.Equal(t, "ghcr.io/the-it-dept/ffs@"+dg, c.Image)
	}
	var chart struct {
		AppVersion string `yaml:"appVersion"`
	}
	require.NoError(t, yaml.Unmarshal([]byte(readFile(t, chartDir+"/Chart.yaml")), &chart))
	for _, c := range podSpec(t).Containers {
		require.Equal(t, "ghcr.io/the-it-dept/ffs:"+chart.AppVersion, c.Image)
	}
}

func TestChart_CRDsMatchGenerated(t *testing.T) {
	names := func(dir string) []string {
		m, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
		require.NoError(t, err)
		for i := range m {
			m[i] = filepath.Base(m[i])
		}
		slices.Sort(m)
		return m
	}
	gen := names("../../config/crd/bases")
	require.NotEmpty(t, gen)
	require.Equal(t, gen, names(chartDir+"/crds"))
	for _, n := range gen {
		require.Equal(t, readFile(t, "../../config/crd/bases/"+n), readFile(t, chartDir+"/crds/"+n), n)
	}
}

func TestChart_NotesAndHiddenCategory(t *testing.T) {
	notes := readFile(t, chartDir+"/templates/NOTES.txt")
	require.Contains(t, notes, `kubectl -n {{ .Release.Namespace }} port-forward deploy/{{ include "ffs.fullname" . }} 8080`)
	require.Contains(t, notes, "http://127.0.0.1:8080")
	hidden := "anx" + "iety"
	require.NoError(t, filepath.WalkDir(chartDir, func(p string, d fs.DirEntry, err error) error {
		require.NoError(t, err)
		if d.IsDir() {
			if d.Name() == "crds" {
				return filepath.SkipDir
			}
			return nil
		}
		b, err := os.ReadFile(p) //nolint:gosec // chart file walk
		require.NoError(t, err)
		require.NotContains(t, strings.ToLower(string(b)), hidden, p)
		return nil
	}))
}

// TestChart_ServiceMonitorHonorsLabels pins honorLabels on the ServiceMonitor (F35): the finding
// metrics carry the workload's namespace, which the target's namespace label must not replace.
func TestChart_ServiceMonitorHonorsLabels(t *testing.T) {
	sm := render(t, "metrics.serviceMonitor.enabled=true").get(t, "ServiceMonitor", "ffs")
	eps, _, _ := unstructured.NestedSlice(sm.Object, "spec", "endpoints")
	require.Len(t, eps, 1)
	require.Equal(t, true, eps[0].(map[string]any)["honorLabels"])
}

// TestChart_ScratchLimitQuantities is the regression test for F16: a quantity such as 18Gi used to
// render --scratch-limit=0, which the cataloguer reads as unlimited.
// TestChart_ControllerGoMemLimit checks the controller's GOMEMLIMIT is 90% of its memory limit, so
// memory the Go runtime does not count (SQLite's, mostly) fits under the limit too, and that without
// a limit it falls back to the container's allocatable memory.
func TestChart_ControllerGoMemLimit(t *testing.T) {
	env := func(sets ...string) corev1.EnvVar {
		t.Helper()
		c := container(t, podSpec(t, sets...), "controller")
		require.Len(t, c.Env, 1)
		require.Equal(t, "GOMEMLIMIT", c.Env[0].Name)
		return c.Env[0]
	}
	require.Equal(t, "966367641", env().Value)
	require.Equal(t, "1449551462", env("controller.resources.limits.memory=1536Mi").Value)
	require.Equal(t, "1800000000", env("controller.resources.limits.memory=2G").Value)
	e := env("controller.resources.limits=null")
	require.Empty(t, e.Value)
	e = env("controller.resources=null")
	require.Empty(t, e.Value)
	require.Equal(t, "limits.memory", e.ValueFrom.ResourceFieldRef.Resource)
	require.Equal(t, "controller", e.ValueFrom.ResourceFieldRef.ContainerName)

	_, err := renderErr(t, "controller.resources.limits.memory=1.5Gi")
	require.ErrorContains(t, err, "controller.resources.limits.memory must be a byte count or a quantity such as 18Gi")
}

func TestChart_ScratchLimitQuantities(t *testing.T) {
	limit := func(sets ...string) string {
		t.Helper()
		for _, a := range container(t, podSpec(t, sets...), "catalog").Args {
			if v, ok := strings.CutPrefix(a, "--scratch-limit="); ok {
				return v
			}
		}
		t.Fatal("no --scratch-limit argument")
		return ""
	}
	require.Equal(t, "19327352832", limit(), "the default byte count")
	require.Equal(t, "19327352832", limit("catalog.scratchLimit=18Gi"))
	require.Equal(t, "19327352832", limit("catalog.scratchLimit=19327352832"))
	require.Equal(t, "15000000000", limit("catalog.scratchLimit=15G"))
	require.Equal(t, "1073741824", limit("catalog.scratchLimit=1Gi", "catalog.scratchSizeLimit=2Gi"))

	values := filepath.Join(t.TempDir(), "values.yaml")
	require.NoError(t, os.WriteFile(values, []byte("catalog:\n  scratchLimit: 18Gi\n"), 0o600))
	args := []string{"template", "ffs", chartDir, "-n", "ffs", "--kube-version", kubeVersion, "-f", values}
	out, err := exec.CommandContext(t.Context(), "helm", args...).CombinedOutput() //nolint:gosec // helm with a values file this test wrote
	require.NoError(t, err, string(out))
	require.Contains(t, string(out), "--scratch-limit=19327352832", "a quantity in a values file")

	for _, c := range []struct{ set, want string }{
		{"catalog.scratchLimit=0", "catalog.scratchLimit must be greater than 0"},
		{"catalog.scratchLimit=20Gi", "catalog.scratchLimit (21474836480 bytes) must be below catalog.scratchSizeLimit (21474836480 bytes)"},
		{"catalog.scratchLimit=25Gi", "must be below catalog.scratchSizeLimit"},
		{"catalog.scratchLimit=18GB", "catalog.scratchLimit must be a byte count or a quantity such as 18Gi"},
		{"catalog.scratchLimit=1.5Gi", "catalog.scratchLimit must be a byte count or a quantity such as 18Gi"},
	} {
		_, err := renderErr(t, c.set)
		require.ErrorContains(t, err, c.want, c.set)
	}
}

// TestChart_WebServiceLoopbackGuardAndHosts covers the F11 chart side: the loopback guard knows
// localhost and [::1], and a dashboard Service adds its own DNS names to config.allowedHosts so a
// proxy that forwards the Service name is answered.
func TestChart_WebServiceLoopbackGuardAndHosts(t *testing.T) {
	for _, listen := range []string{"localhost:8080", "[::1]:8080", "127.0.0.2:8080"} {
		_, err := renderErr(t, "web.service.enabled=true", "config.listen="+listen)
		require.ErrorContains(t, err, "web.service.enabled needs config.listen bound beyond loopback", listen)
	}
	var c config.Config
	require.NoError(t, yaml.Unmarshal([]byte(renderedConfig(t, render(t))), &c))
	require.Empty(t, c.AllowedHosts)

	o := render(t, "web.service.enabled=true", "config.listen=0.0.0.0:8080", "config.allowedHosts={ffs.example.com}")
	require.NoError(t, yaml.Unmarshal([]byte(renderedConfig(t, o)), &c))
	require.Equal(t, []string{"ffs.example.com", "ffs-web", "ffs-web.ffs", "ffs-web.ffs.svc", "ffs-web.ffs.svc.cluster.local"}, c.AllowedHosts)
	path := writeTemp(t, renderedConfig(t, o))
	_, err := config.Load(path)
	require.NoError(t, err)
}

func TestChart_NodeAgentConfig(t *testing.T) {
	o := render(t, "nodeAgent.enabled=false", "nodeAgent.port=9444", "nodeAgent.namespace=node-agents",
		"nodeAgent.exposedNodes=node-role.example.com/edge", "nodeAgent.staleAfter=1h", "nodeAgent.maxReportBytes=64Mi")
	c, err := config.Load(writeTemp(t, renderedConfig(t, o)))
	require.NoError(t, err)
	require.Equal(t, config.NodeAgentConfig{Enabled: false, Listen: ":9444", CertDir: "/etc/ffs/agent-tls",
		Namespace: "node-agents", ServiceAccount: "ffs-agent", MaxReportBytes: 64 << 20, ReportInterval: 6 * time.Hour,
		ImageListInterval: 5 * time.Minute, StaleAfter: time.Hour, RuntimeGrace: 2 * time.Hour, WorkPerReport: 3,
		WorkTimeout: 30 * time.Minute, ExposedNodes: "node-role.example.com/edge", Architectures: []string{"amd64"},
		NodeSelector: map[string]string{"kubernetes.io/os": "linux"}}, c.NodeAgent)

	o = render(t, "nodeAgent.architectures={amd64,arm64}", "nodeAgent.nodeSelector.pool=general")
	c, err = config.Load(writeTemp(t, renderedConfig(t, o)))
	require.NoError(t, err)
	require.Equal(t, []string{"amd64", "arm64"}, c.NodeAgent.Architectures)
	require.Equal(t, map[string]string{"kubernetes.io/os": "linux", "pool": "general"}, c.NodeAgent.NodeSelector)

	o = render(t, "config.nodeAgent.listen=:1") // the top-level nodeAgent values win
	c, err = config.Load(writeTemp(t, renderedConfig(t, o)))
	require.NoError(t, err)
	require.Equal(t, ":8444", c.NodeAgent.Listen)
}
