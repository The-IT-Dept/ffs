package chart

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	containerdStore = "/var/lib/containerd/io.containerd.content.v1.content"
	k3sStore        = "/var/lib/rancher/k3s/agent/containerd/io.containerd.content.v1.content"
	rke2Store       = "/var/lib/rancher/rke2/agent/containerd/io.containerd.content.v1.content"
	// testCABundle is a CA bundle as the chart passes it through, without parsing it.
	testCABundle = "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUZmZzLWFnZW50LWNh\n-----END CERTIFICATE-----\n"
)

func daemonSet(t *testing.T, sets ...string) appsv1.DaemonSet {
	t.Helper()
	return as[appsv1.DaemonSet](t, render(t, sets...).get(t, "DaemonSet", "ffs-agent"))
}

// hostMounts returns the DaemonSet's hostPath volumes, host path → hostPath type ("" when unset), after
// asserting that each is mounted once, by the collector only, at /host<path>, read-only, without propagation.
func hostMounts(t *testing.T, ds appsv1.DaemonSet) map[string]string {
	t.Helper()
	ps := ds.Spec.Template.Spec
	require.Empty(t, ps.InitContainers)
	out := map[string]string{}
	for _, v := range ps.Volumes {
		if v.HostPath == nil {
			continue
		}
		typ := ""
		if v.HostPath.Type != nil {
			typ = string(*v.HostPath.Type)
		}
		out[v.HostPath.Path] = typ
		n := 0
		for _, c := range ps.Containers {
			for _, m := range c.VolumeMounts {
				if m.Name != v.Name {
					continue
				}
				n++
				require.Equal(t, "collector", c.Name, "%s is mounted by %s", v.Name, c.Name)
				require.Equal(t, "/host"+v.HostPath.Path, m.MountPath)
				require.True(t, m.ReadOnly, v.Name)
				require.NotNil(t, m.MountPropagation, v.Name)
				require.Equal(t, corev1.MountPropagationNone, *m.MountPropagation, v.Name)
			}
		}
		require.Equal(t, 1, n, "%s is mounted once", v.Name)
	}
	return out
}

func agentContainer(t *testing.T, ds appsv1.DaemonSet, name string) corev1.Container {
	t.Helper()
	return container(t, ds.Spec.Template.Spec, name)
}

// copyChart copies the chart into a temporary directory, adding the given templates.
func copyChart(t *testing.T, templates map[string]string) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "ffs")
	require.NoError(t, filepath.WalkDir(chartDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(chartDir, p)
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o750)
		}
		b, err := os.ReadFile(p) //nolint:gosec // chart file walk
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o600) //nolint:gosec // rel comes from walking the chart's own files
	}))
	for name, body := range templates {
		require.NoError(t, os.WriteFile(filepath.Join(dst, "templates", name), []byte(body), 0o600))
	}
	return dst
}

// helperResults renders the chart copy with values and returns data.result of each ConfigMap "<prefix>-<i>".
func helperResults(t *testing.T, dir string, values any, prefix string, n int) []string {
	t.Helper()
	b, err := yaml.Marshal(values)
	require.NoError(t, err)
	vf := filepath.Join(t.TempDir(), "values.yaml")
	require.NoError(t, os.WriteFile(vf, b, 0o600))
	out, err := helmTemplateChart(t, dir, "-f", vf)
	require.NoError(t, err, out)
	o := decodeObjs(t, out)
	results := make([]string, n)
	for i := range n {
		results[i] = as[corev1.ConfigMap](t, o.get(t, "ConfigMap", fmt.Sprintf("%s-%d", prefix, i))).Data["result"]
	}
	return results
}

func TestChart_AgentDisabledRendersNothing(t *testing.T) {
	o := render(t, "nodeAgent.enabled=false")
	for _, u := range o {
		require.False(t, strings.HasPrefix(u.GetName(), "ffs-agent"), "%s %s rendered", u.GetKind(), u.GetName())
	}
	ps := as[appsv1.Deployment](t, o.get(t, "Deployment", "ffs")).Spec.Template.Spec
	ports := map[string]bool{}
	for _, p := range container(t, ps, "controller").Ports {
		ports[p.Name] = true
	}
	require.Equal(t, map[string]bool{"http": true, "metrics": true, "health": true}, ports)
	require.NotContains(t, volumes(ps), "agent-tls")
	require.NotContains(t, mounts(container(t, ps, "controller")), "agent-tls")
}

func TestChart_AgentSecurityPosture(t *testing.T) {
	allowed := []string{"/etc/os-release", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/var/lib/dpkg", "/var/lib/rpm", "/lib/apk/db",
		"/var/lib/rancher/k3s/data", "/var/lib/rancher/rke2/bin", containerdStore, k3sStore, rke2Store}
	for _, sets := range [][]string{nil, {"nodeAgent.distribution=k3s"}, {"nodeAgent.distribution=rke2"}, {"nodeAgent.distribution=crio"}} {
		o := render(t, sets...)
		ds := as[appsv1.DaemonSet](t, o.get(t, "DaemonSet", "ffs-agent"))
		for p := range hostMounts(t, ds) {
			require.Contains(t, allowed, p, sets)
			require.NotEqual(t, "/", p)
			require.False(t, strings.HasSuffix(p, ".sock"), p)
			for _, bad := range []string{"/run", "/var/run", "/var/lib/kubelet", "/etc/kubernetes", "/etc/rancher"} {
				require.False(t, strings.HasPrefix(p, bad), p)
			}
		}

		ps := ds.Spec.Template.Spec
		require.False(t, ps.HostNetwork)
		require.False(t, ps.HostPID)
		require.False(t, ps.HostIPC)
		require.False(t, *ps.AutomountServiceAccountToken)
		require.Equal(t, "ffs-agent", ps.ServiceAccountName)
		require.False(t, *ps.EnableServiceLinks)
		require.Equal(t, corev1.SeccompProfileTypeRuntimeDefault, ps.SecurityContext.SeccompProfile.Type)
		require.EqualValues(t, 65532, *ps.SecurityContext.FSGroup)

		require.Len(t, ps.Containers, 2)
		hardened := func(c corev1.Container) {
			t.Helper()
			sc := c.SecurityContext
			require.False(t, *sc.Privileged, c.Name)
			require.False(t, *sc.AllowPrivilegeEscalation, c.Name)
			require.Equal(t, []corev1.Capability{"ALL"}, sc.Capabilities.Drop, c.Name)
			require.Empty(t, sc.Capabilities.Add, c.Name)
			require.True(t, *sc.ReadOnlyRootFilesystem, c.Name)
			require.Empty(t, c.Ports, c.Name)
		}
		col := agentContainer(t, ds, "collector")
		hardened(col)
		require.EqualValues(t, 0, *col.SecurityContext.RunAsUser)
		require.Equal(t, []string{"/ffs", "agent", "check", "--heartbeat=/run/ffs-agent/heartbeat", "--max-age=15m"},
			col.LivenessProbe.Exec.Command)
		cat := agentContainer(t, ds, "catalog")
		hardened(cat)
		require.EqualValues(t, 65532, *cat.SecurityContext.RunAsUser)
		require.True(t, *cat.SecurityContext.RunAsNonRoot)
		require.Equal(t, []string{"catalog-scratch", "run", "stage"}, slices.Sorted(maps.Keys(mounts(cat))), "the cataloguer has no host mounts")
		require.True(t, mounts(cat)["stage"].ReadOnly, "the cataloguer cannot change what the collector staged")
		require.NotContains(t, mounts(cat), "heartbeat", "nor reach the collector's heartbeat")

		token := volumes(ps)["token"]
		require.NotNil(t, token.Projected)
		require.Len(t, token.Projected.Sources, 1)
		sat := token.Projected.Sources[0].ServiceAccountToken
		require.NotNil(t, sat)
		require.Equal(t, "ffs-agent", sat.Audience)
		require.EqualValues(t, 3600, *sat.ExpirationSeconds)
		require.Equal(t, "token", sat.Path)
		require.Equal(t, corev1.VolumeMount{Name: "token", MountPath: "/var/run/secrets/ffs-agent", ReadOnly: true}, mounts(col)["token"])
		require.NotContains(t, mounts(cat), "token")

		require.Equal(t, "spec.nodeName", envOf(col)["NODE_NAME"].ValueFrom.FieldRef.FieldPath)
		require.Equal(t, "120795955", envOf(col)["GOMEMLIMIT"].Value, "90% of the collector's 128Mi")
		require.Equal(t, "603979776", envOf(cat)["GOMEMLIMIT"].Value, "90% of the cataloguer's 640Mi")

		for _, u := range o {
			var subjects []rbacv1.Subject
			switch u.GetKind() {
			case "RoleBinding":
				subjects = as[rbacv1.RoleBinding](t, u).Subjects
			case "ClusterRoleBinding":
				subjects = as[rbacv1.ClusterRoleBinding](t, u).Subjects
			}
			for _, s := range subjects {
				require.False(t, s.Kind == "ServiceAccount" && s.Name == "ffs-agent", "%s %s binds the agent", u.GetKind(), u.GetName())
			}
		}
		sa := as[corev1.ServiceAccount](t, o.get(t, "ServiceAccount", "ffs-agent"))
		require.Equal(t, "ffs-agent", sa.Namespace)
		require.False(t, *sa.AutomountServiceAccountToken)
		ns := o.get(t, "Namespace", "ffs-agent").GetLabels()
		for _, mode := range []string{"enforce", "audit", "warn"} {
			require.Equal(t, "privileged", ns["pod-security.kubernetes.io/"+mode], mode)
		}
	}
}

func TestChart_AgentDaemonSetShape(t *testing.T) {
	ds := daemonSet(t)
	require.Equal(t, map[string]string{"app.kubernetes.io/name": "ffs-agent", "app.kubernetes.io/instance": "ffs"}, ds.Spec.Selector.MatchLabels)
	col, cat := agentContainer(t, ds, "collector"), agentContainer(t, ds, "catalog")
	require.Equal(t, []string{"agent", "--controller=https://ffs-agent-api.ffs.svc:8444", "--ca-file=/etc/ffs-agent/ca/ca.crt",
		"--token-file=/var/run/secrets/ffs-agent/token", "--host-root=/host", "--distribution=containerd",
		"--content-store=/host" + containerdStore, "--scratch=/scratch/stage", "--catalog-socket=/run/ffs/catalog.sock",
		"--heartbeat=/run/ffs-agent/heartbeat", "--max-image-bytes=1073741824"}, col.Args)
	require.Equal(t, []string{"catalog", "--socket=/run/ffs/catalog.sock", "--scratch=/scratch/catalog", "--local-root=/scratch/stage",
		"--max-concurrent=1", "--nice=10", "--scratch-limit=2684354560", // its 2816Mi volume − 256Mi
		"--worker-memory-limit=536870912"}, cat.Args) // 640Mi − 128Mi
	require.Equal(t, col.Image, cat.Image)

	res := func(c corev1.Container) []string {
		return []string{c.Resources.Requests.Cpu().String(), c.Resources.Requests.Memory().String(),
			c.Resources.Limits.Cpu().String(), c.Resources.Limits.Memory().String()}
	}
	require.Equal(t, []string{"10m", "32Mi", "100m", "128Mi"}, res(col))
	require.Equal(t, resource.MustParse("1Gi"), col.Resources.Requests[corev1.ResourceEphemeralStorage])
	require.Equal(t, []string{"10m", "32Mi", "400m", "640Mi"}, res(cat))

	ps := ds.Spec.Template.Spec
	v := volumes(ps)
	require.EqualValues(t, int64(1342177280), v["stage"].EmptyDir.SizeLimit.Value(), "1Gi image + 256Mi")
	require.EqualValues(t, int64(2952790016), v["catalog-scratch"].EmptyDir.SizeLimit.Value(), "4Gi − 1280Mi")
	require.Equal(t, resource.MustParse("1Mi"), *v["heartbeat"].EmptyDir.SizeLimit)
	require.NotNil(t, v["run"].EmptyDir)
	require.Equal(t, "ffs-agent-ca", v["ca"].ConfigMap.Name)
	require.Equal(t, corev1.VolumeMount{Name: "ca", MountPath: "/etc/ffs-agent/ca", ReadOnly: true}, mounts(col)["ca"])
	require.Equal(t, corev1.VolumeMount{Name: "stage", MountPath: "/scratch/stage"}, mounts(col)["stage"])
	require.Equal(t, corev1.VolumeMount{Name: "heartbeat", MountPath: "/run/ffs-agent"}, mounts(col)["heartbeat"])
	require.Equal(t, "/run/ffs", mounts(col)["run"].MountPath)
	require.Equal(t, corev1.VolumeMount{Name: "stage", MountPath: "/scratch/stage", ReadOnly: true}, mounts(cat)["stage"])
	require.Equal(t, corev1.VolumeMount{Name: "catalog-scratch", MountPath: "/scratch/catalog"}, mounts(cat)["catalog-scratch"])
	require.Equal(t, "/run/ffs", mounts(cat)["run"].MountPath)
	require.NotContains(t, v, "scratch", "no volume is shared but the socket's")

	require.Equal(t, []corev1.Toleration{{Operator: corev1.TolerationOpExists}}, ps.Tolerations)
	require.Equal(t, map[string]string{"kubernetes.io/os": "linux"}, ps.NodeSelector)
	arch := func(ps corev1.PodSpec) []corev1.NodeSelectorRequirement {
		return ps.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms[0].MatchExpressions
	}
	require.Equal(t, []corev1.NodeSelectorRequirement{{Key: "kubernetes.io/arch", Operator: corev1.NodeSelectorOpIn,
		Values: []string{"amd64"}}}, arch(ps))
	require.Empty(t, ps.PriorityClassName)

	ps = daemonSet(t, "nodeAgent.architectures={amd64,arm64}", "nodeAgent.priorityClassName=system-node-critical").Spec.Template.Spec
	require.Equal(t, []string{"amd64", "arm64"}, arch(ps)[0].Values)
	require.Equal(t, "system-node-critical", ps.PriorityClassName)

	_, err := renderErr(t, "nodeAgent.port=8443")
	require.ErrorContains(t, err, "nodeAgent.port must not be one of the controller's other ports (8080, 8081, 8443)")
}

func TestChart_AgentMountsPerDistribution(t *testing.T) {
	base := map[string]string{"/etc/os-release": "File", "/usr/bin": "Directory", "/usr/sbin": "Directory", "/usr/local/bin": "Directory",
		"/var/lib/dpkg": "", "/var/lib/rpm": ""}
	with := func(extra map[string]string, drop ...string) map[string]string {
		m := map[string]string{}
		for k, v := range base {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		for _, k := range drop {
			delete(m, k)
		}
		return m
	}
	for _, tc := range []struct {
		name  string
		sets  []string
		want  map[string]string
		dist  string
		store string
		extra string
	}{
		{"default", nil, with(map[string]string{containerdStore: "Directory"}), "containerd", containerdStore, ""},
		{"k3s", []string{"nodeAgent.distribution=k3s"},
			with(map[string]string{"/var/lib/rancher/k3s/data": "Directory", k3sStore: "Directory"}), "k3s", k3sStore, ""},
		{"rke2", []string{"nodeAgent.distribution=rke2"},
			with(map[string]string{"/var/lib/rancher/rke2/bin": "Directory", rke2Store: "Directory"}),
			"rke2", rke2Store, ""},
		{"crio", []string{"nodeAgent.distribution=crio"}, with(nil), "crio", "", ""},
		{"apk", []string{"nodeAgent.packageDatabases={apk}"},
			with(map[string]string{"/lib/apk/db": "Directory", containerdStore: "Directory"}, "/var/lib/dpkg", "/var/lib/rpm"), "containerd", containerdStore, ""},
		{"image-based", []string{"nodeAgent.packageDatabases={}"},
			with(map[string]string{containerdStore: "Directory"}, "/var/lib/dpkg", "/var/lib/rpm", "/usr/local/bin"), "containerd", containerdStore, ""},
		{"extra bin dir", []string{"nodeAgent.hostPaths.extraBinDirs={/opt/bin}"},
			with(map[string]string{containerdStore: "Directory", "/opt/bin": "Directory"}), "containerd", containerdStore, "/opt/bin"},
	} {
		ds := daemonSet(t, tc.sets...)
		require.Equal(t, tc.want, hostMounts(t, ds), tc.name)
		args := agentContainer(t, ds, "collector").Args
		require.Contains(t, args, "--distribution="+tc.dist, tc.name)
		hasStore := slices.ContainsFunc(args, func(a string) bool { return strings.HasPrefix(a, "--content-store=") })
		if tc.store == "" {
			require.False(t, hasStore, tc.name)
		} else {
			require.Contains(t, args, "--content-store=/host"+tc.store, tc.name)
		}
		hasExtra := slices.ContainsFunc(args, func(a string) bool { return strings.HasPrefix(a, "--extra-bin-dir=") })
		require.Equal(t, tc.extra != "", hasExtra, tc.name)
		if tc.extra != "" {
			require.Contains(t, args, "--extra-bin-dir="+tc.extra, tc.name)
		}
	}

	_, err := renderErr(t, "nodeAgent.hostPaths.extraBinDirs={/var/lib/kubelet}")
	require.ErrorContains(t, err, "nodeAgent.hostPaths.extraBinDirs: /var/lib/kubelet is not allowed; use a directory under /usr or /opt")
	_, err = renderErr(t, "nodeAgent.hostPaths.extraBinDirs={/opt/../etc}")
	require.ErrorContains(t, err, "nodeAgent.hostPaths.extraBinDirs: /opt/../etc is not allowed; use a directory under /usr or /opt")
	_, err = renderErr(t, "nodeAgent.distribution=bogus")
	require.ErrorContains(t, err, "nodeAgent.distribution must be auto, containerd, k3s, rke2 or crio")
}

func TestChart_AgentAutoDetectFromNodes(t *testing.T) {
	dir := copyChart(t, map[string]string{"zz-detect.yaml": `{{- range $i, $c := .Values.testCases }}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: detect-{{ $i }}
data:
  result: {{ include "ffs.agentHostFrom" (dict "nodes" $c.nodes "agent" (mergeOverwrite (deepCopy $.Values.nodeAgent) ($c.agent | default dict))) | quote }}
{{- end }}
`})
	type nodeInfo = map[string]string
	node := func(info nodeInfo) map[string]any { return map[string]any{"status": map[string]any{"nodeInfo": info}} }
	k3s := node(nodeInfo{"kubeletVersion": "v1.37.0+k3s1", "osImage": "Ubuntu 26.04 LTS"})
	talos := node(nodeInfo{"kubeletVersion": "v1.37.0", "osImage": "Talos (v1.12.0)"})
	type want struct {
		Distribution     string   `json:"distribution"`
		PackageDatabases []string `json:"packageDatabases"`
		ImageBased       bool     `json:"imageBased"`
	}
	cases := []struct {
		nodes []map[string]any
		agent map[string]any
		want  want
	}{
		{[]map[string]any{k3s, k3s, k3s}, nil, want{"k3s", []string{"dpkg"}, false}},
		{[]map[string]any{node(nodeInfo{"kubeletVersion": "v1.37.0+rke2r1", "osImage": "Red Hat Enterprise Linux 9.6"}),
			node(nodeInfo{"kubeletVersion": "v1.37.0+rke2r1", "osImage": "SUSE Linux Enterprise Server 15 SP6"})}, nil,
			want{"rke2", []string{"rpm"}, false}},
		{[]map[string]any{node(nodeInfo{"kubeletVersion": "v1.37.0", "containerRuntimeVersion": "cri-o://1.37.0", "osImage": "Fedora CoreOS 43"})},
			nil, want{"crio", []string{"rpm"}, false}},
		{[]map[string]any{talos, talos}, nil, want{"containerd", []string{}, true}},
		{[]map[string]any{talos, node(nodeInfo{"kubeletVersion": "v1.37.0", "osImage": "Debian GNU/Linux 13 (trixie)"})}, nil,
			want{"containerd", []string{"dpkg"}, false}},
		{[]map[string]any{node(nodeInfo{"kubeletVersion": "v1.37.0", "osImage": "Arch Linux"})}, nil,
			want{"containerd", []string{"dpkg", "rpm"}, false}},
		{[]map[string]any{k3s, node(nodeInfo{"kubeletVersion": "v1.37.0", "containerRuntimeVersion": "containerd://2.2.1", "osImage": "Ubuntu 26.04 LTS"})},
			nil, want{"containerd", []string{"dpkg"}, false}},
		{[]map[string]any{k3s}, map[string]any{"distribution": "crio"}, want{"crio", []string{"dpkg"}, false}},
	}
	var values []map[string]any
	for _, c := range cases {
		values = append(values, map[string]any{"nodes": c.nodes, "agent": c.agent})
	}
	results := helperResults(t, dir, map[string]any{"testCases": values}, "detect", len(cases))
	for i, c := range cases {
		var got want
		require.NoError(t, json.Unmarshal([]byte(results[i]), &got), results[i])
		require.Equal(t, c.want, got, "case %d: %s", i, results[i])
	}
}

func TestChart_AgentTLS(t *testing.T) {
	o := render(t)
	sec := as[corev1.Secret](t, o.get(t, "Secret", "ffs-agent-tls"))
	require.Equal(t, "ffs", sec.Namespace)
	require.Equal(t, corev1.SecretTypeTLS, sec.Type)
	block, _ := pem.Decode(sec.Data["tls.crt"])
	require.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	require.Equal(t, []string{"ffs-agent-api", "ffs-agent-api.ffs", "ffs-agent-api.ffs.svc", "ffs-agent-api.ffs.svc.cluster.local"}, cert.DNSNames)
	_, err = tls.X509KeyPair(sec.Data["tls.crt"], sec.Data["tls.key"])
	require.NoError(t, err)
	cm := as[corev1.ConfigMap](t, o.get(t, "ConfigMap", "ffs-agent-ca"))
	require.Equal(t, "ffs-agent", cm.Namespace)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM([]byte(cm.Data["ca.crt"])))
	_, err = cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: "ffs-agent-api.ffs.svc"})
	require.NoError(t, err)
	notAfter, err := strconv.ParseInt(sec.Annotations["ffs.theitdept.au/not-after"], 10, 64)
	require.NoError(t, err)
	require.InDelta(t, time.Now().Add(3650*24*time.Hour).Unix(), notAfter, float64(24*time.Hour/time.Second))

	// Reuse is decided by ffs.agentTLSPair; helm template has no lookup data, so it is called directly.
	dir := copyChart(t, map[string]string{"zz-tls.yaml": `{{- range $i, $c := .Values.tlsCases }}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: tls-{{ $i }}
data:
  result: {{ include "ffs.agentTLSPair" (dict "secret" $c.secret "configMap" $c.configMap "root" $) | quote }}
{{- end }}
`})
	existing := func(notAfter string) map[string]any {
		return map[string]any{
			"secret": map[string]any{"metadata": map[string]any{"annotations": map[string]any{"ffs.theitdept.au/not-after": notAfter}},
				"data": map[string]any{"tls.crt": "dGxzLWNydA", "tls.key": "dGxzLWtleQ"}},
			"configMap": map[string]any{"data": map[string]any{"ca.crt": testCABundle}},
		}
	}
	unix := func(d time.Duration) string { return strconv.FormatInt(time.Now().Add(d).Unix(), 10) }
	kept := unix(60 * 24 * time.Hour)
	noCM := existing(kept)
	delete(noCM, "configMap")
	cases := []map[string]any{existing(kept), existing(unix(10 * 24 * time.Hour)), noCM, existing("soon")}
	results := helperResults(t, dir, map[string]any{"tlsCases": cases}, "tls", len(cases))
	type pair struct {
		TLSCrt   string `json:"tlsCrt"`
		TLSKey   string `json:"tlsKey"`
		CACrt    string `json:"caCrt"`
		NotAfter string `json:"notAfter"`
	}
	var got []pair
	for _, r := range results {
		var p pair
		require.NoError(t, json.Unmarshal([]byte(r), &p), r)
		got = append(got, p)
	}
	require.Equal(t, pair{"dGxzLWNydA", "dGxzLWtleQ", testCABundle, kept}, got[0], "a pair with more than 30 days left is kept")
	for i, why := range []string{"10 days left", "no ConfigMap", "an unreadable annotation"} {
		require.NotEqual(t, "dGxzLWNydA", got[i+1].TLSCrt, "a new pair: %s", why)
		require.NotEqual(t, testCABundle, got[i+1].CACrt, why)
	}

	ps := podSpec(t)
	var port corev1.ContainerPort
	for _, p := range container(t, ps, "controller").Ports {
		if p.Name == "agent-api" {
			port = p
		}
	}
	require.Equal(t, corev1.ContainerPort{Name: "agent-api", ContainerPort: 8444, Protocol: corev1.ProtocolTCP}, port)
	require.Equal(t, "ffs-agent-tls", volumes(ps)["agent-tls"].Secret.SecretName)
	require.Equal(t, corev1.VolumeMount{Name: "agent-tls", MountPath: "/etc/ffs/agent-tls", ReadOnly: true},
		mounts(container(t, ps, "controller"))["agent-tls"])

	svc := as[corev1.Service](t, o.get(t, "Service", "ffs-agent-api"))
	require.Equal(t, "ffs", svc.Namespace)
	require.Equal(t, map[string]string{"app.kubernetes.io/name": "ffs", "app.kubernetes.io/instance": "ffs"}, svc.Spec.Selector)
	require.Len(t, svc.Spec.Ports, 1)
	require.EqualValues(t, 8444, svc.Spec.Ports[0].Port)
	require.Equal(t, intstr.FromString("agent-api"), svc.Spec.Ports[0].TargetPort)

	certManager := []string{"nodeAgent.tls.certManager.enabled=true", "nodeAgent.tls.certManager.issuerRef.name=ca-issuer",
		"nodeAgent.tls.certManager.issuerRef.kind=ClusterIssuer", "nodeAgent.tls.caBundle=" + testCABundle}
	o = render(t, certManager...)
	crt := o.get(t, "Certificate", "ffs-agent-tls")
	require.Equal(t, "ffs", crt.GetNamespace())
	spec, _, err := unstructured.NestedMap(crt.Object, "spec")
	require.NoError(t, err)
	require.Len(t, spec, 3)
	// cert-manager's Secret has a name of its own, so switching certManager.enabled either way never asks Helm to
	// adopt cert-manager's Secret, or cert-manager to take over the chart's.
	require.Equal(t, "ffs-agent-cert-manager-tls", spec["secretName"])
	require.Equal(t, "ffs-agent-cert-manager-tls", volumes(podSpec(t, certManager...))["agent-tls"].Secret.SecretName)
	require.Equal(t, []any{"ffs-agent-api", "ffs-agent-api.ffs", "ffs-agent-api.ffs.svc", "ffs-agent-api.ffs.svc.cluster.local"}, spec["dnsNames"])
	require.Equal(t, map[string]any{"name": "ca-issuer", "kind": "ClusterIssuer"}, spec["issuerRef"])
	require.False(t, o.has("Secret", "ffs-agent-tls"))
	require.False(t, o.has("Secret", "ffs-agent-cert-manager-tls"), "cert-manager writes it, not the chart")
	require.Equal(t, testCABundle, as[corev1.ConfigMap](t, o.get(t, "ConfigMap", "ffs-agent-ca")).Data["ca.crt"])

	_, err = renderErr(t, "nodeAgent.tls.certManager.enabled=true", "nodeAgent.tls.certManager.issuerRef.name=ca-issuer")
	require.ErrorContains(t, err, "nodeAgent.tls.caBundle is required when nodeAgent.tls.certManager.enabled is true")
}

// TestChart_NetworkPolicy: the ffs pod's NetworkPolicy admits the agent API from the agent pods while the agent
// runs, metrics and health from anywhere, and the web UI port only from web.networkPolicy.from on a listen address
// beyond loopback. It renders with or without the node agent, so web.networkPolicy.from is always in force: a web
// UI Service without those peers is refused, because the policy would close it, and peers without the policy are
// refused, because nothing would apply them.
func TestChart_NetworkPolicy(t *testing.T) {
	policy := func(sets ...string) networkingv1.NetworkPolicy {
		t.Helper()
		return as[networkingv1.NetworkPolicy](t, render(t, sets...).get(t, "NetworkPolicy", "ffs"))
	}
	np := policy()
	require.Equal(t, "ffs", np.Namespace)
	require.Equal(t, map[string]string{"app.kubernetes.io/name": "ffs", "app.kubernetes.io/instance": "ffs"}, np.Spec.PodSelector.MatchLabels)
	require.Equal(t, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}, np.Spec.PolicyTypes)
	require.Len(t, np.Spec.Ingress, 2, "no web UI rule by default")
	tcp := corev1.ProtocolTCP
	port := func(p intstr.IntOrString) networkingv1.NetworkPolicyPort {
		return networkingv1.NetworkPolicyPort{Protocol: &tcp, Port: &p}
	}
	in := np.Spec.Ingress[0]
	require.Len(t, in.From, 1)
	require.Equal(t, map[string]string{"kubernetes.io/metadata.name": "ffs-agent"}, in.From[0].NamespaceSelector.MatchLabels)
	require.Equal(t, map[string]string{"app.kubernetes.io/name": "ffs-agent"}, in.From[0].PodSelector.MatchLabels)
	require.Equal(t, []networkingv1.NetworkPolicyPort{port(intstr.FromString("agent-api"))}, in.Ports)
	open := networkingv1.NetworkPolicyIngressRule{Ports: []networkingv1.NetworkPolicyPort{port(intstr.FromString("metrics")), port(intstr.FromString("health"))}}
	require.Equal(t, open, np.Spec.Ingress[1])
	webRule := networkingv1.NetworkPolicyIngressRule{
		From:  []networkingv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "oauth2-proxy"}}}},
		Ports: []networkingv1.NetworkPolicyPort{port(intstr.FromInt32(9090))}, // the port of config.listen
	}

	for _, sets := range [][]string{
		{"web.service.enabled=true", "config.listen=0.0.0.0:9090", webPeer},
		{"config.listen=0.0.0.0:9090", webPeer}, // a Service of your own
	} {
		np = policy(sets...)
		require.Len(t, np.Spec.Ingress, 3, sets)
		require.Equal(t, webRule, np.Spec.Ingress[2], sets)
	}
	require.Len(t, policy(webPeer).Spec.Ingress, 2, "nothing outside the pod reaches a loopback listener")
	for _, rule := range policy("config.listen=0.0.0.0:8080").Spec.Ingress {
		for _, p := range rule.Ports {
			require.NotEqual(t, intstr.FromInt32(8080), *p.Port, "no web UI rule without peers")
			require.NotEqual(t, intstr.FromString("http"), *p.Port)
		}
	}

	// Without the node agent the policy stays, minus the agent API rule.
	require.Equal(t, []networkingv1.NetworkPolicyIngressRule{open}, policy("nodeAgent.enabled=false").Spec.Ingress)
	require.Equal(t, []networkingv1.NetworkPolicyIngressRule{open, webRule},
		policy("nodeAgent.enabled=false", "web.service.enabled=true", "config.listen=0.0.0.0:9090", webPeer).Spec.Ingress)

	for _, agent := range []string{"nodeAgent.enabled=true", "nodeAgent.enabled=false"} {
		_, err := renderErr(t, agent, "web.service.enabled=true", "config.listen=0.0.0.0:8080")
		require.ErrorContains(t, err, "web.service.enabled needs web.networkPolicy.from: the NetworkPolicy of nodeAgent.networkPolicy.enabled "+
			"admits the web UI port only from the peers listed there", agent)

		off := []string{agent, "nodeAgent.networkPolicy.enabled=false"}
		o := render(t, append(off, "web.service.enabled=true", "config.listen=0.0.0.0:8080")...)
		require.False(t, o.has("NetworkPolicy", "ffs"), off)
		require.False(t, o.has("NetworkPolicy", "ffs-agent-api"), off)
		require.True(t, o.has("Service", "ffs-web"), off)
		for _, sets := range [][]string{{webPeer}, {"web.service.enabled=true", "config.listen=0.0.0.0:8080", webPeer}} {
			_, err = renderErr(t, append(off, sets...)...)
			require.ErrorContains(t, err, "web.networkPolicy.from takes effect only through the NetworkPolicy of nodeAgent.networkPolicy.enabled, "+
				"which is false", "%v %v", off, sets)
		}
	}
}

func TestChart_AgentOptIns(t *testing.T) {
	ds := daemonSet(t)
	for _, c := range ds.Spec.Template.Spec.Containers {
		require.Nil(t, c.SecurityContext.SELinuxOptions, c.Name)
	}
	ds = daemonSet(t, "nodeAgent.seLinuxType=spc_t")
	require.Equal(t, "spc_t", agentContainer(t, ds, "collector").SecurityContext.SELinuxOptions.Type)
	require.Nil(t, agentContainer(t, ds, "catalog").SecurityContext.SELinuxOptions)

	o := render(t)
	require.False(t, o.has("SecurityContextConstraints", "ffs-agent"))
	require.False(t, o.has("ClusterRole", "ffs-agent-scc"))
	require.False(t, o.has("RoleBinding", "ffs-agent-scc"))

	o = render(t, "nodeAgent.openshift.scc=true")
	scc := o.get(t, "SecurityContextConstraints", "ffs-agent").Object
	for field, want := range map[string]any{
		"allowHostDirVolumePlugin": true, "allowPrivilegedContainer": false, "allowPrivilegeEscalation": false,
		"readOnlyRootFilesystem": true, "allowHostNetwork": false, "allowHostPID": false, "allowHostIPC": false, "allowHostPorts": false,
		"requiredDropCapabilities": []any{"ALL"}, "volumes": []any{"configMap", "emptyDir", "hostPath", "projected"},
	} {
		require.Equal(t, want, scc[field], field)
	}
	cr := clusterRole(t, o, "ffs-agent-scc")
	require.Equal(t, []rbacv1.PolicyRule{{APIGroups: []string{"security.openshift.io"}, Resources: []string{"securitycontextconstraints"},
		ResourceNames: []string{"ffs-agent"}, Verbs: []string{"use"}}}, cr.Rules)
	var bindings []string
	for _, u := range o {
		var subjects []rbacv1.Subject
		switch u.GetKind() {
		case "RoleBinding":
			subjects = as[rbacv1.RoleBinding](t, u).Subjects
		case "ClusterRoleBinding":
			subjects = as[rbacv1.ClusterRoleBinding](t, u).Subjects
		}
		for _, s := range subjects {
			if s.Kind == "ServiceAccount" && s.Name == "ffs-agent" {
				bindings = append(bindings, u.GetKind()+"/"+u.GetName())
			}
		}
	}
	require.Equal(t, []string{"RoleBinding/ffs-agent-scc"}, bindings, "the SCC binding is the only one naming the agent")
	rb := as[rbacv1.RoleBinding](t, o.get(t, "RoleBinding", "ffs-agent-scc"))
	require.Equal(t, "ffs-agent", rb.Namespace)
	require.Equal(t, rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "ffs-agent-scc"}, rb.RoleRef)
	require.Equal(t, []rbacv1.Subject{{Kind: "ServiceAccount", Name: "ffs-agent", Namespace: "ffs-agent"}}, rb.Subjects)
}

// envOf maps a container's environment variables by name.
func envOf(c corev1.Container) map[string]corev1.EnvVar {
	out := map[string]corev1.EnvVar{}
	for _, e := range c.Env {
		out[e.Name] = e
	}
	return out
}

// TestChart_AgentMemoryLimits: GOMEMLIMIT is 90% of each agent container's memory limit, and the cataloguer's
// workers get its limit less 128Mi for the catalog server; without limits both fall back to the container's
// allocatable memory.
func TestChart_AgentMemoryLimits(t *testing.T) {
	ds := daemonSet(t, "nodeAgent.resources.collector.limits.memory=256Mi", "nodeAgent.resources.catalog.limits.memory=1Gi")
	col, cat := agentContainer(t, ds, "collector"), agentContainer(t, ds, "catalog")
	require.Equal(t, "241591910", envOf(col)["GOMEMLIMIT"].Value)
	require.Equal(t, "966367641", envOf(cat)["GOMEMLIMIT"].Value)
	require.Contains(t, cat.Args, "--worker-memory-limit=939524096") // 1Gi − 128Mi

	ds = daemonSet(t, "nodeAgent.resources.collector.limits=null", "nodeAgent.resources.catalog.limits=null")
	for _, c := range ds.Spec.Template.Spec.Containers {
		e := envOf(c)["GOMEMLIMIT"]
		require.Empty(t, e.Value, c.Name)
		require.Equal(t, corev1.ResourceFieldSelector{ContainerName: c.Name, Resource: "limits.memory"}, *e.ValueFrom.ResourceFieldRef, c.Name)
		require.False(t, slices.ContainsFunc(c.Args, func(a string) bool { return strings.HasPrefix(a, "--worker-memory-limit") }), c.Name)
	}

	_, err := renderErr(t, "nodeAgent.resources.catalog.limits.memory=160Mi")
	require.ErrorContains(t, err, "nodeAgent.resources.catalog.limits.memory must be at least 128Mi plus 64Mi per concurrent catalog job (1)")

	// The controller's cataloguer runs config.catalog.concurrency workers at once, which share what the server leaves.
	cc := container(t, podSpec(t, "config.catalog.concurrency=4"), "catalog")
	require.Contains(t, cc.Args, "--worker-memory-limit=503316480") // (2Gi − 128Mi) / 4
	require.Equal(t, "1932735283", envOf(cc)["GOMEMLIMIT"].Value)
	cc = container(t, podSpec(t, "catalog.resources.limits=null"), "catalog")
	require.Equal(t, "limits.memory", envOf(cc)["GOMEMLIMIT"].ValueFrom.ResourceFieldRef.Resource)
	require.False(t, slices.ContainsFunc(cc.Args, func(a string) bool { return strings.HasPrefix(a, "--worker-memory-limit") }))
}

// TestChart_FractionalMemoryLimits: memory limits with a decimal fraction, as Kubernetes takes them, keep
// rendering: 1.5Gi is 1536Mi for every container's GOMEMLIMIT and worker limit, beside the whole 2Gi.
func TestChart_FractionalMemoryLimits(t *testing.T) {
	for _, c := range []struct {
		limit            string
		goMemLimit       string // 90%
		agentWorkerLimit string // less 128Mi
		workerLimit      string // less 128Mi, over the default 2 jobs
	}{
		{"1.5Gi", "1449551462", "--worker-memory-limit=1476395008", "--worker-memory-limit=738197504"},
		{"1536Mi", "1449551462", "--worker-memory-limit=1476395008", "--worker-memory-limit=738197504"},
		{"2Gi", "1932735283", "--worker-memory-limit=2013265920", "--worker-memory-limit=1006632960"},
	} {
		o := render(t, "controller.resources.limits.memory="+c.limit, "catalog.resources.limits.memory="+c.limit,
			"nodeAgent.resources.collector.limits.memory="+c.limit, "nodeAgent.resources.catalog.limits.memory="+c.limit)
		ps := as[appsv1.Deployment](t, o.get(t, "Deployment", "ffs")).Spec.Template.Spec
		ds := as[appsv1.DaemonSet](t, o.get(t, "DaemonSet", "ffs-agent"))
		for _, ctr := range []corev1.Container{container(t, ps, "controller"), container(t, ps, "catalog"),
			agentContainer(t, ds, "collector"), agentContainer(t, ds, "catalog")} {
			require.Equal(t, c.goMemLimit, envOf(ctr)["GOMEMLIMIT"].Value, "%s %s", c.limit, ctr.Name)
		}
		require.Contains(t, container(t, ps, "catalog").Args, c.workerLimit, c.limit)
		require.Contains(t, agentContainer(t, ds, "catalog").Args, c.agentWorkerLimit, c.limit)
	}
}

// TestChart_BytesQuantities: ffs.bytes reads byte counts and Kubernetes quantities, whole or with up to six
// decimal digits, rounding a fraction of a byte up as Kubernetes does, and refuses anything else.
func TestChart_BytesQuantities(t *testing.T) {
	dir := copyChart(t, map[string]string{"zz-bytes.yaml": `{{- range $i, $v := .Values.byteCases }}
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: bytes-{{ $i }}
data:
  result: {{ include "ffs.bytes" (list "case" $v) | quote }}
{{- end }}
`})
	cases := []struct {
		in   any
		want string
	}{
		{"2Gi", "2147483648"},
		{"1.5Gi", "1610612736"},
		{"0.5Gi", "536870912"},
		{"1536Mi", "1610612736"},
		{"1.05Gi", "1127428916"}, // 1127428915.2, rounded up; 05 is decimal, not octal
		{"1.5G", "1500000000"},
		{"0.25Ki", "256"},
		{"0.1", "1"},
		{"128974848", "128974848"},
		{128974848, "128974848"},
		{"1.000001Ti", "1099512727288"},
	}
	values := make([]any, len(cases))
	for i, c := range cases {
		values[i] = c.in
	}
	got := helperResults(t, dir, map[string]any{"byteCases": values}, "bytes", len(cases))
	for i, c := range cases {
		require.Equal(t, c.want, got[i], "%v", c.in)
		if s, ok := c.in.(string); ok {
			want, err := resource.ParseQuantity(s)
			require.NoError(t, err, s)
			require.Equal(t, strconv.FormatInt(want.Value(), 10), got[i], "%s as Kubernetes reads it", s)
		}
	}

	for _, bad := range []string{"1.5GB", ".5Gi", "1.Gi", "1.1234567Gi", "01Gi", "1.5.0Gi", "1e9", "-1Gi"} {
		_, err := renderErr(t, "controller.resources.limits.memory="+bad)
		require.ErrorContains(t, err, fmt.Sprintf("controller.resources.limits.memory must be a byte count or a quantity such as 18Gi, not %q", bad), bad)
	}
}

// TestChart_AgentScratchVolumes: nodeAgent.scratchSizeLimit is split between the collector's staging volume
// and the cataloguer's own, and a total too small for both is refused.
func TestChart_AgentScratchVolumes(t *testing.T) {
	sizes := func(sets ...string) (stage, catalog int64, limit string) {
		t.Helper()
		ds := daemonSet(t, sets...)
		v := volumes(ds.Spec.Template.Spec)
		for _, a := range agentContainer(t, ds, "catalog").Args {
			if l, ok := strings.CutPrefix(a, "--scratch-limit="); ok {
				limit = l
			}
		}
		return v["stage"].EmptyDir.SizeLimit.Value(), v["catalog-scratch"].EmptyDir.SizeLimit.Value(), limit
	}
	stage, catalog, limit := sizes("nodeAgent.maxImageBytes=16Mi", "nodeAgent.scratchSizeLimit=2Gi")
	require.Equal(t, int64(805306368), stage, "host inputs (512Mi) outgrow a small image, + 256Mi")
	require.Equal(t, int64(1342177280), catalog)
	require.Equal(t, "1073741824", limit)

	stage, catalog, limit = sizes("nodeAgent.maxImageBytes=2Gi", "nodeAgent.scratchSizeLimit=8Gi")
	require.Equal(t, int64(2415919104), stage, "2Gi image + 256Mi")
	require.Equal(t, int64(6174015488), catalog)
	require.Equal(t, "5905580032", limit)

	_, err := renderErr(t, "nodeAgent.scratchSizeLimit=1Gi", "nodeAgent.maxImageBytes=1Gi")
	require.ErrorContains(t, err, "nodeAgent.scratchSizeLimit (1073741824 bytes) must be at least 1879048192 bytes: the staging volume "+
		"takes nodeAgent.maxImageBytes or 512Mi, whichever is larger, plus 256Mi, and the cataloguer needs 512Mi to unpack images")
	_, err = renderErr(t, "nodeAgent.scratchSizeLimit=1Gi", "nodeAgent.maxImageBytes=64Mi")
	require.ErrorContains(t, err, "nodeAgent.scratchSizeLimit (1073741824 bytes) must be at least 1342177280 bytes")
}

// TestChart_AgentContainerdRoot: nodeAgent.hostPaths.containerdRoot moves the content store mount and the
// collector's --content-store together, for any containerd distribution.
func TestChart_AgentContainerdRoot(t *testing.T) {
	for _, tc := range []struct {
		root, dist string
	}{
		{"/var/lib/k0s/containerd", "containerd"},
		{"/var/snap/microk8s/common/var/lib/containerd", "containerd"},
		{"/data/containerd", "k3s"},
	} {
		ds := daemonSet(t, "nodeAgent.hostPaths.containerdRoot="+tc.root, "nodeAgent.distribution="+tc.dist)
		store := tc.root + "/io.containerd.content.v1.content"
		hm := hostMounts(t, ds)
		require.Equal(t, "Directory", hm[store], tc.root)
		for _, def := range []string{containerdStore, k3sStore} {
			require.NotContains(t, hm, def, "the distribution's content store is not mounted as well")
		}
		require.Contains(t, agentContainer(t, ds, "collector").Args, "--content-store=/host"+store, tc.root)
	}
	require.Contains(t, hostMounts(t, daemonSet(t, "nodeAgent.hostPaths.containerdRoot=")), containerdStore, "empty uses the table")

	for root, want := range map[string]string{
		"var/lib/containerd":               "must be an absolute path to containerd's root directory",
		"/var/lib/../../etc":               "must be an absolute path to containerd's root directory",
		"/var/lib/containerd/./x":          "must be an absolute path to containerd's root directory",
		"/var/lib/containerd with a space": "must be an absolute path to containerd's root directory",
		"/run/containerd":                  "/run/containerd is not allowed; the agent never mounts it",
		"/var/lib/kubelet":                 "/var/lib/kubelet is not allowed; the agent never mounts it",
	} {
		_, err := renderErr(t, "nodeAgent.hostPaths.containerdRoot="+root)
		require.ErrorContains(t, err, "nodeAgent.hostPaths.containerdRoot", root)
		require.ErrorContains(t, err, want, root)
	}
	_, err := renderErr(t, "nodeAgent.hostPaths.containerdRoot=/var/lib/k0s/containerd", "nodeAgent.distribution=crio")
	require.ErrorContains(t, err, "nodeAgent.hostPaths.containerdRoot does not apply to crio")
}

// TestChart_AgentScratchRequest: the collector requests nodeAgent.scratchRequest of ephemeral storage, unless
// its resources already say how much.
func TestChart_AgentScratchRequest(t *testing.T) {
	req := func(sets ...string) (resource.Quantity, bool) {
		t.Helper()
		q, ok := agentContainer(t, daemonSet(t, sets...), "collector").Resources.Requests[corev1.ResourceEphemeralStorage]
		return q, ok
	}
	q, ok := req()
	require.True(t, ok)
	require.Equal(t, resource.MustParse("1Gi"), q)
	q, _ = req("nodeAgent.scratchRequest=2Gi")
	require.Equal(t, resource.MustParse("2Gi"), q)
	q, _ = req("nodeAgent.resources.collector.requests.ephemeral-storage=3Gi")
	require.Equal(t, resource.MustParse("3Gi"), q, "an explicit request wins")
	_, ok = req("nodeAgent.scratchRequest=")
	require.False(t, ok, "empty requests none")
	_, ok = agentContainer(t, daemonSet(t), "catalog").Resources.Requests[corev1.ResourceEphemeralStorage]
	require.False(t, ok, "the request is the collector's")
}

// TestChart_AgentUpdateStrategy: the agent DaemonSet replaces a tenth of its pods at a time by default.
func TestChart_AgentUpdateStrategy(t *testing.T) {
	ten := intstr.FromString("10%")
	require.Equal(t, appsv1.DaemonSetUpdateStrategy{Type: appsv1.RollingUpdateDaemonSetStrategyType,
		RollingUpdate: &appsv1.RollingUpdateDaemonSet{MaxUnavailable: &ten}}, daemonSet(t).Spec.UpdateStrategy)
	five := intstr.FromInt32(5)
	require.Equal(t, &five, daemonSet(t, "nodeAgent.updateStrategy.rollingUpdate.maxUnavailable=5").Spec.UpdateStrategy.RollingUpdate.MaxUnavailable)
	ds := daemonSet(t, "nodeAgent.updateStrategy.type=OnDelete", "nodeAgent.updateStrategy.rollingUpdate=null")
	require.Equal(t, appsv1.DaemonSetUpdateStrategy{Type: appsv1.OnDeleteDaemonSetStrategyType}, ds.Spec.UpdateStrategy)
}

// TestChart_AgentValueGuards: values that would render an invalid DaemonSet are refused with a clear message.
func TestChart_AgentValueGuards(t *testing.T) {
	for sets, want := range map[string]string{
		"nodeAgent.hostPaths.extraBinDirs={/opt/bin,/opt/bin}": "nodeAgent.hostPaths.extraBinDirs: /opt/bin is listed twice",
		"nodeAgent.hostPaths.extraBinDirs={/usr/bin}":          "nodeAgent.hostPaths.extraBinDirs: /usr/bin is searched already; list only other directories",
		"nodeAgent.hostPaths.extraBinDirs={/usr/sbin}":         "nodeAgent.hostPaths.extraBinDirs: /usr/sbin is searched already",
		"nodeAgent.hostPaths.extraBinDirs={/usr/local/bin}":    "nodeAgent.hostPaths.extraBinDirs: /usr/local/bin is searched already",
		"nodeAgent.hostPaths.extraBinDirs={/usr/./bin}":        "nodeAgent.hostPaths.extraBinDirs: /usr/./bin is not allowed; use a directory under /usr or /opt",
		"nodeAgent.hostPaths.extraBinDirs={/opt/../etc}":       "nodeAgent.hostPaths.extraBinDirs: /opt/../etc is not allowed",
		"nodeAgent.hostPaths.extraBinDirs={/opt/tools/.}":      "nodeAgent.hostPaths.extraBinDirs: /opt/tools/. is not allowed",
		"nodeAgent.hostPaths.extraBinDirs={/opt/tools/..}":     "nodeAgent.hostPaths.extraBinDirs: /opt/tools/.. is not allowed",
		"nodeAgent.architectures=null":                         "nodeAgent.architectures must list at least one node architecture",
		"nodeAgent.architectures={}":                           "nodeAgent.architectures must list at least one node architecture",
	} {
		_, err := renderErr(t, strings.Split(sets, ";")...)
		require.ErrorContains(t, err, want, sets)
	}
	// On image-based OSes /usr/local/bin is not mounted, so it may be listed.
	hm := hostMounts(t, daemonSet(t, "nodeAgent.packageDatabases={}", "nodeAgent.hostPaths.extraBinDirs={/usr/local/bin}"))
	require.Equal(t, "Directory", hm["/usr/local/bin"])
	// A dot inside a name is not a . or .. component.
	require.Equal(t, "Directory", hostMounts(t, daemonSet(t, "nodeAgent.hostPaths.extraBinDirs={/opt/tools..v2/bin}"))["/opt/tools..v2/bin"])
	ps := daemonSet(t, "nodeAgent.architectures={amd64,,arm64}").Spec.Template.Spec
	require.Equal(t, []string{"amd64", "arm64"},
		ps.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms[0].MatchExpressions[0].Values)
}
