package repo

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"

	apiv1alpha1 "github.com/the-it-dept/ffs/api/v1alpha1"
	"github.com/the-it-dept/ffs/internal/config"
)

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // repo-relative fixture path
	require.NoError(t, err)
	return string(b)
}

func glob(t *testing.T, pattern string) []string {
	t.Helper()
	m, err := filepath.Glob(pattern)
	require.NoError(t, err)
	return m
}

// docFiles are the public user docs: README, SECURITY, docs/*.md and the examples.
func docFiles(t *testing.T) []string {
	t.Helper()
	files := []string{"../../README.md", "../../SECURITY.md"}
	files = append(files, glob(t, "../../docs/*.md")...)
	files = append(files, glob(t, "../../docs/examples/*")...)
	return files
}

func TestDocs_ConfigurationCoversEveryField(t *testing.T) {
	doc := readFile(t, "../../docs/configuration.md")
	for _, p := range config.FieldPaths() {
		require.Contains(t, doc, "`"+p+"`", "docs/configuration.md does not describe %s", p)
	}
}

var (
	yamlBlock    = regexp.MustCompile("(?ms)^```yaml\n(.*?)^```")
	docSeparator = regexp.MustCompile(`(?m)^---\s*$`)
)

func TestDocs_ExamplesStrictDecode(t *testing.T) {
	examples := glob(t, "../../docs/examples/*.yaml")
	require.NotEmpty(t, examples)
	for _, path := range examples {
		decoded := 0
		for i, doc := range splitDocs(readFile(t, path)) {
			kind := kindOf(t, doc)
			if kind == "Secret" {
				require.NoError(t, yaml.UnmarshalStrict([]byte(doc), &corev1.Secret{}), "%s document %d", path, i)
				continue
			}
			require.Contains(t, []string{"AlertTarget", "Exception"}, kind, "%s document %d", path, i)
			decodeFFS(t, path, kind, doc)
			decoded++
		}
		require.Positive(t, decoded, "%s has no AlertTarget or Exception", path)
	}

	docs := append([]string{"../../README.md"}, glob(t, "../../docs/*.md")...)
	blocks := 0
	for _, path := range docs {
		for _, m := range yamlBlock.FindAllStringSubmatch(readFile(t, path), -1) {
			for _, doc := range splitDocs(m[1]) {
				if k := kindOf(t, doc); k == "AlertTarget" || k == "Exception" {
					decodeFFS(t, path, k, doc)
					blocks++
				}
			}
		}
	}
	require.Positive(t, blocks, "no AlertTarget or Exception examples in the markdown docs")
}

// splitDocs splits a YAML stream on document separators, dropping empty documents.
func splitDocs(s string) []string {
	var out []string
	for _, d := range docSeparator.Split(s, -1) {
		if strings.TrimSpace(d) != "" {
			out = append(out, d)
		}
	}
	return out
}

func kindOf(t *testing.T, doc string) string {
	t.Helper()
	var tm struct {
		Kind string `json:"kind"`
	}
	require.NoError(t, yaml.Unmarshal([]byte(doc), &tm), doc)
	return tm.Kind
}

// decodeFFS strictly decodes doc into the ffs type kind names and checks its apiVersion.
func decodeFFS(t *testing.T, path, kind, doc string) {
	t.Helper()
	var apiVersion string
	switch kind {
	case "AlertTarget":
		var at apiv1alpha1.AlertTarget
		require.NoError(t, yaml.UnmarshalStrict([]byte(doc), &at), "%s: %s", path, doc)
		apiVersion = at.APIVersion
	case "Exception":
		// A fixed expiry would make the example invalid once it is more than a year away or past (F55): it is
		// filled in as the example is applied.
		require.Contains(t, doc, "\n  expires: \"${EXPIRES}\"\n", "%s: an Exception example's expires is the ${EXPIRES} placeholder", path)
		doc = strings.ReplaceAll(doc, "${EXPIRES}", time.Now().AddDate(0, 0, 90).UTC().Format(time.RFC3339))
		var ex apiv1alpha1.Exception
		require.NoError(t, yaml.UnmarshalStrict([]byte(doc), &ex), "%s: %s", path, doc)
		require.True(t, ex.Spec.Expires.After(time.Now()), "%s: expires", path)
		apiVersion = ex.APIVersion
	default:
		t.Fatalf("%s: kind %q is not an ffs input kind", path, kind)
	}
	require.Equal(t, apiv1alpha1.GroupVersion.String(), apiVersion, "%s: %s", path, doc)
}

func TestDocs_NoHiddenCategory(t *testing.T) {
	needle := []byte("anx" + "iety")
	for _, path := range docFiles(t) {
		require.False(t, bytes.Contains(bytes.ToLower([]byte(readFile(t, path))), needle), "%s mentions the hidden category", path)
	}
}

func TestDocs_CoverageListsBlindSpots(t *testing.T) {
	doc := readFile(t, "../../docs/coverage.md")
	for _, want := range []string{"cargo-auditable", "KEP-4412", "unresolvable", "registry mirror", "kernel", "runc",
		"CPE", "workload identity", "LoadBalancer", "triage", "attestation", "node agent", "no package database (image-based OS)",
		"node agent has not reported", "no containerd content store on this node", "deferred"} {
		require.Contains(t, doc, want)
	}
	require.NotContains(t, doc, "A later node agent")
}

func TestDocs_NodeAgentListsEveryMount(t *testing.T) {
	doc := readFile(t, "../../docs/node-agent.md")
	for _, p := range []string{"/etc/os-release", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/var/lib/dpkg", "/var/lib/rpm", "/lib/apk/db",
		"/var/lib/rancher/k3s/data", "/var/lib/rancher/rke2/bin", "/var/lib/containerd/io.containerd.content.v1.content",
		"/var/lib/rancher/k3s/agent/containerd/io.containerd.content.v1.content",
		"/var/lib/rancher/rke2/agent/containerd/io.containerd.content.v1.content"} {
		require.Contains(t, doc, "`"+p+"`", "docs/node-agent.md does not list the mount %s", p)
	}
	for _, want := range []string{"GKE Autopilot", "--set nodeAgent.enabled=false", "spc_t", "nodeAgent.openshift.scc",
		"no package database (image-based OS)", "pod-security.kubernetes.io/enforce: privileged", "ffs-agent", "empty directory",
		"under-report", "FFSNodeAgentNotReporting", "/usr/lib/sysimage/rpm", "ffs.theitdept.au/not-after", "certManager", "Argo CD",
		"crio", "runc findings re-detect"} {
		require.Contains(t, doc, want)
	}
}

// nodeAgentLeaves are the nodeAgent values documented as one row although they hold maps or lists.
var nodeAgentLeaves = map[string]bool{"resources": true, "nodeSelector": true, "tolerations": true,
	"tls.certManager.issuerRef": true, "hostPaths.extraBinDirs": true, "updateStrategy": true}

// valuePaths returns the dotted paths of the leaves under m, prefix included.
func valuePaths(prefix string, m map[string]any) []string {
	var out []string
	for k, v := range m {
		p := k
		if prefix != "" {
			p = prefix + "." + k
		}
		if sub, ok := v.(map[string]any); ok && !nodeAgentLeaves[p] {
			out = append(out, valuePaths(p, sub)...)
			continue
		}
		out = append(out, p)
	}
	return out
}

func TestDocs_NodeAgentCoversEveryValue(t *testing.T) {
	var values struct {
		NodeAgent map[string]any `json:"nodeAgent"`
	}
	require.NoError(t, yaml.Unmarshal([]byte(readFile(t, "../../charts/ffs/values.yaml")), &values))
	paths := valuePaths("", values.NodeAgent)
	require.Len(t, paths, 30)
	doc := readFile(t, "../../docs/node-agent.md")
	for _, p := range paths {
		require.Contains(t, doc, "`nodeAgent."+p+"`", "docs/node-agent.md does not describe nodeAgent.%s", p)
	}
}

func TestDocs_ReadmeSaysAgentIsDefault(t *testing.T) {
	doc := readFile(t, "../../README.md")
	for _, want := range []string{"DaemonSet", "installed by default", "docs/node-agent.md", "--set nodeAgent.enabled=false", "GKE Autopilot"} {
		require.Contains(t, doc, want)
	}
}

// openAPI is the API contract, api/openapi.yaml.
func openAPI(t *testing.T) map[string]any {
	t.Helper()
	var spec map[string]any
	require.NoError(t, yaml.Unmarshal([]byte(readFile(t, "../../api/openapi.yaml")), &spec))
	return spec
}

// enum returns the values of the enum schema components.schemas.<schema>, which must have some.
func enum(t *testing.T, spec map[string]any, schema string) []string {
	t.Helper()
	components, _ := spec["components"].(map[string]any)
	schemas, _ := components["schemas"].(map[string]any)
	s, _ := schemas[schema].(map[string]any)
	values, _ := s["enum"].([]any)
	require.NotEmpty(t, values, "components.schemas.%s.enum", schema)
	out := make([]string, len(values))
	for i, v := range values {
		str, ok := v.(string)
		require.True(t, ok, "components.schemas.%s.enum[%d] is not a string", schema, i)
		out[i] = str
	}
	return out
}

func TestDocs_APIDocumentsEveryOperation(t *testing.T) {
	doc, spec := readFile(t, "../../docs/api.md"), openAPI(t)
	paths, _ := spec["paths"].(map[string]any)
	require.NotEmpty(t, paths)
	for p := range paths {
		require.Contains(t, doc, "`/api/v1"+p+"`") // includes /stream
	}
	require.Contains(t, doc, "`/api/v1/openapi.yaml`")
	for _, c := range enum(t, spec, "ProblemCode") {
		require.Contains(t, doc, "`"+c+"`")
	}
	for _, w := range []string{"Last-Event-ID", "application/problem+json", "generatedAt", "cursor", "421", "405"} {
		require.Contains(t, doc, w)
	}
	require.Contains(t, readFile(t, "../../README.md"), "(docs/api.md)")
}

func TestDocs_CoverageListsEveryGapAndRemedy(t *testing.T) {
	doc, spec := readFile(t, "../../docs/coverage.md"), openAPI(t)
	for _, c := range enum(t, spec, "GapCode") {
		require.Contains(t, doc, "| `"+c+"` |") // first table column
	}
	for _, c := range enum(t, spec, "RemedyCode") {
		require.Contains(t, doc, "`"+c+"`")
	}
}

// TestDocs_CallItTheWebUI: user-facing copy calls the embedded UI "the web UI"; "dashboard" survives only for the
// Grafana dashboard and the dashboardURL key.
func TestDocs_CallItTheWebUI(t *testing.T) {
	files := append(docFiles(t), "../../charts/ffs/templates/NOTES.txt", "../../charts/ffs/values.yaml")
	for _, path := range files {
		for i, line := range strings.Split(readFile(t, path), "\n") {
			l := strings.ToLower(line)
			if strings.Contains(l, "dashboard") && !strings.Contains(l, "grafana") && !strings.Contains(l, "dashboardurl") {
				t.Errorf("%s:%d says dashboard; call it the web UI: %s", path, i+1, line)
			}
		}
	}
	require.Contains(t, readFile(t, "../../README.md"), "web UI")
}

// TestDocs_SnippetsUseTheNewestRelease (W12): the README's install and upgrade snippets and SECURITY.md's verify snippet
// name the release of the newest Upgrading heading, so the tag commit cannot leave them at the release before.
func TestDocs_SnippetsUseTheNewestRelease(t *testing.T) {
	readme := readFile(t, "../../README.md")
	newest := regexp.MustCompile(`(?m)^### v(\d+\.\d+\.\d+)$`).FindStringSubmatch(readme)
	require.NotNil(t, newest, "README.md has no Upgrading heading")
	v := newest[1]
	pins := regexp.MustCompile(`(?m)^V=(\S+) +# the release to (?:install|upgrade to),`).FindAllStringSubmatch(readme, -1)
	require.Len(t, pins, 2, "README.md's install and upgrade snippets")
	for _, p := range pins {
		require.Equal(t, v, p[1], "README.md: %s", p[0])
	}
	verify := regexp.MustCompile(`(?m)^TAG=v(\S+) V=(\S+) +# the release to verify$`).FindStringSubmatch(readFile(t, "../../SECURITY.md"))
	require.NotNil(t, verify, "SECURITY.md has no verify snippet")
	require.Equal(t, []string{v, v}, verify[1:], "SECURITY.md: %s", verify[0])
}
