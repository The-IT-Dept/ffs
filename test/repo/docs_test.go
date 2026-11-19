package repo

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

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
		var ex apiv1alpha1.Exception
		require.NoError(t, yaml.UnmarshalStrict([]byte(doc), &ex), "%s: %s", path, doc)
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
		"CPE", "workload identity", "LoadBalancer", "triage", "attestation"} {
		require.Contains(t, doc, want)
	}
}
