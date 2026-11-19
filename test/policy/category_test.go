package policy

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAnxietyOnlyInMarkers(t *testing.T) {
	needle := "anx" + "iety"
	root := moduleRoot(t)
	skip := []string{".git", "bin", "docs/superpowers", "docs/research", "config/crd", "charts/ffs/crds"}
	out, err := exec.CommandContext(t.Context(), "git", "-C", root, "ls-files", "-z").Output() //nolint:gosec // fixed git binary; root is the module root derived from the test file
	require.NoError(t, err)
	var allowed []string
files:
	for _, rel := range strings.Split(string(out), "\x00") {
		if rel == "" {
			continue
		}
		for _, s := range skip {
			if rel == s || strings.HasPrefix(rel, s+"/") {
				continue files
			}
		}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel))) //nolint:gosec // path comes from git ls-files under the module root
		if err != nil && os.IsNotExist(err) {
			continue // tracked but deleted in the working tree
		}
		require.NoError(t, err, rel)
		if bytes.IndexByte(data[:min(len(data), 8000)], 0) >= 0 {
			continue
		}
		for i, line := range strings.Split(string(data), "\n") {
			if !strings.Contains(strings.ToLower(line), needle) {
				continue
			}
			trimmed := strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(rel, "api/v1alpha1/") && strings.HasPrefix(trimmed, "// +kubebuilder:resource:"):
				allowed = append(allowed, rel)
			case rel == "test/policy/category_test.go" && strings.HasPrefix(trimmed, "func Test") && strings.HasSuffix(trimmed, "(t *testing.T) {"):
			default:
				t.Errorf("%s:%d mentions the hidden category", rel, i+1)
			}
		}
	}
	require.ElementsMatch(t, []string{"api/v1alpha1/finding_types.go", "api/v1alpha1/vulnerability_types.go"}, allowed)
}
