package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/mod/modfile"
)

// moduleRoot walks up from the working directory to the directory holding go.mod.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqual(t, dir, parent, "go.mod not found")
		dir = parent
	}
}

// forbiddenDeps are module paths, or prefixes of them, that ffs must not require directly: no k8schain and no cloud
// SDKs (registry credentials come from pull secrets and the operator Secret only).
var forbiddenDeps = []string{
	"github.com/google/go-containerregistry/pkg/authn/k8schain",
	"github.com/aws/",
	"cloud.google.com/",
	"github.com/Azure/",
}

// forbiddenDirectDeps returns the direct requirements of f that forbiddenDeps names.
func forbiddenDirectDeps(f *modfile.File) []string {
	var out []string
	for _, r := range f.Require {
		if r.Indirect {
			continue
		}
		for _, p := range forbiddenDeps {
			if r.Mod.Path == p || strings.HasPrefix(r.Mod.Path, p) {
				out = append(out, r.Mod.Path)
			}
		}
	}
	return out
}

func TestNoForbiddenDirectDeps(t *testing.T) {
	path := filepath.Join(moduleRoot(t), "go.mod")
	data, err := os.ReadFile(path) //nolint:gosec // path is derived from the module root, not user input
	require.NoError(t, err)
	f, err := modfile.Parse(path, data, nil)
	require.NoError(t, err)
	require.Empty(t, forbiddenDirectDeps(f))
}

// TestForbiddenDirectDeps_Detects: the check finds a forbidden module required directly, by exact path or prefix, and
// leaves indirect requirements alone (F55).
func TestForbiddenDirectDeps_Detects(t *testing.T) {
	const gomod = `module example.com/m

go 1.27.0

require (
	cloud.google.com/go/storage v1.50.0
	github.com/google/go-containerregistry/pkg/authn/k8schain v0.0.0-20260101000000-000000000000
	github.com/stretchr/testify v1.11.1
)

require (
	github.com/aws/aws-sdk-go-v2 v1.36.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.17.0 // indirect
)
`
	f, err := modfile.Parse("go.mod", []byte(gomod), nil)
	require.NoError(t, err)
	require.Equal(t, []string{"cloud.google.com/go/storage", "github.com/google/go-containerregistry/pkg/authn/k8schain"},
		forbiddenDirectDeps(f))
}
