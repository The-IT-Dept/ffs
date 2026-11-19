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

func TestNoForbiddenDirectDeps(t *testing.T) {
	path := filepath.Join(moduleRoot(t), "go.mod")
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	f, err := modfile.Parse(path, data, nil)
	require.NoError(t, err)

	forbidden := []string{
		"github.com/google/go-containerregistry/pkg/authn/k8schain",
		"github.com/aws/",
		"cloud.google.com/",
		"github.com/Azure/",
	}
	for _, r := range f.Require {
		if r.Indirect {
			continue
		}
		for _, p := range forbidden {
			require.False(t, r.Mod.Path == p || strings.HasPrefix(r.Mod.Path, p),
				"forbidden direct dependency %s", r.Mod.Path)
		}
	}
}
