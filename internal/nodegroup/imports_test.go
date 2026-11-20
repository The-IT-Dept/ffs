package nodegroup

import (
	"go/build"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestImports_Pure(t *testing.T) {
	p, err := build.ImportDir(".", 0)
	require.NoError(t, err)
	for _, imp := range p.Imports {
		if first, _, _ := strings.Cut(imp, "/"); !strings.Contains(first, ".") {
			continue // standard library
		}
		require.Contains(t, []string{"github.com/the-it-dept/ffs/internal/model", "github.com/google/osv-scalibr/semantic"}, imp)
	}
}
