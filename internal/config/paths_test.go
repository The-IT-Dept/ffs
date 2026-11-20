package config

import (
	"slices"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFieldPaths(t *testing.T) {
	p := FieldPaths()
	require.True(t, sort.StringsAreSorted(p))
	require.Len(t, p, len(slices.Compact(slices.Clone(p)))) // unique
	for _, want := range []string{"clusterName", "listen", "catalog.socket", "catalog.maxImageBytes",
		"registry.mirrors", "feeds.osv.interval", "feeds.grypedb.staleAfter", "crd.maxFindings", "upgrades.overrides",
		"nodeAgent.exposedNodes", "nodeAgent.staleAfter"} {
		require.Contains(t, p, want)
	}
	for _, s := range p {
		require.NotContains(t, s, ",") // tag options stripped
	}
	require.NotContains(t, p, "registry") // structs are not leaves
}
