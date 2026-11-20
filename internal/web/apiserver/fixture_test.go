package apiserver_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
	"github.com/the-it-dept/ffs/internal/web/apigen"
	"github.com/the-it-dept/ffs/internal/web/webtest"
)

// TestFixture_SmallDerivedFacts pins what the handler tests derive from Small, read straight from
// the store.
func TestFixture_SmallDerivedFacts(t *testing.T) {
	f := webtest.Open(t)
	cluster := model.Scope{Kind: model.ScopeCluster}
	st, err := f.Store.ScopeStats(t.Context(), cluster)
	require.NoError(t, err)
	require.Equal(t, smallOpen, apigen.PriorityCounts{Urgent: st.Counts.Urgent, High: st.Counts.High, Medium: st.Counts.Medium,
		Low: st.Counts.Low})
	require.Equal(t, smallOpenTotal, st.Open)
	require.Equal(t, 9, st.Fixable)
	require.Equal(t, 2, st.Exploited)
	require.Equal(t, 1, st.Excepted)

	groups, err := f.Store.FindingGroups(t.Context(), store.FindingQuery{Limit: 200}, store.GroupFix)
	require.NoError(t, err)
	require.Equal(t, smallFixGroups, groups.Groups)

	cov, err := f.Store.CoverageOf(t.Context(), cluster)
	require.NoError(t, err)
	require.Equal(t, store.CoverageFigure{InUse: 10, SeenInto: 6, Full: 4}, cov)
}
