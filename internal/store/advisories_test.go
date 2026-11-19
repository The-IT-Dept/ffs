package store

import (
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

func TestCanonical_GHSAAliasingCVE(t *testing.T) {
	s := newStore(t)
	require.NoError(t, s.UpsertAdvisory(ctx, model.Advisory{ID: "GHSA-aaaa-bbbb-cccc", Aliases: []string{"CVE-2026-0001"}, Title: "x"}))
	for _, id := range []string{"GHSA-aaaa-bbbb-cccc", "CVE-2026-0001"} {
		c, err := s.Canonical(ctx, id)
		require.NoError(t, err)
		require.Equal(t, "CVE-2026-0001", c)
	}
	c, _ := s.Canonical(ctx, "PYSEC-2026-99")
	require.Equal(t, "PYSEC-2026-99", c) // unknown resolves to itself
	a, ok, _ := s.GetAdvisory(ctx, "GHSA-aaaa-bbbb-cccc")
	require.True(t, ok)
	require.Equal(t, "CVE-2026-0001", a.ID)
	require.Equal(t, []string{"GHSA-aaaa-bbbb-cccc"}, a.Aliases)
}

func TestUpsertAdvisory_KeepsFirstObservedAndMerges(t *testing.T) {
	s := newStore(t)
	kev := t0.Add(-48 * time.Hour)
	require.NoError(t, s.UpsertAdvisory(ctx, model.Advisory{ID: "CVE-2026-0001", Title: "old", Observed: t0, KEVAdded: &kev, EPSS: 0.4}))
	require.NoError(t, s.UpsertAdvisory(ctx, model.Advisory{ID: "CVE-2026-0001", Title: "new", Observed: t0.Add(time.Hour), Aliases: []string{"GHSA-aaaa-bbbb-cccc"}}))
	a, _, _ := s.GetAdvisory(ctx, "CVE-2026-0001")
	require.True(t, a.Observed.Equal(t0))
	require.Equal(t, "new", a.Title)
	require.NotNil(t, a.KEVAdded) // zero fields keep stored enrichment
	require.Equal(t, 0.4, a.EPSS)
	require.Equal(t, []string{"GHSA-aaaa-bbbb-cccc"}, a.Aliases)
	require.NoError(t, s.UpsertAdvisory(ctx, model.Advisory{ID: "CVE-2026-0002"}))
	b, _, _ := s.GetAdvisory(ctx, "CVE-2026-0002")
	require.False(t, b.Observed.IsZero())
	m, _ := s.Advisories(ctx, []string{"GHSA-aaaa-bbbb-cccc", "CVE-2026-0002", "CVE-2026-9999"})
	require.ElementsMatch(t, []string{"CVE-2026-0001", "CVE-2026-0002"}, slices.Collect(maps.Keys(m)))
}

func TestUpsertAdvisory_RekeysMatchesWhenCVEArrives(t *testing.T) {
	s := newStore(t)
	require.NoError(t, s.UpsertAdvisory(ctx, model.Advisory{ID: "GHSA-aaaa-bbbb-cccc", Observed: t0}))
	_, err := s.ReplaceMatches(ctx, MatchScope{Source: model.SourceOSV, Digests: []string{"sha256:a"}},
		[]model.Match{{ImageDigest: "sha256:a", PackageID: "p1", AdvisoryID: "GHSA-aaaa-bbbb-cccc", Source: model.SourceOSV, FixState: model.FixFixed}})
	require.NoError(t, err)
	require.NoError(t, s.UpsertAdvisory(ctx, model.Advisory{ID: "GHSA-aaaa-bbbb-cccc", Aliases: []string{"CVE-2026-0001"}}))
	ms, _ := s.MatchesForDigests(ctx, []string{"sha256:a"})
	require.Equal(t, "CVE-2026-0001", ms[0].AdvisoryID)
	a, _, _ := s.GetAdvisory(ctx, "CVE-2026-0001")
	require.True(t, a.Observed.Equal(t0))
	ids, _ := s.AdvisoryIDsInUse(ctx)
	require.Equal(t, []string{"CVE-2026-0001"}, ids)
}
