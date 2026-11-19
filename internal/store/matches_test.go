package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

func TestReplaceMatches_Scope(t *testing.T) {
	s := newStore(t)
	seed(t, s, mt("sha256:d1", "p1", "CVE-1", model.SourceGrype), mt("sha256:d1", "p2", "CVE-2", model.SourceGrype),
		mt("sha256:d2", "p3", "CVE-1", model.SourceGrype), mt("sha256:d1", "p1", "CVE-1", model.SourceOSV))
	aff, err := s.ReplaceMatches(ctx, MatchScope{Source: model.SourceGrype, Digests: []string{"sha256:d1"}},
		[]model.Match{mt("sha256:d1", "p1", "CVE-3", model.SourceGrype)})
	require.NoError(t, err)
	require.Equal(t, []string{"sha256:d1"}, aff)
	require.ElementsMatch(t, []string{"grype:CVE-3", "osv:CVE-1"}, keys(t, s, "sha256:d1")) // other sources untouched
	require.ElementsMatch(t, []string{"grype:CVE-1"}, keys(t, s, "sha256:d2"))              // other digests untouched
	aff, _ = s.ReplaceMatches(ctx, MatchScope{Source: model.SourceOSV, AdvisoryIDs: []string{"CVE-1"}}, nil)
	require.Equal(t, []string{"sha256:d1"}, aff)
	require.ElementsMatch(t, []string{"grype:CVE-1"}, keys(t, s, "sha256:d2")) // AND: grype CVE-1 survives an osv-scoped delete
	aff, _ = s.ReplaceMatches(ctx, MatchScope{Source: model.SourceGrype, Digests: []string{"sha256:d2"}}, []model.Match{mt("sha256:d2", "p3", "CVE-1", model.SourceGrype)})
	require.Empty(t, aff) // identical replace changes nothing
	_, err = s.ReplaceMatches(ctx, MatchScope{}, nil)
	require.ErrorIs(t, err, ErrEmptyScope)
	_, err = s.ReplaceMatches(ctx, MatchScope{Source: model.SourceGrype}, nil)
	require.ErrorIs(t, err, ErrEmptyScope) // a Source-only scope would delete every grype match
	require.ElementsMatch(t, []string{"grype:CVE-1"}, keys(t, s, "sha256:d2"))
	_, err = s.ReplaceMatches(ctx, MatchScope{Source: model.SourceOSV, Digests: []string{"sha256:d1"}}, []model.Match{mt("sha256:d2", "p3", "CVE-9", model.SourceOSV)})
	require.Error(t, err) // match outside scope
}

func TestReplaceMatches_CanonicalisesAndKeepsObservedAt(t *testing.T) {
	s := newStore(t)
	require.NoError(t, s.UpsertAdvisory(ctx, model.Advisory{ID: "GHSA-aaaa-bbbb-cccc", Aliases: []string{"CVE-2026-0001"}}))
	m := mt("sha256:d1", "p1", "GHSA-aaaa-bbbb-cccc", model.SourceOSV)
	m.ObservedAt = t0
	_, err := s.ReplaceMatches(ctx, MatchScope{Source: model.SourceOSV, AdvisoryIDs: []string{"GHSA-aaaa-bbbb-cccc"}}, []model.Match{m})
	require.NoError(t, err)
	m.ObservedAt = t0.Add(time.Hour)
	m.FixedVersions = []string{"1.2.3"}
	aff, _ := s.ReplaceMatches(ctx, MatchScope{Source: model.SourceOSV, AdvisoryIDs: []string{"CVE-2026-0001"}}, []model.Match{m})
	require.Equal(t, []string{"sha256:d1"}, aff) // fixed versions changed
	ms, _ := s.MatchesForDigests(ctx, []string{"sha256:d1"})
	require.Equal(t, "CVE-2026-0001", ms[0].AdvisoryID)
	require.True(t, ms[0].ObservedAt.Equal(t0))
	require.Equal(t, []string{"1.2.3"}, ms[0].FixedVersions)
}

// TestReplaceMatches_KeepsEarlierObservedAt (F2): a surviving row takes an earlier incoming
// observation, such as the OSV record's observation time, but never a later one.
func TestReplaceMatches_KeepsEarlierObservedAt(t *testing.T) {
	s := newStore(t)
	m := mt("sha256:d1", "p1", "CVE-1", model.SourceOSV)
	m.ObservedAt = t0
	scope := MatchScope{Source: model.SourceOSV, Digests: []string{"sha256:d1"}}
	_, err := s.ReplaceMatches(ctx, scope, []model.Match{m})
	require.NoError(t, err)
	m.ObservedAt = t0.Add(-48 * time.Hour)
	aff, err := s.ReplaceMatches(ctx, scope, []model.Match{m})
	require.NoError(t, err)
	require.Empty(t, aff, "observed_at alone is not a change")
	ms, err := s.MatchesForDigests(ctx, []string{"sha256:d1"})
	require.NoError(t, err)
	require.True(t, ms[0].ObservedAt.Equal(t0.Add(-48*time.Hour)))
	m.ObservedAt = time.Time{} // none: the stored time stands
	_, err = s.ReplaceMatches(ctx, scope, []model.Match{m})
	require.NoError(t, err)
	ms, err = s.MatchesForDigests(ctx, []string{"sha256:d1"})
	require.NoError(t, err)
	require.True(t, ms[0].ObservedAt.Equal(t0.Add(-48*time.Hour)))
}
