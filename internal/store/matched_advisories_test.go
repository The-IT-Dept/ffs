package store

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

func TestAdvisoriesWithMatches(t *testing.T) {
	s := newStore(t)
	m := func(source model.MatchSource, advisory string) model.Match {
		return model.Match{ImageDigest: "sha256:a", PackageID: "pkg-php", AdvisoryID: advisory, Source: source, FixState: model.FixFixed}
	}
	_, err := s.ReplaceMatches(ctx, MatchScope{Source: model.SourceUpstream, Digests: []string{"sha256:a"}},
		[]model.Match{m(model.SourceUpstream, "CVE-2026-0002"), m(model.SourceUpstream, "CVE-2026-0001")})
	require.NoError(t, err)
	_, err = s.ReplaceMatches(ctx, MatchScope{Source: model.SourceOSV, Digests: []string{"sha256:a"}},
		[]model.Match{m(model.SourceOSV, "CVE-2026-0003")})
	require.NoError(t, err)

	got, err := s.AdvisoriesWithMatches(ctx, model.SourceUpstream, []string{"CVE-2026-0003", "CVE-2026-0002", "CVE-2026-0001", "CVE-2026-0009"})
	require.NoError(t, err)
	require.Equal(t, []string{"CVE-2026-0001", "CVE-2026-0002"}, got)
	got, err = s.AdvisoriesWithMatches(ctx, model.SourceUpstream, nil)
	require.NoError(t, err)
	require.Empty(t, got)
}

// TestMatchersVersion: a store no full re-match by every matcher has run on has no matchers
// version, and a recorded one replaces the last.
func TestMatchersVersion(t *testing.T) {
	s := newStore(t)
	v, err := s.MatchersVersion(ctx)
	require.NoError(t, err)
	require.Empty(t, v)
	for _, want := range []string{"2", "3"} {
		require.NoError(t, s.RecordMatchersVersion(ctx, want))
		v, err = s.MatchersVersion(ctx)
		require.NoError(t, err)
		require.Equal(t, want, v)
	}
}
