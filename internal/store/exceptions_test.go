package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/findings"
)

func TestExceptionRules_RoundTrip(t *testing.T) {
	s := newStore(t)
	accept := findings.ExceptionRule{Namespace: "web", Name: "accept", AdvisoryIDs: []string{"CVE-2026-41873"},
		Packages: []string{"openssl"}, Expires: t0.Add(30 * 24 * time.Hour), VEXStatus: "not_affected"}
	admin := findings.ExceptionRule{Namespace: "ffs", Name: "accept", ClusterWide: true,
		ImageRepoGlobs: []string{"docker.io/library/*"}, Expires: t0.Add(time.Hour)}
	// "web-a/x" sorts before "web/accept" by key, but after it by (namespace, name).
	hyphen := findings.ExceptionRule{Namespace: "web-a", Name: "x", Owners: []string{"api"}, Expires: t0.Add(time.Hour)}

	changed, err := s.PutExceptionRule(ctx, accept)
	require.NoError(t, err)
	require.True(t, changed)
	changed, err = s.PutExceptionRule(ctx, accept)
	require.NoError(t, err)
	require.False(t, changed, "an identical rule is not rewritten")

	accept.Packages = []string{"openssl", "libssl3"}
	changed, err = s.PutExceptionRule(ctx, accept)
	require.NoError(t, err)
	require.True(t, changed, "a changed field replaces the rule")

	for _, r := range []findings.ExceptionRule{hyphen, admin} {
		changed, err = s.PutExceptionRule(ctx, r)
		require.NoError(t, err)
		require.True(t, changed)
	}
	rules, err := s.ExceptionRules(ctx)
	require.NoError(t, err)
	require.Equal(t, []findings.ExceptionRule{admin, hyphen, accept}, rules)

	deleted, err := s.DeleteExceptionRule(ctx, "web", "accept")
	require.NoError(t, err)
	require.True(t, deleted)
	deleted, err = s.DeleteExceptionRule(ctx, "web", "accept")
	require.NoError(t, err)
	require.False(t, deleted)

	rules, err = s.ExceptionRules(ctx)
	require.NoError(t, err)
	require.Equal(t, []findings.ExceptionRule{admin, hyphen}, rules)
}
