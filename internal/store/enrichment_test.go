package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

func TestSetAdvisoryKEV_ClearsAndKeepsOtherFields(t *testing.T) {
	s := newStore(t)
	require.NoError(t, s.UpsertAdvisory(ctx, model.Advisory{
		ID: "CVE-2026-0001", Aliases: []string{"GHSA-x"}, Title: "title", EPSS: 0.4, Observed: t0,
	}))
	d := time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)

	require.NoError(t, s.SetAdvisoryKEV(ctx, "GHSA-x", &d))
	a, ok, err := s.GetAdvisory(ctx, "CVE-2026-0001")
	require.NoError(t, err)
	require.True(t, ok)
	require.NotNil(t, a.KEVAdded)
	require.True(t, a.KEVAdded.Equal(d))
	require.Equal(t, "title", a.Title)
	require.Equal(t, 0.4, a.EPSS)

	require.NoError(t, s.SetAdvisoryKEV(ctx, "CVE-2026-0001", nil))
	a, _, _ = s.GetAdvisory(ctx, "CVE-2026-0001")
	require.Nil(t, a.KEVAdded)
	require.Equal(t, "title", a.Title)
	require.Equal(t, 0.4, a.EPSS)

	require.NoError(t, s.SetAdvisoryKEV(ctx, "CVE-unknown", &d))
	_, ok, _ = s.GetAdvisory(ctx, "CVE-unknown")
	require.False(t, ok)
}

func TestSetAdvisoryEPSS_KeepsOtherFields(t *testing.T) {
	s := newStore(t)
	d := t0.Add(-time.Hour)
	require.NoError(t, s.UpsertAdvisory(ctx, model.Advisory{ID: "CVE-2026-0001", Title: "title", KEVAdded: &d, Observed: t0}))
	require.NoError(t, s.SetAdvisoryEPSS(ctx, "CVE-2026-0001", 0.25, 0.9))
	a, _, _ := s.GetAdvisory(ctx, "CVE-2026-0001")
	require.Equal(t, 0.25, a.EPSS)
	require.Equal(t, 0.9, a.EPSSPercentile)
	require.Equal(t, "title", a.Title)
	require.NotNil(t, a.KEVAdded)
	require.NoError(t, s.SetAdvisoryEPSS(ctx, "CVE-unknown", 0.1, 0.1))
}
