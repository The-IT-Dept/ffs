package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

// TestStore_OpenFindingCounts (W33): open findings counted by owner, priority, fix and the
// advisory's KEV listing as stored now; excepted and resolved findings and advisories with no row
// count as not listed.
func TestStore_OpenFindingCounts(t *testing.T) {
	s := newStore(t)
	added := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for _, a := range []model.Advisory{{ID: "CVE-2026-0001", KEVAdded: &added}, {ID: "CVE-2026-0002"}, {ID: "CVE-2026-0003", KEVAdded: &added}} {
		require.NoError(t, s.UpsertAdvisory(ctx, a))
	}
	web := model.OwnerRef{Kind: "Deployment", Namespace: "shop", Name: "web"}
	api := model.OwnerRef{Kind: "Deployment", Namespace: "shop", Name: "api"}
	finding := func(o model.OwnerRef, id string, p model.Priority, fixable bool, state model.FindingState) model.Finding {
		return model.Finding{Fingerprint: model.FindingFingerprint("test", o, "ghcr.io/a", id), Owner: o, ImageRepo: "ghcr.io/a",
			AdvisoryID: id, Priority: p, FixAvailable: fixable, State: state}
	}
	require.NoError(t, s.ApplyFindings(ctx, []model.Finding{
		finding(web, "CVE-2026-0001", model.PriorityHigh, true, model.StateOpen),
		finding(web, "CVE-2026-0002", model.PriorityHigh, true, model.StateOpen),
		finding(api, "CVE-2026-0001", model.PriorityMedium, false, model.StateOpen),
		finding(api, "CVE-2026-0003", model.PriorityUrgent, true, model.StateExcepted),
		finding(api, "CVE-2026-0009", model.PriorityLow, false, model.StateOpen), // no advisory row
	}, nil))

	got, err := s.OpenFindingCounts(ctx)
	require.NoError(t, err)
	require.Equal(t, []FindingCount{
		{OwnerKey: api.Key(), Namespace: "shop", Priority: model.PriorityLow, N: 1},
		{OwnerKey: api.Key(), Namespace: "shop", Priority: model.PriorityMedium, KEV: true, N: 1},
		{OwnerKey: web.Key(), Namespace: "shop", Priority: model.PriorityHigh, FixAvailable: true, N: 1},
		{OwnerKey: web.Key(), Namespace: "shop", Priority: model.PriorityHigh, FixAvailable: true, KEV: true, N: 1},
	}, got)

	none := newStore(t)
	got, err = none.OpenFindingCounts(ctx)
	require.NoError(t, err)
	require.Empty(t, got)
}
