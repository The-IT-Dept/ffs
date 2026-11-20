package engine_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/feeds/grypedb"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

// transitionsOf returns the transitions on advisory, oldest first.
func (h *harness) transitionsOf(advisory string) []model.Transition {
	h.t.Helper()
	var out []model.Transition
	for _, tr := range h.transitions() {
		if tr.AdvisoryID == advisory {
			out = append(out, tr)
		}
	}
	return out
}

// A rollout that removes a finding, recomputed together with a Grype DB update, resolves it as an
// InventoryChange (spec §6.7.5), not as the DB update's NewAdvisory (F74).
func TestEngine_RolloutDuringGrypeDBResolvesAsInventoryChange(t *testing.T) {
	h := newHarness(t)
	h.catalogueAPI()
	require.Equal(t, model.StateOpen, h.finding(apiKey, cve).State)

	// web/api rolls out d3, a catalogued and matched image without the vulnerable package...
	const d3 = "sha256:d3"
	zlib := model.Package{ImageDigest: d3, Ecosystem: "deb", Distro: debian, Name: "zlib1g", Version: "1:1.3.dfsg-3", Arch: "amd64"}
	zlib.ID = model.PackageID(d3, zlib)
	require.NoError(t, h.st.UpsertImage(ctx, model.Image{Digest: d3, Repo: apiRepo, Platform: "linux/amd64",
		Status: model.ImageCatalogued, Source: "registry", ConfigUser: "app", CataloguedAt: t0}))
	require.NoError(t, h.st.PutSBOM(ctx, d3, []byte(`{"artifacts":[]}`), []model.Package{zlib}))
	require.NoError(t, h.e.OnImageCatalogued(ctx, d3))
	require.NoError(t, h.st.UpsertOwner(ctx, model.Owner{Ref: apiRef, ServiceAccount: "default", Arch: []string{"amd64"},
		Containers: []model.ContainerUse{{Name: "api", Kind: model.ContainerRegular, ImageRef: apiRepo + ":1.1",
			Repo: apiRepo, Digest: d3, Platform: "linux/amd64"}}}))
	require.NoError(t, h.e.OnOwnersChanged(ctx, []string{apiKey}))
	// ...and a Grype DB arrives before the owner is recomputed.
	h.clock.now = t0.Add(2 * time.Hour)
	require.NoError(t, h.e.OnGrypeDB(ctx, grypedb.Update{Path: "db", Built: t0.Add(90 * time.Minute), Full: true}))
	require.NoError(t, h.e.Drain(ctx))

	require.Equal(t, model.StateResolved, h.finding(apiKey, cve).State)
	ts := h.transitionsOf(cve)
	last := ts[len(ts)-1]
	require.Equal(t, apiRef, last.Owner)
	require.Equal(t, model.StateResolved, last.ToState)
	require.Equal(t, model.TriggerInventoryChange, last.Trigger)
}

// A finding the recompute of an exception change creates carries the exception trigger,
// ExceptionExpired, not PriorityChange (F74): here a match stored without its owner being queued,
// as when a matcher's write races the exception change's recompute.
func TestEngine_CreationByAnExceptionChangeCarriesTheExceptionTrigger(t *testing.T) {
	h := newHarness(t)
	h.catalogueAPI()
	m := newMatch(h.zlib1g, cve, model.SourceGrype, "1:1.3.dfsg-1")
	m.DBBuilt, m.VendorSeverity, m.VendorSeveritySource = t0, model.SeverityHigh, "debian"
	_, err := h.st.Store.ReplaceMatches(ctx, store.MatchScope{Source: model.SourceGrype, Digests: []string{d2}}, []model.Match{m})
	require.NoError(t, err)

	h.clock.now = t0.Add(time.Minute)
	require.NoError(t, h.e.OnExceptionsChanged(ctx))
	require.NoError(t, h.e.Drain(ctx))

	f := h.finding(cartKey, cve)
	require.Equal(t, model.StateOpen, f.State)
	var created []model.Transition
	for _, tr := range h.transitionsOf(cve) {
		if tr.Owner == cartRef {
			created = append(created, tr)
		}
	}
	require.Len(t, created, 1)
	require.Equal(t, model.FindingState(""), created[0].FromState)
	require.Equal(t, model.TriggerExceptionExpired, created[0].Trigger)
	require.Len(t, h.transitionsOf(cve), 2, "web/api's finding did not change")
}

// EPSS has a hysteresis band (F61): a finding bumped at 0.1 keeps its priority until EPSS falls
// below 0.09, so a score hovering at the edge does not flap the priority daily.
func TestEngine_EPSSHysteresisHoldsPriority(t *testing.T) {
	h := newHarness(t)
	const lowCVE = "CVE-2026-60001"
	require.NoError(t, h.st.UpsertAdvisory(ctx, model.Advisory{ID: lowCVE, Published: t0.Add(-time.Hour),
		CNASeverity: model.SeverityLow, CNASource: "openssl"}))
	h.osv.fn = matchOn(nil, d1, newMatch(h.libssl3, lowCVE, model.SourceOSV, "3.0.15-1"))
	require.NoError(t, h.e.OnImageCatalogued(ctx, d1))
	require.NoError(t, h.e.Drain(ctx))
	require.Equal(t, model.PriorityLow, h.finding(apiKey, lowCVE).Priority)

	steps := []struct {
		epss float64
		want model.Priority
	}{
		{0.1, model.PriorityMedium},   // enters at 0.1
		{0.095, model.PriorityMedium}, // inside the band: held
		{0.09, model.PriorityMedium},  // at the leave edge: held
		{0.0899, model.PriorityLow},   // below it: leaves
		{0.095, model.PriorityLow},    // inside the band from below: stays
		{0.1, model.PriorityMedium},
	}
	for i, s := range steps {
		h.clock.now = t0.Add(time.Duration(i+1) * 24 * time.Hour)
		require.NoError(t, h.st.SetAdvisoryEPSS(ctx, lowCVE, s.epss, 0.9))
		require.NoError(t, h.e.OnAdvisoriesEnriched(ctx, []string{lowCVE}))
		require.NoError(t, h.e.Drain(ctx))
		f := h.finding(apiKey, lowCVE)
		require.Equal(t, s.want, f.Priority, "EPSS %v", s.epss)
		require.Equal(t, s.want == model.PriorityMedium, f.Signals.EPSSElevated, "EPSS %v", s.epss)
	}
	var moves []model.Priority
	for _, tr := range h.transitionsOf(lowCVE)[1:] {
		require.Equal(t, model.TriggerPriorityChange, tr.Trigger)
		moves = append(moves, tr.ToPriority)
	}
	require.Equal(t, []model.Priority{model.PriorityMedium, model.PriorityLow, model.PriorityMedium}, moves)
}
