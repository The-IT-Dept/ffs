package engine_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

func TestEngine_ScoreMatchesUsesOwnerContext(t *testing.T) {
	h := newHarness(t)
	const cand = "sha256:cand"
	pkg := h.libssl3
	pkg.ImageDigest = cand
	pkg.ID = model.PackageID(cand, pkg)
	require.NoError(t, h.st.UpsertImage(ctx, model.Image{Digest: cand, Repo: apiRepo, Platform: "linux/amd64",
		Status: model.ImageCatalogued, Source: "registry", ConfigUser: "app", CataloguedAt: t0}))
	require.NoError(t, h.st.PutSBOM(ctx, cand, []byte(`{"artifacts":[]}`), []model.Package{pkg}))
	// rated critical by its CNA only, with a fix
	m := newMatch(pkg, cve, model.SourceGrype, "3.0.15-1")
	m.DBBuilt = t0.Add(time.Hour)

	owner, ok, err := h.st.GetOwner(ctx, apiKey)
	require.NoError(t, err)
	require.True(t, ok)
	exposed := owner
	exposed.Context = model.WorkloadContext{Exposed: true, ExposurePaths: []string{"Service web/api (LoadBalancer)"}}

	fs, err := h.e.ScoreMatches(ctx, exposed, apiRepo, []model.Match{m})
	require.NoError(t, err)
	require.Len(t, fs, 1)
	require.Equal(t, model.PriorityUrgent, fs[0].Priority, "critical and exposed")
	require.Equal(t, []string{cand}, fs[0].Digests)
	require.Equal(t, apiRepo, fs[0].ImageRepo)
	require.Equal(t, model.StateOpen, fs[0].State)

	fs, err = h.e.ScoreMatches(ctx, owner, apiRepo, []model.Match{m})
	require.NoError(t, err)
	require.Len(t, fs, 1)
	require.Equal(t, model.PriorityHigh, fs[0].Priority, "critical with a fix, not exposed")

	require.Empty(t, h.findings(apiKey), "nothing is persisted")
	require.Empty(t, h.transitions())
	require.True(t, h.e.Idle())
}

// recordingObserver records observer calls in order.
type recordingObserver struct{ calls []string }

func (r *recordingObserver) MatchesReplaced(_ context.Context, digests []string) {
	for _, d := range digests {
		r.calls = append(r.calls, "matches "+d)
	}
}

func (r *recordingObserver) OwnersRecomputed(_ context.Context, keys []string) {
	for _, k := range keys {
		r.calls = append(r.calls, "owners "+k)
	}
}

func TestEngine_ObserversNotified(t *testing.T) {
	h := newHarness(t)
	obs := &recordingObserver{}
	h.e.AddObserver(obs)
	h.catalogueAPI() // OnImageCatalogued(d1) + Drain
	require.Equal(t, []string{"matches " + d1, "owners " + apiKey}, obs.calls)

	// re-cataloguing with the same matches replaces nothing, but the owners are still recomputed
	obs.calls = nil
	require.NoError(t, h.e.OnImageCatalogued(ctx, d1))
	require.NoError(t, h.e.Drain(ctx))
	require.Equal(t, []string{"owners " + apiKey}, obs.calls)
}
