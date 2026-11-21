package controller

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/engine"
	"github.com/the-it-dept/ffs/internal/feeds"
	"github.com/the-it-dept/ffs/internal/match"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

// TestWire_KEVAndEPSSObserveNewMatches: the wired KEV and EPSS feeds give a newly stored match its
// KEV date and EPSS score from their cached data before the engine queues its owners (F27).
func TestWire_KEVAndEPSSObserveNewMatches(t *testing.T) {
	ctx := context.Background()
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(cfg.DataDir, "feeds"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(cfg.DataDir, "feeds", "kev.json"),
		[]byte(`{"vulnerabilities":[{"cveID":"CVE-2024-10441","dateAdded":"2026-11-18"}]}`), 0o600))
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, err := zw.Write([]byte("#model_version:v2026.06.15,score_date:2026-11-18T12:00:28Z\ncve,epss,percentile\nCVE-2024-10441,0.62000,0.98000\n"))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	require.NoError(t, os.WriteFile(filepath.Join(cfg.DataDir, "feeds", "epss.csv.gz"), gz.Bytes(), 0o600))

	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "ffs.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	eng := engine.New(engine.Options{Config: cfg, Store: st})
	newFeeds(cfg, st, eng, nil)

	const id, d = "CVE-2024-10441", "sha256:new"
	require.NoError(t, st.UpsertAdvisory(ctx, model.Advisory{ID: id, Observed: time.Now()}))
	require.NoError(t, eng.OnMatchDelta(ctx, match.Delta{
		Scope:   store.MatchScope{Source: model.SourceGrype, Digests: []string{d}},
		Matches: []model.Match{{ImageDigest: d, PackageID: "p", AdvisoryID: id, Source: model.SourceGrype, FixState: model.FixFixed}},
	}, model.TriggerInventoryChange))
	a, ok, err := st.GetAdvisory(ctx, id)
	require.NoError(t, err)
	require.True(t, ok)
	require.NotNil(t, a.KEVAdded)
	require.InDelta(t, 0.62, a.EPSS, 1e-9)
}

// TestWire_EPSSLeaveEdgeQueuesARecompute (W7): the wired EPSS feed queues a recompute when a score
// crosses a leave edge, not only an entry edge. A finding held at medium at EPSS 0.095 is recomputed
// when its score falls to 0.085, below the 0.09 leave edge, though it crosses no entry edge.
func TestWire_EPSSLeaveEdgeQueuesARecompute(t *testing.T) {
	ctx := context.Background()
	const id, d = "CVE-2024-10441", "sha256:web"
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, err := zw.Write([]byte("#model_version:v2026.06.15,score_date:2026-11-19T12:00:28Z\ncve,epss,percentile\n" + id + ",0.08500,0.90000\n"))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(gz.Bytes()) }))
	t.Cleanup(srv.Close)

	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	cfg.Feeds.EPSS.URL = srv.URL
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "ffs.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	eng := engine.New(engine.Options{Config: cfg, Store: st})
	fs, _ := newFeeds(cfg, st, eng, nil)
	var f feeds.Feed
	for _, x := range fs {
		if x.Name() == feeds.NameEPSS {
			f = x
		}
	}
	require.NotNil(t, f)

	require.NoError(t, st.UpsertAdvisory(ctx, model.Advisory{ID: id, Observed: time.Now()}))
	require.NoError(t, st.SetAdvisoryEPSS(ctx, id, 0.095, 0.9))
	_, err = st.ReplaceMatches(ctx, store.MatchScope{Source: model.SourceGrype, Digests: []string{d}},
		[]model.Match{{ImageDigest: d, PackageID: "p", AdvisoryID: id, Source: model.SourceGrype, FixState: model.FixFixed}})
	require.NoError(t, err)
	web := model.OwnerRef{Kind: "Deployment", Namespace: "shop", Name: "web"}
	require.NoError(t, st.ApplyFindings(ctx, []model.Finding{{Fingerprint: "fp-web", Owner: web, ImageRepo: "ghcr.io/example/web",
		AdvisoryID: id, State: model.StateOpen, Priority: model.PriorityMedium}}, nil))
	require.True(t, eng.Idle())

	require.NoError(t, f.Sync(ctx))
	a, ok, err := st.GetAdvisory(ctx, id)
	require.NoError(t, err)
	require.True(t, ok)
	require.InDelta(t, 0.085, a.EPSS, 1e-9)
	require.False(t, eng.Idle(), "the finding's owner is queued for a recompute")
}
