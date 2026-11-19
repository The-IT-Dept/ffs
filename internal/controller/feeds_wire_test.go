package controller

import (
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/engine"
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
