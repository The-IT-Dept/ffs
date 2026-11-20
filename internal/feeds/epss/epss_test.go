package epss_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/engine"
	"github.com/the-it-dept/ffs/internal/feeds"
	"github.com/the-it-dept/ffs/internal/feeds/epss"
	"github.com/the-it-dept/ffs/internal/match"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

var ctx = context.Background()

func csvGz(t *testing.T, rows ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err := fmt.Fprint(zw, "#model_version:v2026.06.15,score_date:2026-11-18T12:00:28Z\ncve,epss,percentile\n")
	require.NoError(t, err)
	for _, r := range rows {
		_, err = fmt.Fprintln(zw, r)
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

// server redirects /current to /file and serves file; it counts file GETs.
type server struct {
	*httptest.Server
	mu    sync.Mutex
	file  []byte
	name  string
	files int
}

func newServer(t *testing.T, file []byte) *server {
	t.Helper()
	s := &server{file: file, name: "/epss_scores-2026-11-18.csv.gz"}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if r.URL.Path == "/current" {
			http.Redirect(w, r, s.name, http.StatusFound)
			return
		}
		s.files++
		_, _ = w.Write(s.file)
	}))
	t.Cleanup(s.Close)
	return s
}

func newStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(ctx, filepath.Join(t.TempDir(), "ffs.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	return s
}

func inUse(t *testing.T, s *store.Store, id string, score float64) {
	t.Helper()
	require.NoError(t, s.UpsertAdvisory(ctx, model.Advisory{ID: id, EPSS: score, Observed: time.Now()}))
	_, err := s.ReplaceMatches(ctx, store.MatchScope{Source: model.SourceOSV, Digests: []string{"sha256:" + id}},
		[]model.Match{{ImageDigest: "sha256:" + id, PackageID: "p", AdvisoryID: id, Source: model.SourceOSV, FixState: model.FixFixed}})
	require.NoError(t, err)
}

type harness struct {
	feed *epss.Feed
	got  [][]string
}

func newFeed(t *testing.T, s *store.Store, srv *server) *harness {
	t.Helper()
	h := &harness{}
	h.feed = epss.New(epss.Options{
		Config: config.FeedConfig{URL: srv.URL + "/current"}, Store: s, DataDir: t.TempDir(),
		Thresholds: []float64{0.1, 0.5},
		Handler: func(_ context.Context, ids []string) error {
			h.got = append(h.got, ids)
			return nil
		},
	})
	return h
}

func score(t *testing.T, s *store.Store, id string) float64 {
	t.Helper()
	a, ok, err := s.GetAdvisory(ctx, id)
	require.NoError(t, err)
	require.True(t, ok)
	return a.EPSS
}

func TestEPSS_UpdatesOnlyInUse(t *testing.T) {
	s := newStore(t)
	inUse(t, s, "CVE-2026-0001", 0)
	inUse(t, s, "CVE-2026-0002", 0)
	require.NoError(t, s.UpsertAdvisory(ctx, model.Advisory{ID: "CVE-2026-0003", Observed: time.Now()}))
	srv := newServer(t, csvGz(t, "CVE-2026-0001,0.2,0.8", "CVE-2026-0002,0.03,0.4", "CVE-2026-0003,0.9,0.99"))
	h := newFeed(t, s, srv)
	require.Equal(t, feeds.NameEPSS, h.feed.Name())

	require.NoError(t, h.feed.Sync(ctx))
	a, _, _ := s.GetAdvisory(ctx, "CVE-2026-0001")
	require.Equal(t, 0.2, a.EPSS)
	require.Equal(t, 0.8, a.EPSSPercentile)
	require.Equal(t, 0.03, score(t, s, "CVE-2026-0002"))
	require.Equal(t, 0.0, score(t, s, "CVE-2026-0003"))
	st, _ := s.FeedState(ctx, feeds.NameEPSS)
	require.Equal(t, "2026-11-18T12:00:28Z", st.Meta["scoreDate"])
}

func TestEPSS_ThresholdCrossingNotifies(t *testing.T) {
	s := newStore(t)
	inUse(t, s, "CVE-2026-0001", 0.05)
	inUse(t, s, "CVE-2026-0002", 0.12)
	inUse(t, s, "CVE-2026-0003", 0.45)
	inUse(t, s, "CVE-2026-0004", 0.55)
	inUse(t, s, "CVE-2026-0005", 0.0)
	h := newFeed(t, s, newServer(t, csvGz(t,
		"CVE-2026-0001,0.12,0.5", "CVE-2026-0002,0.20,0.5", "CVE-2026-0003,0.55,0.5",
		"CVE-2026-0004,0.40,0.5", "CVE-2026-0005,0.09,0.5")))

	require.NoError(t, h.feed.Sync(ctx))
	require.Equal(t, [][]string{{"CVE-2026-0001", "CVE-2026-0003", "CVE-2026-0004"}}, h.got)
	require.Equal(t, 0.2, score(t, s, "CVE-2026-0002"))
}

func TestEPSS_SameFileNoop(t *testing.T) {
	s := newStore(t)
	inUse(t, s, "CVE-2026-0001", 0)
	srv := newServer(t, csvGz(t, "CVE-2026-0001,0.2,0.8"))
	h := newFeed(t, s, srv)
	require.NoError(t, h.feed.Sync(ctx))
	require.Equal(t, 1, srv.files)

	h.got = nil
	require.NoError(t, h.feed.Sync(ctx))
	require.Equal(t, 1, srv.files)
	require.Empty(t, h.got)
}

func TestEPSS_SameFileScoresNewlyInUse(t *testing.T) {
	s := newStore(t)
	inUse(t, s, "CVE-2026-0001", 0)
	require.NoError(t, s.UpsertAdvisory(ctx, model.Advisory{ID: "CVE-2026-0002", Observed: time.Now()}))
	srv := newServer(t, csvGz(t, "CVE-2026-0001,0.2,0.8", "CVE-2026-0002,0.3,0.9"))
	h := newFeed(t, s, srv)
	require.NoError(t, h.feed.Sync(ctx))
	require.Equal(t, 0.0, score(t, s, "CVE-2026-0002"))

	inUse(t, s, "CVE-2026-0002", 0)
	require.NoError(t, h.feed.Sync(ctx))
	require.Equal(t, 1, srv.files)
	require.Equal(t, 0.3, score(t, s, "CVE-2026-0002"))
	require.Equal(t, 0.2, score(t, s, "CVE-2026-0001"))
}

// TestEPSS_NewMatchTakesCachedScore: a CVE first matched after the daily sync gets its score while
// the match is stored, before the engine queues its owners, instead of at the next daily sync, which
// could escalate the finding and alert twice. After a restart the scores come from the cached file.
func TestEPSS_NewMatchTakesCachedScore(t *testing.T) {
	s := newStore(t)
	dir := t.TempDir()
	srv := newServer(t, csvGz(t, "CVE-2024-10441,0.62000,0.98000", "CVE-2024-20000,0.15000,0.90000", "CVE-2023-0001,0.00100,0.10000"))
	feed := func() *epss.Feed {
		return epss.New(epss.Options{Config: config.FeedConfig{URL: srv.URL + "/current"}, Store: s, DataDir: dir,
			Thresholds: []float64{0.1, 0.5}, Handler: func(context.Context, []string) error { return nil }})
	}
	observer := func(f *epss.Feed) engine.Observer {
		obs, ok := any(f).(engine.Observer)
		require.True(t, ok, "the EPSS feed observes the engine")
		return obs
	}
	first := feed()
	require.NoError(t, first.Sync(ctx)) // nothing is in use yet
	eng := engine.New(engine.Options{Store: s})
	eng.AddObserver(observer(first))
	newMatch := func(e *engine.Engine, id string) {
		t.Helper()
		require.NoError(t, s.UpsertAdvisory(ctx, model.Advisory{ID: id, Observed: time.Now()}))
		d := "sha256:" + id
		require.NoError(t, e.OnMatchDelta(ctx, match.Delta{
			Scope:   store.MatchScope{Source: model.SourceGrype, Digests: []string{d}},
			Matches: []model.Match{{ImageDigest: d, PackageID: "p", AdvisoryID: id, Source: model.SourceGrype, FixState: model.FixFixed}},
		}, model.TriggerInventoryChange))
	}

	newMatch(eng, "CVE-2024-10441")
	a, _, _ := s.GetAdvisory(ctx, "CVE-2024-10441")
	require.InDelta(t, 0.62, a.EPSS, 1e-9, "set when the match is stored")
	require.InDelta(t, 0.98, a.EPSSPercentile, 1e-9)

	restarted := engine.New(engine.Options{Store: s})
	restarted.AddObserver(observer(feed()))
	newMatch(restarted, "CVE-2023-0001")
	require.InDelta(t, 0.001, score(t, s, "CVE-2023-0001"), 1e-9, "from the cached file after a restart")

	newMatch(eng, "CVE-2024-30000")
	require.Zero(t, score(t, s, "CVE-2024-30000"), "not in the file")
}
