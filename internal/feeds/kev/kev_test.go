package kev_test

import (
	"context"
	"errors"
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
	"github.com/the-it-dept/ffs/internal/feeds/kev"
	"github.com/the-it-dept/ffs/internal/match"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

var ctx = context.Background()

const etag = `"1c70eb-66091dd613278"`

func catalogue(entries ...string) string {
	s := `{"vulnerabilities":[`
	for i, e := range entries {
		if i > 0 {
			s += ","
		}
		s += `{"cveID":"` + e + `","dateAdded":"2026-11-18"}`
	}
	return s + `]}`
}

// server serves body with an ETag, answering 304 when the request carries it. It records the
// If-None-Match header of every request.
type server struct {
	*httptest.Server
	mu   sync.Mutex
	body string
	seen []string
}

func newServer(t *testing.T, body string) *server {
	t.Helper()
	s := &server{body: body}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.seen = append(s.seen, r.Header.Get("If-None-Match"))
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		_, _ = w.Write([]byte(s.body))
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

// inUse stores an advisory and a match on it.
func inUse(t *testing.T, s *store.Store, id string) {
	t.Helper()
	require.NoError(t, s.UpsertAdvisory(ctx, model.Advisory{ID: id, Observed: time.Now()}))
	_, err := s.ReplaceMatches(ctx, store.MatchScope{Source: model.SourceOSV, Digests: []string{"sha256:" + id}},
		[]model.Match{{ImageDigest: "sha256:" + id, PackageID: "p", AdvisoryID: id, Source: model.SourceOSV, FixState: model.FixFixed}})
	require.NoError(t, err)
}

type harness struct {
	feed *kev.Feed
	got  [][]string
	fail error
}

func newFeed(t *testing.T, s *store.Store, srv *server, dir string) *harness {
	t.Helper()
	h := &harness{}
	h.feed = kev.New(kev.Options{
		Config: config.FeedConfig{URL: srv.URL}, Store: s, DataDir: dir,
		Handler: func(_ context.Context, ids []string) error {
			h.got = append(h.got, ids)
			return h.fail
		},
	})
	return h
}

func TestKEV_SetsKEVAddedAndNotifies(t *testing.T) {
	s := newStore(t)
	inUse(t, s, "CVE-2024-10441")
	require.NoError(t, s.UpsertAdvisory(ctx, model.Advisory{ID: "CVE-2024-99999", Observed: time.Now()}))
	h := newFeed(t, s, newServer(t, catalogue("CVE-2024-10441", "CVE-2024-99999")), t.TempDir())
	require.Equal(t, feeds.NameKEV, h.feed.Name())

	require.NoError(t, h.feed.Sync(ctx))
	require.Equal(t, [][]string{{"CVE-2024-10441"}}, h.got)
	a, _, _ := s.GetAdvisory(ctx, "CVE-2024-10441")
	require.NotNil(t, a.KEVAdded)
	require.True(t, a.KEVAdded.Equal(time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)))
	other, _, _ := s.GetAdvisory(ctx, "CVE-2024-99999")
	require.Nil(t, other.KEVAdded)
}

func TestKEV_NotModifiedStillAppliesCatalog(t *testing.T) {
	s := newStore(t)
	inUse(t, s, "CVE-2024-10441")
	srv := newServer(t, catalogue("CVE-2024-10441", "CVE-2024-20000"))
	h := newFeed(t, s, srv, t.TempDir())
	require.NoError(t, h.feed.Sync(ctx))

	inUse(t, s, "CVE-2024-20000")
	h.got = nil
	require.NoError(t, h.feed.Sync(ctx))
	require.Equal(t, []string{"", etag}, srv.seen)
	require.Equal(t, [][]string{{"CVE-2024-20000"}}, h.got)
	a, _, _ := s.GetAdvisory(ctx, "CVE-2024-20000")
	require.NotNil(t, a.KEVAdded)
}

func TestKEV_RemovedFromCatalogClears(t *testing.T) {
	s := newStore(t)
	inUse(t, s, "CVE-2024-10441")
	d := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	require.NoError(t, s.SetAdvisoryKEV(ctx, "CVE-2024-10441", &d))
	h := newFeed(t, s, newServer(t, catalogue("CVE-2024-30000")), t.TempDir())

	require.NoError(t, h.feed.Sync(ctx))
	require.Equal(t, [][]string{{"CVE-2024-10441"}}, h.got)
	a, _, _ := s.GetAdvisory(ctx, "CVE-2024-10441")
	require.Nil(t, a.KEVAdded)
}

func TestKEV_HandlerErrorRedelivers(t *testing.T) {
	s := newStore(t)
	inUse(t, s, "CVE-2024-10441")
	h := newFeed(t, s, newServer(t, catalogue("CVE-2024-10441")), t.TempDir())
	h.fail = errors.New("boom")

	require.Error(t, h.feed.Sync(ctx))
	st, err := s.FeedState(ctx, feeds.NameKEV)
	require.NoError(t, err)
	require.Equal(t, []string{"CVE-2024-10441"}, feeds.Pending(st))

	h.fail, h.got = nil, nil
	require.NoError(t, h.feed.Sync(ctx)) // 304: nothing new, pending delivered
	require.Equal(t, [][]string{{"CVE-2024-10441"}}, h.got)
	st, _ = s.FeedState(ctx, feeds.NameKEV)
	require.Empty(t, feeds.Pending(st))
}

// TestKEV_RefusesEmptyOrShrunkCatalogue: an empty, reshaped or sharply shrunk catalogue fails the
// sync and leaves the KEV flags as they were, instead of clearing them and de-escalating findings.
func TestKEV_RefusesEmptyOrShrunkCatalogue(t *testing.T) {
	ids := make([]string, 0, 40)
	for i := range 40 {
		ids = append(ids, fmt.Sprintf("CVE-2024-%05d", 10441+i))
	}
	for name, bad := range map[string]string{
		"empty":    `{"vulnerabilities":[]}`,
		"reshaped": `{"catalogVersion":"2026.11.19","items":[{"cve":"CVE-2024-10441"}]}`,
		"renamed":  `{"vulnerabilities":[{"cve":"CVE-2024-10441","added":"2026-11-18"},{"cve":"CVE-2024-10442","added":"2026-11-18"}]}`,
		"shrunk":   catalogue(ids[:10]...),
	} {
		t.Run(name, func(t *testing.T) {
			s := newStore(t)
			inUse(t, s, ids[0])
			srv := newServer(t, catalogue(ids...))
			h := newFeed(t, s, srv, t.TempDir())
			require.NoError(t, h.feed.Sync(ctx))
			a, _, _ := s.GetAdvisory(ctx, ids[0])
			require.NotNil(t, a.KEVAdded)

			srv.mu.Lock()
			srv.body = bad
			srv.mu.Unlock()
			require.NoError(t, s.PutFeedState(ctx, func() store.FeedState { // drop the ETag so the server answers 200
				st, err := s.FeedState(ctx, feeds.NameKEV)
				require.NoError(t, err)
				delete(st.Meta, "etag")
				return st
			}()))
			h.got = nil
			require.ErrorIs(t, h.feed.Sync(ctx), feeds.ErrImplausible)
			require.Empty(t, h.got)
			a, _, _ = s.GetAdvisory(ctx, ids[0])
			require.NotNil(t, a.KEVAdded, "the flag stays")
		})
	}
}

// TestKEV_NewMatchTakesCachedKEV: a CVE first matched after the sync gets its KEV date while the
// match is stored, before the engine queues its owners, instead of at the next hourly sync, which
// would escalate the finding and alert twice (or, on a first install, after the baseline). After a
// restart the catalogue comes from the cached copy.
func TestKEV_NewMatchTakesCachedKEV(t *testing.T) {
	s := newStore(t)
	dir := t.TempDir()
	srv := newServer(t, catalogue("CVE-2024-10441", "CVE-2024-20000"))
	h := newFeed(t, s, srv, dir)
	require.NoError(t, h.feed.Sync(ctx)) // nothing is in use yet
	require.Empty(t, h.got)

	observer := func(f *kev.Feed) engine.Observer {
		obs, ok := any(f).(engine.Observer)
		require.True(t, ok, "the KEV feed observes the engine")
		return obs
	}
	eng := engine.New(engine.Options{Store: s})
	eng.AddObserver(observer(h.feed))
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
	require.NotNil(t, a.KEVAdded, "set when the match is stored")
	require.True(t, a.KEVAdded.Equal(time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)))

	restarted := engine.New(engine.Options{Store: s})
	restarted.AddObserver(observer(newFeed(t, s, srv, dir).feed))
	newMatch(restarted, "CVE-2024-20000")
	a, _, _ = s.GetAdvisory(ctx, "CVE-2024-20000")
	require.NotNil(t, a.KEVAdded, "from the cached catalogue after a restart")

	newMatch(eng, "CVE-2024-30000")
	a, _, _ = s.GetAdvisory(ctx, "CVE-2024-30000")
	require.Nil(t, a.KEVAdded, "not in the catalogue")
}
