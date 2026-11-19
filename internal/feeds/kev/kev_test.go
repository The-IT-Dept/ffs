package kev_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/feeds"
	"github.com/the-it-dept/ffs/internal/feeds/kev"
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
