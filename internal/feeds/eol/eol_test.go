package eol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/feeds"
	"github.com/the-it-dept/ffs/internal/store"
)

var ctx = context.Background()

func newStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(ctx, filepath.Join(t.TempDir(), "ffs.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	return s
}

type fixture struct {
	feed    *Feed
	st      *store.Store
	updates *atomic.Int32
	paths   chan string
	ifNone  chan string
}

func newFixture(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) *fixture {
	t.Helper()
	fx := &fixture{st: newStore(t), updates: &atomic.Int32{}, paths: make(chan string, 8), ifNone: make(chan string, 8)}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fx.paths <- r.URL.Path
		fx.ifNone <- r.Header.Get("If-None-Match")
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	cfg := config.FeedConfig{Enabled: true, URL: srv.URL + "/", Interval: time.Hour, StaleAfter: time.Hour}
	fx.feed = New(cfg, fx.st, feeds.NewHTTPClient("test"), func(context.Context) error { fx.updates.Add(1); return nil })
	return fx
}

func serveFixture(t *testing.T) func(w http.ResponseWriter, r *http.Request) {
	body, err := os.ReadFile("testdata/products-full.json")
	require.NoError(t, err)
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write(body)
	}
}

func find(cs []store.EOLCycle, product, cycle string) (store.EOLCycle, bool) {
	for _, c := range cs {
		if c.Product == product && c.Cycle == cycle {
			return c, true
		}
	}
	return store.EOLCycle{}, false
}

func day(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 0, 0, 0, 0, time.UTC) }

func TestEOLFeed_SyncStoresCycles(t *testing.T) {
	fx := newFixture(t, serveFixture(t))
	require.NoError(t, fx.feed.Sync(ctx))
	require.Equal(t, "/products/full", <-fx.paths)
	require.EqualValues(t, 1, fx.updates.Load())

	cs, err := fx.st.ListEOL(ctx)
	require.NoError(t, err)
	deb, ok := find(cs, "debian", "12")
	require.True(t, ok)
	require.Equal(t, "Bookworm", deb.Codename)
	require.Equal(t, day(2028, 6, 30), *deb.EOLDate)
	require.False(t, deb.IsEOL)
	k, ok := find(cs, "kubernetes", "1.34")
	require.True(t, ok)
	require.Equal(t, day(2026, 10, 27), *k.EOLDate)
	require.True(t, k.IsEOL)
	g, ok := find(cs, "go", "1.26")
	require.True(t, ok)
	require.Nil(t, g.EOLDate)
	n := 0
	for _, c := range cs {
		if c.Product == "kubernetes" {
			n++
			require.NotEmpty(t, c.Latest, c.Cycle)
		}
	}
	require.Positive(t, n)
}

func TestEOLFeed_NotModifiedKeepsRows(t *testing.T) {
	fx := newFixture(t, serveFixture(t))
	require.NoError(t, fx.feed.Sync(ctx))
	before, err := fx.st.ListEOL(ctx)
	require.NoError(t, err)
	<-fx.paths
	require.Empty(t, <-fx.ifNone)

	require.NoError(t, fx.feed.Sync(ctx))
	<-fx.paths
	require.Equal(t, `"v1"`, <-fx.ifNone)
	after, err := fx.st.ListEOL(ctx)
	require.NoError(t, err)
	require.Equal(t, before, after)
	require.EqualValues(t, 2, fx.updates.Load()) // onUpdate runs on a 304 too
}

func TestEOLFeed_RejectsOversizeBody(t *testing.T) {
	var big atomic.Bool
	ok := serveFixture(t)
	fx := newFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if !big.Load() {
			ok(w, r)
			return
		}
		chunk := []byte(strings.Repeat("x", 1<<20))
		for i := 0; i < 33; i++ {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	})
	require.NoError(t, fx.feed.Sync(ctx))
	before, err := fx.st.ListEOL(ctx)
	require.NoError(t, err)

	big.Store(true)
	// Drop the stored ETag so the server does not answer 304.
	require.NoError(t, fx.st.PutFeedState(ctx, store.FeedState{Name: feeds.NameEOL}))
	err = fx.feed.Sync(ctx)
	require.ErrorIs(t, err, feeds.ErrTooLarge)
	after, err := fx.st.ListEOL(ctx)
	require.NoError(t, err)
	require.Equal(t, before, after)
}

// TestEOLFeed_RefusesEmptyOrReshapedList: a 200 whose list is empty, reshaped or far shorter than
// the stored one fails the sync and keeps the stored cycles, instead of wiping them and reporting
// success.
func TestEOLFeed_RefusesEmptyOrReshapedList(t *testing.T) {
	good, err := os.ReadFile("testdata/products-full.json")
	require.NoError(t, err)
	var body atomic.Value
	body.Store(good)
	fx := newFixture(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body.Load().([]byte))
	})
	require.NoError(t, fx.feed.Sync(ctx))
	before, err := fx.st.ListEOL(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, before)

	for name, bad := range map[string]string{
		"empty result":  `{"schema_version":"1.2.1","total":0,"result":[]}`,
		"no result":     `{"schema_version":"1.3.0","data":[{"name":"go","releases":[{"name":"1.25"}]}]}`,
		"renamed names": `{"result":[{"id":"go","releases":[{"label":"1.25"},{"label":"1.24"}]}]}`,
		"shrunk":        `{"result":[{"name":"go","releases":[{"name":"1.25","isEol":false}]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			body.Store([]byte(bad))
			updates := fx.updates.Load()
			err := fx.feed.Sync(ctx)
			require.ErrorIs(t, err, feeds.ErrImplausible)
			require.Equal(t, updates, fx.updates.Load(), "the evaluator is not reloaded")
			after, err := fx.st.ListEOL(ctx)
			require.NoError(t, err)
			require.Equal(t, before, after)
		})
	}
}
