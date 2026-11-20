package grypedb_test

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/feeds"
	"github.com/the-it-dept/ffs/internal/feeds/grypedb"
	"github.com/the-it-dept/ffs/internal/feeds/grypedb/grypedbtest"
	"github.com/the-it-dept/ffs/internal/store"
)

var (
	ctx    = context.Background()
	now    = time.Date(2026, 11, 19, 6, 0, 0, 0, time.UTC)
	built1 = time.Date(2026, 11, 18, 18, 19, 44, 0, time.UTC)
	built2 = built1.Add(24 * time.Hour)
	built3 = built2.Add(24 * time.Hour)
)

// dbServer serves latest.json and archives under /databases/v6/.
type dbServer struct {
	*httptest.Server
	mu          sync.Mutex
	listing     string
	archives    map[string][]byte
	archiveGETs atomic.Int32
}

func newDBServer(t *testing.T) *dbServer {
	t.Helper()
	s := &dbServer{archives: map[string][]byte{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/databases/v6/latest.json", func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		_, _ = w.Write([]byte(s.listing))
	})
	mux.HandleFunc("/databases/v6/{archive}", func(w http.ResponseWriter, r *http.Request) {
		s.archiveGETs.Add(1)
		s.mu.Lock()
		b, ok := s.archives[r.PathValue("archive")]
		s.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	})
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

func (s *dbServer) listingURL() string { return s.URL + "/databases/v6/latest.json" }

// serve publishes archive under path with a latest.json naming it. An empty checksum is computed
// from the archive.
func (s *dbServer) serve(built time.Time, path string, archive []byte, checksum string) {
	if checksum == "" {
		sum := sha256.Sum256(archive)
		checksum = "sha256:" + hex.EncodeToString(sum[:])
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.archives[path] = archive
	s.listing = fmt.Sprintf(`{"status":"active","schemaVersion":"v6.1.10","built":%q,"path":%q,"checksum":%q}`,
		built.Format(time.RFC3339), path, checksum)
}

// publish serves the DB directory dir as the build stamped built, under a real-style archive name.
func (s *dbServer) publish(t *testing.T, dir string, built time.Time) {
	t.Helper()
	s.serve(built, archiveName(built), dbArchive(t, dir), "")
}

func archiveName(built time.Time) string {
	return fmt.Sprintf("vulnerability-db_v6.1.10_%s_%d.tar.zst", built.Format(time.RFC3339), built.Unix())
}

type entry struct {
	name string
	body []byte
}

// tarZst builds a tar.zst holding regular files.
func tarZst(t *testing.T, entries ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf)
	require.NoError(t, err)
	tw := tar.NewWriter(zw)
	for _, e := range entries {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: e.name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(e.body))}))
		_, err := tw.Write(e.body)
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

// dbArchive packs a built DB directory the way grype's publisher does.
func dbArchive(t *testing.T, dir string) []byte {
	t.Helper()
	var entries []entry
	for _, name := range []string{"vulnerability.db", "import.json"} {
		b, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // G304: test fixture path
		if errors.Is(err, fs.ErrNotExist) && name == "import.json" {
			continue
		}
		require.NoError(t, err)
		entries = append(entries, entry{name, b})
	}
	return tarZst(t, entries...)
}

// handler records every Update and fails while failures > 0.
type handler struct {
	updates  []grypedb.Update
	failures int
}

func (h *handler) handle(_ context.Context, u grypedb.Update) error {
	h.updates = append(h.updates, u)
	if h.failures > 0 {
		h.failures--
		return errors.New("engine busy")
	}
	return nil
}

type fixture struct {
	srv     *dbServer
	st      *store.Store
	dataDir string
	h       *handler
	feed    *grypedb.Feed
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "ffs.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	fx := &fixture{srv: newDBServer(t), st: st, dataDir: t.TempDir(), h: &handler{}}
	fx.feed = grypedb.New(grypedb.Options{
		Config:  config.FeedConfig{Enabled: true, URL: fx.srv.listingURL(), Interval: time.Hour, StaleAfter: 48 * time.Hour},
		DataDir: fx.dataDir,
		Store:   st,
		HTTP:    fx.srv.Client(),
		Handler: fx.h.handle,
		Now:     func() time.Time { return now },
	})
	return fx
}

func (fx *fixture) state(t *testing.T) store.FeedState {
	t.Helper()
	st, err := fx.st.FeedState(ctx, feeds.NameGrypeDB)
	require.NoError(t, err)
	return st
}

// dbDirs returns the names of the entries under DataDir/grypedb.
func (fx *fixture) dbDirs(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(fx.dataDir, "grypedb"))
	require.NoError(t, err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestGrypeDB_FirstInstallIsFull(t *testing.T) {
	fx := newFixture(t)
	// latest.json: {"status":"active","schemaVersion":"v6.1.10","built":"2026-11-18T18:19:44Z",
	// "path":"vulnerability-db_v6.1.10_x.tar.zst","checksum":"sha256:<hex of served archive>"}
	fx.srv.serve(built1, "vulnerability-db_v6.1.10_x.tar.zst", dbArchive(t, grypedbtest.BuildDB(t, built1)), "")

	require.Equal(t, feeds.NameGrypeDB, fx.feed.Name())
	_, _, ok, err := fx.feed.Current(ctx)
	require.NoError(t, err)
	require.False(t, ok)

	require.NoError(t, fx.feed.Sync(ctx))
	require.Len(t, fx.h.updates, 1)
	u := fx.h.updates[0]
	require.True(t, u.Full)
	require.Empty(t, u.Changed)
	require.True(t, u.Built.Equal(built1), "Built %v", u.Built)
	require.FileExists(t, filepath.Join(u.Path, "vulnerability.db"))
	require.Equal(t, "2026-11-18T18:19:44Z", fx.state(t).Watermark)
	require.Empty(t, feeds.Pending(fx.state(t)))

	path, built, ok, err := fx.feed.Current(ctx)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, u.Path, path)
	require.True(t, built.Equal(built1))
	require.Equal(t, []string{"20261118T181944Z"}, fx.dbDirs(t))
}

func TestGrypeDB_DiffReportsChangedPackages(t *testing.T) {
	fx := newFixture(t)
	fx.srv.publish(t, grypedbtest.BuildDB(t, built1, "**/debian-12/cve-2022-38178.json"), built1)
	require.NoError(t, fx.feed.Sync(ctx))
	fx.srv.publish(t, grypedbtest.BuildDB(t, built2), built2)
	require.NoError(t, fx.feed.Sync(ctx))

	require.Len(t, fx.h.updates, 2)
	u := fx.h.updates[1]
	require.False(t, u.Full)
	require.True(t, u.Built.Equal(built2))
	require.Contains(t, u.Changed, grypedb.PackageKey{Ecosystem: "deb", Name: "firefox-esr"})
	require.Contains(t, u.Changed, grypedb.PackageKey{Ecosystem: "deb", Name: "thunderbird"})
	require.NotContains(t, u.Changed, grypedb.PackageKey{Ecosystem: "deb", Name: "bind9"})
}

// TestGrypeDB_DiffWhileTheMatcherHoldsTheCurrentDB: the Grype matcher keeps the current build open
// read-only, through SQLite's per-process shared cache, while the next build is diffed against it. The
// diff must not need a writable connection to that file ("attempt to write a readonly database"), and the
// copy it reads is gone afterwards.
func TestGrypeDB_DiffWhileTheMatcherHoldsTheCurrentDB(t *testing.T) {
	fx := newFixture(t)
	fx.srv.publish(t, grypedbtest.BuildDB(t, built1, "**/debian-12/cve-2022-38178.json"), built1)
	require.NoError(t, fx.feed.Sync(ctx))
	require.Len(t, fx.h.updates, 1)

	rdr, err := v6.NewReader(v6.Config{DBDirPath: fx.h.updates[0].Path}) // as internal/match/grype opens it
	require.NoError(t, err)
	t.Cleanup(func() { _ = rdr.Close() })

	fx.srv.publish(t, grypedbtest.BuildDB(t, built2), built2)
	require.NoError(t, fx.feed.Sync(ctx))
	require.Len(t, fx.h.updates, 2)
	require.False(t, fx.h.updates[1].Full)
	require.Contains(t, fx.h.updates[1].Changed, grypedb.PackageKey{Ecosystem: "deb", Name: "firefox-esr"})

	entries, err := os.ReadDir(filepath.Dir(fx.h.updates[1].Path))
	require.NoError(t, err)
	for _, e := range entries {
		require.NotEqual(t, ".diff-old", e.Name(), "the copy the diff read is removed")
	}
}

func TestGrypeDB_ChecksumMismatch(t *testing.T) {
	fx := newFixture(t)
	fx.srv.publish(t, grypedbtest.BuildDB(t, built1), built1)
	require.NoError(t, fx.feed.Sync(ctx))
	current := fx.dbDirs(t)

	other := sha256.Sum256([]byte("something else"))
	fx.srv.serve(built2, archiveName(built2), dbArchive(t, grypedbtest.BuildDB(t, built2)), "sha256:"+hex.EncodeToString(other[:]))
	err := fx.feed.Sync(ctx)
	require.ErrorIs(t, err, grypedb.ErrChecksum)
	require.Len(t, fx.h.updates, 1, "handler not called for a bad archive")
	require.Equal(t, current, fx.dbDirs(t), "only the current DB dir remains")
	require.Equal(t, built1.Format(time.RFC3339), fx.state(t).Watermark)
}

func TestGrypeDB_SameBuildIsNoop(t *testing.T) {
	fx := newFixture(t)
	fx.srv.publish(t, grypedbtest.BuildDB(t, built1), built1)
	require.NoError(t, fx.feed.Sync(ctx))
	require.Equal(t, int32(1), fx.srv.archiveGETs.Load())

	require.NoError(t, fx.feed.Sync(ctx))
	require.Equal(t, int32(1), fx.srv.archiveGETs.Load(), "no archive request for the same build")
	require.Len(t, fx.h.updates, 1)
}

func TestGrypeDB_UnsafeArchiveRejected(t *testing.T) {
	fx := newFixture(t)
	fx.srv.serve(built1, archiveName(built1), tarZst(t, entry{"../evil", []byte("x")}), "")

	err := fx.feed.Sync(ctx)
	require.ErrorIs(t, err, grypedb.ErrUnsafeArchive)
	require.Empty(t, fx.h.updates)
	root := filepath.Dir(fx.dataDir)
	require.NoError(t, filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		require.NotEqual(t, "evil", d.Name(), "extracted to %s", path)
		return nil
	}))
	require.Empty(t, fx.dbDirs(t))
}

func TestGrypeDB_HandlerErrorRetriesWithoutDownload(t *testing.T) {
	fx := newFixture(t)
	fx.h.failures = 1
	fx.srv.publish(t, grypedbtest.BuildDB(t, built1), built1)

	require.Error(t, fx.feed.Sync(ctx))
	st := fx.state(t)
	require.Empty(t, st.Watermark, "watermark unchanged by a failed handler")
	require.Equal(t, []string{built1.Format(time.RFC3339)}, feeds.Pending(st))
	require.Equal(t, int32(1), fx.srv.archiveGETs.Load())

	require.NoError(t, fx.feed.Sync(ctx))
	require.Equal(t, int32(1), fx.srv.archiveGETs.Load(), "retry reuses the extracted build")
	require.Len(t, fx.h.updates, 2)
	require.True(t, fx.h.updates[1].Built.Equal(built1))
	require.Equal(t, fx.h.updates[0].Path, fx.h.updates[1].Path)
	st = fx.state(t)
	require.Equal(t, built1.Format(time.RFC3339), st.Watermark)
	require.Empty(t, feeds.Pending(st))
}

func TestGrypeDB_KeepsCurrentAndPrevious(t *testing.T) {
	fx := newFixture(t)
	for _, b := range []time.Time{built1, built2, built3} {
		fx.srv.publish(t, grypedbtest.BuildDB(t, b), b)
		require.NoError(t, fx.feed.Sync(ctx))
	}
	require.Len(t, fx.h.updates, 3)
	require.ElementsMatch(t, []string{built2.Format("20060102T150405Z"), built3.Format("20060102T150405Z")}, fx.dbDirs(t))
}

// TestGrypeDB_NoDiffWhenFull: when the weekly full re-match is due, Changed is unused, so the diff
// (minutes and gigabytes of SQLite temp space on a production DB) is not run.
func TestGrypeDB_NoDiffWhenFull(t *testing.T) {
	fx := newFixture(t)
	clock := now
	fx.feed = grypedb.New(grypedb.Options{
		Config:  config.FeedConfig{Enabled: true, URL: fx.srv.listingURL(), Interval: time.Hour, StaleAfter: 48 * time.Hour},
		DataDir: fx.dataDir,
		Store:   fx.st,
		HTTP:    fx.srv.Client(),
		Handler: fx.h.handle,
		Now:     func() time.Time { return clock },
	})
	fx.srv.publish(t, grypedbtest.BuildDB(t, built1, "**/debian-12/cve-2022-38178.json"), built1)
	require.NoError(t, fx.feed.Sync(ctx))

	clock = clock.Add(8 * 24 * time.Hour) // the last full re-match is over 7 days old
	fx.srv.publish(t, grypedbtest.BuildDB(t, built2), built2)
	require.NoError(t, fx.feed.Sync(ctx))

	require.Len(t, fx.h.updates, 2)
	u := fx.h.updates[1]
	require.True(t, u.Full)
	require.Empty(t, u.Changed, "no diff for a full re-match")
	require.Equal(t, clock.UTC().Format(time.RFC3339), fx.state(t).Meta["lastFull"])
}
