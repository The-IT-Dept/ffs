package osv_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/feeds"
	"github.com/the-it-dept/ffs/internal/feeds/osv"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

var (
	ctx = context.Background()
	now = time.Date(2026, 11, 19, 6, 0, 0, 0, time.UTC)
)

// fakeBucket is one ecosystem directory of the fake OSV bucket.
type fakeBucket struct {
	csv     []byte
	gen     string            // x-goog-generation; "" sends none
	records map[string][]byte // served as <id>.json and inside all.zip
}

// bucketServer serves <bucket>/modified_id.csv (with Range support), <bucket>/<id>.json and
// <bucket>/all.zip. A bucket it does not know has an empty listing and an empty all.zip.
type bucketServer struct {
	*httptest.Server
	mu      sync.Mutex
	buckets map[string]*fakeBucket
	gets    map[string]int      // "<bucket>/<file>" → GETs
	ranges  map[string][]string // bucket → Range headers sent for modified_id.csv
}

func newBucketServer(t *testing.T) *bucketServer {
	t.Helper()
	s := &bucketServer{buckets: map[string]*fakeBucket{}, gets: map[string]int{}, ranges: map[string][]string{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

func (s *bucketServer) serve(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	b, file, _ := strings.Cut(path, "/")
	s.mu.Lock()
	s.gets[path]++
	fb := s.buckets[b]
	if fb == nil {
		fb = &fakeBucket{}
	}
	csv, gen := fb.csv, fb.gen
	records := maps.Clone(fb.records)
	if rg := r.Header.Get("Range"); rg != "" && file == "modified_id.csv" {
		s.ranges[b] = append(s.ranges[b], rg)
	}
	s.mu.Unlock()

	if gen != "" {
		w.Header().Set("x-goog-generation", gen)
	}
	switch file {
	case "modified_id.csv":
		http.ServeContent(w, r, file, time.Time{}, bytes.NewReader(csv)) // 416 for a Range read of an empty file
	case "all.zip":
		_, _ = w.Write(zipOf(records))
	default:
		raw, ok := records[strings.TrimSuffix(file, ".json")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(raw)
	}
}

func (s *bucketServer) set(b string, fb *fakeBucket) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buckets[b] = fb
}

func (s *bucketServer) count(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gets[path]
}

// rangesOf returns the Range headers sent for b's modified_id.csv.
func (s *bucketServer) rangesOf(b string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.ranges[b])
}

// recordGETs counts per-record GETs in bucket b.
func (s *bucketServer) recordGETs(b string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for p, c := range s.gets {
		if strings.HasPrefix(p, b+"/") && strings.HasSuffix(p, ".json") {
			n += c
		}
	}
	return n
}

// listedBuckets returns the buckets whose modified_id.csv was requested.
func (s *bucketServer) listedBuckets() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for p := range s.gets {
		if b, ok := strings.CutSuffix(p, "/modified_id.csv"); ok {
			out = append(out, b)
		}
	}
	slices.Sort(out)
	return out
}

func zipOf(records map[string][]byte) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, id := range slices.Sorted(maps.Keys(records)) {
		w, err := zw.Create(id + ".json")
		if err != nil {
			panic(err)
		}
		_, _ = w.Write(records[id])
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

type row struct {
	ts time.Time
	id string
}

func csvOf(rows ...row) []byte {
	var b bytes.Buffer
	for _, r := range rows {
		fmt.Fprintf(&b, "%s,%s\n", r.ts.UTC().Format(time.RFC3339Nano), r.id)
	}
	return b.Bytes()
}

// record returns an OSV record affecting one package in ecosystem, fixed in fixed.
func record(id, ecosystem, name, fixed string, modified time.Time) []byte {
	return fmt.Appendf(nil, `{"schema_version":"1.6.0","id":%q,"modified":%q,"published":"2026-01-02T03:04:05Z",`+
		`"aliases":["CVE-2026-%s"],"summary":"test","affected":[{"package":{"ecosystem":%q,"name":%q},`+
		`"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":%q}]}]}]}`,
		id, modified.UTC().Format(time.RFC3339Nano), id, ecosystem, name, fixed)
}

func pypi(id, fixed string, modified time.Time) []byte {
	return record(id, "PyPI", "Requests_"+id, fixed, modified)
}

// gitRecord returns a GIT-ecosystem record with one GIT range on repo.
func gitRecord(id, repo string, modified time.Time) []byte {
	return fmt.Appendf(nil, `{"id":%q,"modified":%q,"affected":[{"ranges":[{"type":"GIT","repo":%q,`+
		`"events":[{"introduced":"0"},{"fixed":"abc123"}]}],"versions":["v1.0.0"]}]}`, id, modified.UTC().Format(time.RFC3339Nano), repo)
}

// sink records handler calls and fails the first fail calls.
type sink struct {
	mu    sync.Mutex
	calls [][]osv.Changed
	fail  int
}

func (s *sink) handle(_ context.Context, recs []osv.Changed) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail > 0 {
		s.fail--
		return errors.New("handler unavailable")
	}
	s.calls = append(s.calls, slices.Clone(recs))
	return nil
}

func (s *sink) all() []osv.Changed {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []osv.Changed
	for _, c := range s.calls {
		out = append(out, c...)
	}
	return out
}

func (s *sink) keys() []string {
	var out []string
	for _, c := range s.all() {
		out = append(out, c.Ecosystem+"/"+c.ID)
	}
	slices.Sort(out)
	return out
}

type env struct {
	st      *store.Store
	srv     *bucketServer
	sink    *sink
	dataDir string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "ffs.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	return &env{st: st, srv: newBucketServer(t), sink: &sink{}, dataDir: t.TempDir()}
}

func (e *env) feed(mod ...func(*osv.Options)) *osv.Feed {
	o := osv.Options{
		Config:  config.FeedConfig{Enabled: true, URL: e.srv.URL + "/", Interval: 5 * time.Minute, StaleAfter: 2 * time.Hour},
		Store:   e.st,
		HTTP:    e.srv.Client(),
		Handler: e.sink.handle,
		DataDir: e.dataDir,
		Now:     func() time.Time { return now },
	}
	for _, m := range mod {
		m(&o)
	}
	return osv.New(o)
}

// inUse stores one package per key so EcosystemsInUse reports it.
func (e *env) inUse(t *testing.T, keys ...store.EcosystemKey) {
	t.Helper()
	var pkgs []model.Package
	for i, k := range keys {
		p := model.Package{Ecosystem: k.Ecosystem, Name: fmt.Sprintf("p%d", i), Version: "1.0"}
		if k.DistroID != "" {
			p.Distro = &model.Distro{ID: k.DistroID, VersionID: k.DistroVersion}
		}
		pkgs = append(pkgs, p)
	}
	require.NoError(t, e.st.PutSBOM(ctx, "sha256:image", nil, pkgs))
}

func (e *env) meta(t *testing.T) map[string]string {
	t.Helper()
	st, err := e.st.FeedState(ctx, feeds.NameOSV)
	require.NoError(t, err)
	return st.Meta
}

func (e *env) putMeta(t *testing.T, kv map[string]string) {
	t.Helper()
	st, err := e.st.FeedState(ctx, feeds.NameOSV)
	require.NoError(t, err)
	if st.Meta == nil {
		st.Meta = map[string]string{}
	}
	for k, v := range kv {
		st.Meta[k] = v
	}
	require.NoError(t, e.st.PutFeedState(ctx, st))
}

// cache stores raw as a cached record, as the feed would.
func (e *env) cache(t *testing.T, bucket, id string, modified time.Time, raw []byte) {
	t.Helper()
	h, err := osv.AffectedHash(raw)
	require.NoError(t, err)
	_, err = e.st.PutOSVRecord(ctx, bucket, id, modified, h, raw)
	require.NoError(t, err)
}

func (e *env) ids(t *testing.T, bucket string) []string {
	t.Helper()
	ids, err := e.st.OSVRecordIDs(ctx, bucket)
	require.NoError(t, err)
	return ids
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

var python = store.EcosystemKey{Ecosystem: "python"}

func TestOSVSync_TimestampChurnIgnored(t *testing.T) {
	e := newEnv(t)
	e.inUse(t, python)
	t0, t1 := now.Add(-time.Hour), now.Add(-10*time.Minute)
	const n = 10000
	records := make(map[string][]byte, n)
	var rows []row
	for i := range n {
		id := fmt.Sprintf("PYSEC-2026-%05d", i)
		e.cache(t, "PyPI", id, t0, pypi(id, "1.2.3", t0))
		records[id] = pypi(id, "1.2.3", t1) // identical except "modified"
		rows = append(rows, row{t1, id})
	}
	e.srv.set("PyPI", &fakeBucket{csv: csvOf(rows...), records: records})
	e.putMeta(t, map[string]string{"wm.PyPI": ts(t0), "setdiff": ts(now)})

	require.NoError(t, e.feed().Sync(ctx))
	require.Empty(t, e.sink.all())
	require.Equal(t, ts(t1), e.meta(t)["wm.PyPI"])
	trs, err := e.st.TransitionsAfter(ctx, 0, 10)
	require.NoError(t, err)
	require.Empty(t, trs)
}

func TestOSVSync_ChangedAffectedDelivered(t *testing.T) {
	e := newEnv(t)
	e.inUse(t, python)
	t0, t1 := now.Add(-time.Hour), now.Add(-10*time.Minute)
	records := map[string][]byte{}
	var rows []row
	for _, id := range []string{"PYSEC-2026-1", "PYSEC-2026-2", "PYSEC-2026-3"} {
		e.cache(t, "PyPI", id, t0, pypi(id, "1.2.3", t0))
		records[id] = pypi(id, "1.2.3", t1)
		rows = append(rows, row{t1, id})
	}
	records["PYSEC-2026-2"] = pypi("PYSEC-2026-2", "1.2.4", t1)
	e.srv.set("PyPI", &fakeBucket{csv: csvOf(rows...), records: records})
	e.putMeta(t, map[string]string{"wm.PyPI": ts(t0), "setdiff": ts(now)})

	require.NoError(t, e.feed().Sync(ctx))
	got := e.sink.all()
	require.Len(t, got, 1)
	require.Equal(t, "PyPI", got[0].Ecosystem)
	require.Equal(t, "PYSEC-2026-2", got[0].ID)
	require.JSONEq(t, string(records["PYSEC-2026-2"]), string(got[0].Raw))
	ids, err := e.st.OSVRecordIDsByName(ctx, "PyPI", []string{"requests-pysec-2026-2"})
	require.NoError(t, err)
	require.Equal(t, []string{"PYSEC-2026-2"}, ids)
}

func TestOSVSync_RangeReadsStopAtWatermark(t *testing.T) {
	e := newEnv(t)
	e.inUse(t, python)
	var rows []row
	for i := 0; ; i++ {
		rows = append(rows, row{now.Add(-time.Duration(i) * time.Second), fmt.Sprintf("PYSEC-2026-%06d", i)})
		if len(rows)%1000 == 0 && len(csvOf(rows...)) >= 1<<20 {
			break
		}
	}
	e.srv.set("PyPI", &fakeBucket{csv: csvOf(rows...)})
	e.putMeta(t, map[string]string{"wm.PyPI": ts(now.Add(-50 * time.Second)), "setdiff": ts(now)})

	require.NoError(t, e.feed().Sync(ctx))
	require.Equal(t, []string{"bytes=0-262143"}, e.srv.rangesOf("PyPI"))
	require.Equal(t, 50, e.srv.recordGETs("PyPI")) // the rows newer than the watermark, all 404 here
	require.Equal(t, ts(now), e.meta(t)["wm.PyPI"])
}

func TestOSVSync_GenerationUnchangedSkips(t *testing.T) {
	e := newEnv(t)
	e.inUse(t, python)
	t1 := now.Add(-time.Minute)
	e.srv.set("PyPI", &fakeBucket{gen: "1763531000000001", csv: csvOf(row{t1, "PYSEC-2026-1"}),
		records: map[string][]byte{"PYSEC-2026-1": pypi("PYSEC-2026-1", "1.2.3", t1)}})
	e.putMeta(t, map[string]string{"gen.PyPI": "1763531000000001", "setdiff": ts(now)})

	require.NoError(t, e.feed().Sync(ctx))
	require.Zero(t, e.srv.recordGETs("PyPI"))
	require.Empty(t, e.sink.all())

	// a new generation is read, and its generation stored, so the next unchanged poll skips again
	e.srv.set("PyPI", &fakeBucket{gen: "1763531000000002", csv: csvOf(row{t1, "PYSEC-2026-1"}),
		records: map[string][]byte{"PYSEC-2026-1": pypi("PYSEC-2026-1", "1.2.3", t1)}})
	require.NoError(t, e.feed().Sync(ctx))
	require.Equal(t, 1, e.srv.recordGETs("PyPI"))
	require.Equal(t, "1763531000000002", e.meta(t)["gen.PyPI"])
	require.NoError(t, e.feed().Sync(ctx))
	require.Equal(t, 1, e.srv.recordGETs("PyPI"))
	require.Equal(t, []string{"PyPI/PYSEC-2026-1"}, e.sink.keys())
}

func TestOSVSync_NoGenerationHeaderStillPolls(t *testing.T) {
	e := newEnv(t)
	e.inUse(t, python)
	t1, t2 := now.Add(-10*time.Minute), now.Add(-time.Minute)
	e.srv.set("PyPI", &fakeBucket{csv: csvOf(row{t1, "PYSEC-2026-1"}),
		records: map[string][]byte{"PYSEC-2026-1": pypi("PYSEC-2026-1", "1.2.3", t1)}})
	e.putMeta(t, map[string]string{"setdiff": ts(now)})
	f := e.feed()
	require.NoError(t, f.Sync(ctx))
	require.Equal(t, []string{"PyPI/PYSEC-2026-1"}, e.sink.keys())
	require.NotContains(t, e.meta(t), "gen.PyPI")

	changed := pypi("PYSEC-2026-1", "1.2.4", t2)
	e.srv.set("PyPI", &fakeBucket{csv: csvOf(row{t2, "PYSEC-2026-1"}), records: map[string][]byte{"PYSEC-2026-1": changed}})
	require.NoError(t, f.Sync(ctx))
	got := e.sink.all()
	require.Len(t, got, 2)
	require.JSONEq(t, string(changed), string(got[1].Raw))
}

func TestOSVSync_EmptyCSV(t *testing.T) {
	e := newEnv(t)
	e.inUse(t, python)
	require.NoError(t, e.feed().Sync(ctx))
	require.Empty(t, e.sink.all())
	require.Equal(t, []string{"bytes=0-262143"}, e.srv.rangesOf("PyPI")) // answered 416
	meta := e.meta(t)
	require.Equal(t, ts(now), meta["wm.Go"])
	require.Equal(t, ts(now), meta["wm.GIT"])
	require.NotEmpty(t, meta["boot.Go"])
	require.NotEmpty(t, meta["boot.GIT"])
	require.NotContains(t, meta, "wm.PyPI")
	require.Equal(t, 1, e.srv.count("Go/all.zip"))
	require.Equal(t, 1, e.srv.count("GIT/all.zip"))

	require.NoError(t, e.feed().Sync(ctx)) // bootstrapped once only
	require.Equal(t, 1, e.srv.count("Go/all.zip"))
	require.Equal(t, 1, e.srv.count("GIT/all.zip"))
}

func TestOSVSync_PollsOnlyInventoryEcosystems(t *testing.T) {
	keys := []store.EcosystemKey{{Ecosystem: "deb", DistroID: "debian", DistroVersion: "12"}, python,
		{Ecosystem: "apk", DistroID: "wolfi", DistroVersion: "20230201"}, {Ecosystem: "rpm", DistroID: "rhel", DistroVersion: "9.4"},
		{Ecosystem: "binary"}}

	e := newEnv(t)
	e.inUse(t, keys...)
	require.NoError(t, e.feed().Sync(ctx))
	require.Equal(t, []string{"Debian", "GIT", "Go", "PyPI"}, e.srv.listedBuckets())

	e = newEnv(t)
	e.inUse(t, keys...)
	require.NoError(t, e.feed(func(o *osv.Options) { o.Chainguard = true }).Sync(ctx))
	require.Equal(t, []string{"Debian", "GIT", "Go", "PyPI", "Wolfi"}, e.srv.listedBuckets())
}

func TestOSVSync_SkipsNoticeRecords(t *testing.T) {
	e := newEnv(t)
	e.inUse(t, store.EcosystemKey{Ecosystem: "deb", DistroID: "debian", DistroVersion: "12"},
		store.EcosystemKey{Ecosystem: "deb", DistroID: "ubuntu", DistroVersion: "24.04"})
	t1 := now.Add(-time.Minute)
	debian := map[string][]byte{}
	for _, id := range []string{"DEBIAN-CVE-2026-1", "DSA-1", "DLA-2"} {
		debian[id] = record(id, "Debian:12", "openssl", "3.0.15-1~deb12u1", t1)
	}
	e.srv.set("Debian", &fakeBucket{csv: csvOf(row{t1, "DEBIAN-CVE-2026-1"}, row{t1, "DSA-1"}, row{t1, "DLA-2"}, row{t1, ""}),
		records: debian})
	e.srv.set("Ubuntu", &fakeBucket{csv: csvOf(row{t1, "UBUNTU-CVE-2026-2"}, row{t1, "USN-3"}), records: map[string][]byte{
		"UBUNTU-CVE-2026-2": record("UBUNTU-CVE-2026-2", "Ubuntu:24.04:LTS", "openssl", "3.0.13-0ubuntu3.5", t1),
		"USN-3":             record("USN-3", "Ubuntu:24.04:LTS", "openssl", "3.0.13-0ubuntu3.5", t1),
	}})
	e.putMeta(t, map[string]string{"setdiff": ts(now)})

	require.NoError(t, e.feed().Sync(ctx))
	for _, p := range []string{"Debian/DSA-1.json", "Debian/DLA-2.json", "Debian/.json", "Ubuntu/USN-3.json"} {
		require.Zero(t, e.srv.count(p), p)
	}
	require.Equal(t, 1, e.srv.count("Debian/DEBIAN-CVE-2026-1.json"))
	require.Equal(t, []string{"Debian/DEBIAN-CVE-2026-1", "Ubuntu/UBUNTU-CVE-2026-2"}, e.sink.keys())
	ids, err := e.st.OSVRecordIDsByName(ctx, "Debian", []string{"openssl"})
	require.NoError(t, err)
	require.Equal(t, []string{"DEBIAN-CVE-2026-1"}, ids)
}

func TestOSVSync_BulkPathAboveThreshold(t *testing.T) {
	e := newEnv(t)
	e.inUse(t, python)
	t1 := now.Add(-time.Minute)
	const n = 5001
	records := make(map[string][]byte, n)
	var rows []row
	for i := range n {
		id := fmt.Sprintf("GHSA-2026-%05d", i)
		records[id] = pypi(id, "2.0.0", t1)
		rows = append(rows, row{t1, id})
	}
	e.srv.set("PyPI", &fakeBucket{csv: csvOf(rows...), records: records})
	e.putMeta(t, map[string]string{"setdiff": ts(now)})

	require.NoError(t, e.feed().Sync(ctx))
	require.Equal(t, 1, e.srv.count("PyPI/all.zip"))
	require.Zero(t, e.srv.recordGETs("PyPI"))
	require.Len(t, e.sink.all(), n)
	for _, c := range e.sink.calls {
		require.LessOrEqual(t, len(c), 500)
	}
	require.Len(t, e.ids(t, "PyPI"), n)
	left, err := filepath.Glob(filepath.Join(e.dataDir, "osv", "*"))
	require.NoError(t, err)
	require.Empty(t, left)
}

func TestOSVBootstrap_GoFullGITFiltered(t *testing.T) {
	e := newEnv(t)
	tGo, tGIT := now.Add(-2*time.Minute), now.Add(-3*time.Minute)
	goRecs := map[string][]byte{
		"GO-2026-0001": record("GO-2026-0001", "Go", "stdlib", "1.22.5", tGo),
		"GO-2026-0002": record("GO-2026-0002", "Go", "github.com/containerd/containerd/v2", "2.0.1", tGo),
		"GO-2026-0003": record("GO-2026-0003", "Go", "golang.org/x/net", "0.33.0", tGo),
	}
	e.srv.set("Go", &fakeBucket{csv: csvOf(row{tGo, "GO-2026-0001"}, row{tGo.Add(-time.Hour), "GO-2026-0002"}), records: goRecs})
	gitRecs := map[string][]byte{
		"CVE-2026-1001": gitRecord("CVE-2026-1001", "https://github.com/php/php-src", tGIT),
		"CVE-2026-1002": gitRecord("CVE-2026-1002", "https://github.com/kubernetes/kubernetes.git", tGIT),
		"CVE-2026-1003": gitRecord("CVE-2026-1003", "https://github.com/example/other", tGIT),
	}
	e.srv.set("GIT", &fakeBucket{csv: csvOf(row{tGIT, "CVE-2026-1001"}), records: gitRecs})
	e.putMeta(t, map[string]string{"setdiff": ts(now)})
	repos := []string{"github.com/php/php-src", "github.com/kubernetes/kubernetes"}

	require.NoError(t, e.feed(func(o *osv.Options) { o.GitRepos = repos }).Sync(ctx))
	require.Equal(t, []string{"GO-2026-0001", "GO-2026-0002", "GO-2026-0003"}, e.ids(t, "Go"))
	require.Equal(t, []string{"CVE-2026-1001", "CVE-2026-1002"}, e.ids(t, "GIT"))
	require.Equal(t, []string{"GIT/CVE-2026-1001", "GIT/CVE-2026-1002",
		"Go/GO-2026-0001", "Go/GO-2026-0002", "Go/GO-2026-0003"}, e.sink.keys())
	meta := e.meta(t)
	require.Equal(t, ts(tGo), meta["wm.Go"])
	require.Equal(t, ts(tGIT), meta["wm.GIT"])
	require.NotEmpty(t, meta["boot.Go"])
	ids, err := e.st.OSVRecordIDsByName(ctx, "GIT", []string{"github.com/php/php-src"})
	require.NoError(t, err)
	require.Equal(t, []string{"CVE-2026-1001"}, ids)
	ids, _ = e.st.OSVRecordIDsByName(ctx, "Go", []string{"stdlib"})
	require.Equal(t, []string{"GO-2026-0001"}, ids)
	left, _ := filepath.Glob(filepath.Join(e.dataDir, "osv", "*"))
	require.Empty(t, left)

	// a later Sync polls instead of loading again
	require.NoError(t, e.feed(func(o *osv.Options) { o.GitRepos = repos }).Sync(ctx))
	require.Equal(t, 1, e.srv.count("Go/all.zip"))
	require.Equal(t, 1, e.srv.count("GIT/all.zip"))

	// a new repository reloads GIT, so its older records are not missed
	repos = append(repos, "github.com/example/other")
	require.NoError(t, e.feed(func(o *osv.Options) { o.GitRepos = repos }).Sync(ctx))
	require.Equal(t, 1, e.srv.count("Go/all.zip"))
	require.Equal(t, 2, e.srv.count("GIT/all.zip"))
	require.Equal(t, []string{"CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003"}, e.ids(t, "GIT"))
}

func TestOSVSync_PendingRedeliveredAfterHandlerError(t *testing.T) {
	e := newEnv(t)
	e.inUse(t, python)
	t0, t1 := now.Add(-time.Hour), now.Add(-time.Minute)
	e.srv.set("PyPI", &fakeBucket{csv: csvOf(row{t1, "PYSEC-2026-1"}),
		records: map[string][]byte{"PYSEC-2026-1": pypi("PYSEC-2026-1", "1.2.3", t1)}})
	e.putMeta(t, map[string]string{"wm.PyPI": ts(t0), "setdiff": ts(now)})
	e.sink.fail = 1

	err := e.feed().Sync(ctx)
	require.ErrorContains(t, err, "handler unavailable")
	meta := e.meta(t)
	require.Equal(t, ts(t0), meta["wm.PyPI"])
	require.Equal(t, "PyPI/PYSEC-2026-1", meta["pending"])
	require.Empty(t, e.sink.all())

	require.NoError(t, e.feed().Sync(ctx)) // the record is cached unchanged now, yet still delivered, once
	require.Equal(t, []string{"PyPI/PYSEC-2026-1"}, e.sink.keys())
	meta = e.meta(t)
	require.NotContains(t, meta, "pending")
	require.Equal(t, ts(t1), meta["wm.PyPI"])
}

func TestOSVSetDiff_VanishedMarkedWithdrawn(t *testing.T) {
	e := newEnv(t)
	npm := store.EcosystemKey{Ecosystem: "npm"}
	e.inUse(t, python, npm)
	t0 := now.Add(-48 * time.Hour)
	e.cache(t, "PyPI", "PYSEC-2026-1", t0, pypi("PYSEC-2026-1", "1.0.0", t0))
	e.cache(t, "PyPI", "PYSEC-2026-2", t0, pypi("PYSEC-2026-2", "1.0.0", t0))
	require.NoError(t, e.st.PutOSVRecordNames(ctx, "PyPI", "PYSEC-2026-2", []string{"requests-pysec-2026-2"}))
	both := record("GHSA-2026-0001", "npm", "left-pad", "1.3.0", t0)
	e.cache(t, "PyPI", "GHSA-2026-0001", t0, both) // left PyPI but still listed in npm
	e.cache(t, "npm", "GHSA-2026-0001", t0, both)
	e.srv.set("PyPI", &fakeBucket{csv: csvOf(row{t0, "PYSEC-2026-1"})})
	e.srv.set("npm", &fakeBucket{csv: csvOf(row{t0, "GHSA-2026-0001"})})
	e.putMeta(t, map[string]string{"wm.PyPI": ts(now), "wm.npm": ts(now), "setdiff": ts(now.Add(-8 * 24 * time.Hour))})

	require.NoError(t, e.feed().Sync(ctx))
	got := e.sink.all()
	require.Len(t, got, 2)
	byID := map[string]osv.Changed{}
	for _, c := range got {
		byID[c.ID] = c
	}

	w := byID["PYSEC-2026-2"]
	require.Equal(t, "PyPI", w.Ecosystem)
	var rec struct {
		ID        string `json:"id"`
		Withdrawn string `json:"withdrawn"`
	}
	require.NoError(t, json.Unmarshal(w.Raw, &rec))
	require.Equal(t, "PYSEC-2026-2", rec.ID)
	require.Equal(t, now.Format(time.RFC3339), rec.Withdrawn)

	moved := byID["GHSA-2026-0001"]
	require.Equal(t, "npm", moved.Ecosystem)
	require.NotContains(t, string(moved.Raw), "withdrawn")

	require.Equal(t, []string{"PYSEC-2026-1"}, e.ids(t, "PyPI"))
	require.Equal(t, []string{"GHSA-2026-0001"}, e.ids(t, "npm"))
	ids, err := e.st.OSVRecordIDsByName(ctx, "PyPI", []string{"requests-pysec-2026-2"})
	require.NoError(t, err)
	require.Empty(t, ids)
	require.Equal(t, now.Format(time.RFC3339), e.meta(t)["setdiff"])

	require.NoError(t, e.feed().Sync(ctx)) // weekly: nothing more until next week
	require.Len(t, e.sink.all(), 2)
}

func TestOSVRetention_PrunesNonAuthorityOnly(t *testing.T) {
	e := newEnv(t)
	e.inUse(t, python)
	old := now.Add(-15 * 24 * time.Hour)
	e.cache(t, "PyPI", "PYSEC-2026-1", old, pypi("PYSEC-2026-1", "1.0.0", old))
	e.cache(t, "PyPI", "PYSEC-2026-2", now.Add(-24*time.Hour), pypi("PYSEC-2026-2", "1.0.0", now))
	e.cache(t, "Go", "GO-2026-0001", old, record("GO-2026-0001", "Go", "stdlib", "1.22.5", old))
	e.cache(t, "GIT", "CVE-2026-1001", old, gitRecord("CVE-2026-1001", "https://github.com/php/php-src", old))
	e.putMeta(t, map[string]string{"setdiff": ts(now)})

	require.NoError(t, e.feed().Sync(ctx))
	require.Equal(t, []string{"PYSEC-2026-2"}, e.ids(t, "PyPI"))
	require.Equal(t, []string{"GO-2026-0001"}, e.ids(t, "Go"))
	require.Equal(t, []string{"CVE-2026-1001"}, e.ids(t, "GIT"))
}

func TestOSVRetention_KeepsRecordsWithOSVMatches(t *testing.T) {
	e := newEnv(t)
	e.inUse(t, python)
	old := now.Add(-15 * 24 * time.Hour)
	require.NoError(t, e.st.UpsertAdvisory(ctx, model.Advisory{ID: "CVE-2026-1", Aliases: []string{"PYSEC-2026-1", "GHSA-1111-2222-3333"}}))
	require.NoError(t, e.st.UpsertAdvisory(ctx, model.Advisory{ID: "CVE-2026-2", Aliases: []string{"PYSEC-2026-2"}}))
	for _, id := range []string{"PYSEC-2026-1", "GHSA-1111-2222-3333", "PYSEC-2026-2"} {
		e.cache(t, "PyPI", id, old, pypi(id, "1.0.0", old))
		require.NoError(t, e.st.PutOSVRecordNames(ctx, "PyPI", id, []string{"requests"}))
	}
	match := func(adv string, src model.MatchSource) model.Match {
		return model.Match{ImageDigest: "sha256:image", PackageID: "pkg-1", AdvisoryID: adv, Source: src,
			FixState: model.FixFixed, FixedVersions: []string{"1.0.0"}, ObservedAt: old}
	}
	_, err := e.st.ReplaceMatches(ctx, store.MatchScope{Source: model.SourceOSV, AdvisoryIDs: []string{"CVE-2026-1"}},
		[]model.Match{match("CVE-2026-1", model.SourceOSV)})
	require.NoError(t, err)
	_, err = e.st.ReplaceMatches(ctx, store.MatchScope{Source: model.SourceGrype, AdvisoryIDs: []string{"CVE-2026-2"}},
		[]model.Match{match("CVE-2026-2", model.SourceGrype)})
	require.NoError(t, err)
	e.putMeta(t, map[string]string{"setdiff": ts(now)})

	f := e.feed()
	require.NoError(t, f.Sync(ctx))
	require.Equal(t, []string{"GHSA-1111-2222-3333", "PYSEC-2026-1"}, e.ids(t, "PyPI"))
	ids, err := e.st.OSVRecordIDsByName(ctx, "PyPI", []string{"requests"})
	require.NoError(t, err)
	require.Equal(t, []string{"GHSA-1111-2222-3333", "PYSEC-2026-1"}, ids)

	_, err = e.st.ReplaceMatches(ctx, store.MatchScope{Source: model.SourceOSV, AdvisoryIDs: []string{"CVE-2026-1"}}, nil)
	require.NoError(t, err)
	require.NoError(t, f.Sync(ctx))
	require.Empty(t, e.ids(t, "PyPI"))
	ids, _ = e.st.OSVRecordIDsByName(ctx, "PyPI", []string{"requests"})
	require.Empty(t, ids)
}

func TestAffectedHash_IgnoresTimestamps(t *testing.T) {
	hash := func(raw string) string {
		t.Helper()
		h, err := osv.AffectedHash([]byte(raw))
		require.NoError(t, err)
		return h
	}
	base := hash(`{"id":"GHSA-1","modified":"2026-11-01T00:00:00Z","published":"2026-10-01T00:00:00Z","aliases":["CVE-2026-1","PYSEC-2026-1"],
		"affected":[{"package":{"ecosystem":"PyPI","name":"x"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]}]}`)
	require.Equal(t, base, hash(`{"id":"GHSA-1","modified":"2026-11-19T05:00:00.123Z","published":"2026-10-02T00:00:00Z","aliases":["PYSEC-2026-1","CVE-2026-1"],
		"affected":[{"ranges":[{"events":[{"introduced":"0"},{"fixed":"1.2.3"}],"type":"ECOSYSTEM"}],"package":{"name":"x","ecosystem":"PyPI"}}]}`))
	require.NotEqual(t, base, hash(`{"id":"GHSA-1","modified":"2026-11-01T00:00:00Z","aliases":["CVE-2026-1","PYSEC-2026-1"],
		"affected":[{"package":{"ecosystem":"PyPI","name":"x"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.2.4"}]}]}]}`))
	require.NotEqual(t, base, hash(`{"id":"GHSA-1","modified":"2026-11-01T00:00:00Z","aliases":["CVE-2026-1","PYSEC-2026-1"],"withdrawn":"2026-11-19T00:00:00Z",
		"affected":[{"package":{"ecosystem":"PyPI","name":"x"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]}]}`))
	require.NotEqual(t, base, hash(`{"id":"GHSA-1","aliases":["CVE-2026-1"],
		"affected":[{"package":{"ecosystem":"PyPI","name":"x"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]}]}`))
	_, err := osv.AffectedHash([]byte(`not json`))
	require.Error(t, err)
}
