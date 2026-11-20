package osv_test

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
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
	noRange bool              // all.zip ignores Range headers
	zip     []byte            // all.zip, built on first request
	// zipRecords, when set, is what all.zip holds instead of records: an export older than the
	// listing and the record files. zipGen, when set, is all.zip's x-goog-generation instead of gen.
	zipRecords map[string][]byte
	zipGen     string
}

// bucketServer serves <bucket>/modified_id.csv (with Range support), <bucket>/<id>.json and
// <bucket>/all.zip (with Range support unless noRange). A bucket it does not know has an empty
// listing and an empty all.zip.
type bucketServer struct {
	*httptest.Server
	mu       sync.Mutex
	buckets  map[string]*fakeBucket
	gets     map[string]int      // "<bucket>/<file>" → GETs
	ranges   map[string][]string // bucket → Range headers sent for modified_id.csv
	zipWhole map[string]int      // bucket → all.zip GETs without a Range header
	zipBytes map[string]int64    // bucket → all.zip body bytes sent
}

func newBucketServer(t *testing.T) *bucketServer {
	t.Helper()
	s := &bucketServer{buckets: map[string]*fakeBucket{}, gets: map[string]int{}, ranges: map[string][]string{},
		zipWhole: map[string]int{}, zipBytes: map[string]int64{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

// countingWriter counts the body bytes written.
type countingWriter struct {
	http.ResponseWriter
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.ResponseWriter.Write(p)
	c.n += int64(n)
	return n, err
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
	if file == "all.zip" && fb.zipGen != "" {
		gen = fb.zipGen
	}
	if rg := r.Header.Get("Range"); rg != "" && file == "modified_id.csv" {
		s.ranges[b] = append(s.ranges[b], rg)
	}
	var zipped []byte
	if file == "all.zip" {
		if fb.zip == nil {
			src := records
			if fb.zipRecords != nil {
				src = fb.zipRecords
			}
			fb.zip = zipOf(src)
		}
		zipped = fb.zip
		if r.Header.Get("Range") == "" || fb.noRange {
			s.zipWhole[b]++
		}
	}
	noRange := fb.noRange
	s.mu.Unlock()

	if gen != "" {
		w.Header().Set("x-goog-generation", gen)
	}
	switch file {
	case "modified_id.csv":
		http.ServeContent(w, r, file, time.Time{}, bytes.NewReader(csv)) // 416 for a Range read of an empty file
	case "all.zip":
		cw := &countingWriter{ResponseWriter: w}
		if noRange {
			w.Header().Set("Content-Length", fmt.Sprint(len(zipped)))
			_, _ = cw.Write(zipped)
		} else {
			http.ServeContent(cw, r, file, time.Time{}, bytes.NewReader(zipped))
		}
		s.mu.Lock()
		s.zipBytes[b] += cw.n
		s.mu.Unlock()
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

// wholeZips counts the downloads of all of b's all.zip.
func (s *bucketServer) wholeZips(b string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.zipWhole[b]
}

// zipSent returns the all.zip body bytes sent for b.
func (s *bucketServer) zipSent(b string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.zipBytes[b]
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

// sink records handler calls and fails the first fail calls, and the failAt-th call (1-based).
type sink struct {
	mu       sync.Mutex
	calls    [][]osv.Changed
	fail     int
	failAt   int
	attempts int
}

func (s *sink) handle(_ context.Context, recs []osv.Changed) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts++
	if s.fail > 0 || s.attempts == s.failAt {
		s.fail = max(s.fail-1, 0)
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

// A failed name-index write must not lose the record: the write is one transaction with the
// record's, so the next poll sees the record as changed again, hands it off and indexes it.
func TestOSVSync_IndexWriteFailureRetried(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ffs.db")
	st, err := store.Open(ctx, path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	e := &env{st: st, srv: newBucketServer(t), sink: &sink{}, dataDir: t.TempDir()}
	e.inUse(t, python)
	t0, t1 := now.Add(-time.Hour), now.Add(-10*time.Minute)
	e.cache(t, "PyPI", "PYSEC-2026-2", t0, pypi("PYSEC-2026-2", "1.2.3", t0))
	rec := pypi("PYSEC-2026-2", "1.2.4", t1)
	e.srv.set("PyPI", &fakeBucket{csv: csvOf(row{t1, "PYSEC-2026-2"}), records: map[string][]byte{"PYSEC-2026-2": rec}})
	e.putMeta(t, map[string]string{"wm.PyPI": ts(t0), "setdiff": ts(now)})

	inj, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, inj.Close()) })
	_, err = inj.ExecContext(ctx, `CREATE TRIGGER fail_index BEFORE INSERT ON osv_record_names
		BEGIN SELECT RAISE(ABORT, 'injected index failure'); END`)
	require.NoError(t, err)

	require.Error(t, e.feed().Sync(ctx))
	require.Empty(t, e.sink.all())

	_, err = inj.ExecContext(ctx, `DROP TRIGGER fail_index`)
	require.NoError(t, err)
	require.NoError(t, e.feed().Sync(ctx))
	got := e.sink.all()
	require.Len(t, got, 1)
	require.Equal(t, "PYSEC-2026-2", got[0].ID)
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
	require.Equal(t, 1, e.srv.wholeZips("PyPI"), "nearly every record changed: all of all.zip is cheapest")
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

// lastDelivered returns the raw most recently delivered for id.
func (s *sink) lastDelivered(t *testing.T, id string) osv.Changed {
	t.Helper()
	all := s.all()
	for i := len(all) - 1; i >= 0; i-- {
		if all[i].ID == id {
			return all[i]
		}
	}
	t.Fatalf("%s was never delivered", id)
	return osv.Changed{}
}

func TestOSVSync_GITRecordLeavingGitReposDropped(t *testing.T) {
	e := newEnv(t)
	const php, k8s = "github.com/php/php-src", "github.com/kubernetes/kubernetes"
	tBoot := now.Add(-time.Hour)
	recs := map[string][]byte{
		"CVE-2026-2001": gitRecord("CVE-2026-2001", "https://"+php, tBoot),
		"CVE-2026-2002": gitRecord("CVE-2026-2002", "https://"+php, tBoot),
		"CVE-2026-2003": gitRecord("CVE-2026-2003", "https://"+k8s, tBoot),
	}
	e.srv.set("GIT", &fakeBucket{csv: csvOf(row{tBoot, "CVE-2026-2001"}, row{tBoot, "CVE-2026-2002"},
		row{tBoot, "CVE-2026-2003"}), records: maps.Clone(recs)})
	e.putMeta(t, map[string]string{"setdiff": ts(now)})
	feed := e.feed(func(o *osv.Options) { o.GitRepos = []string{php, k8s} })
	phpIDs := func() []string {
		ids, err := e.st.OSVRecordIDsByName(ctx, "GIT", []string{php})
		require.NoError(t, err)
		return ids
	}

	require.NoError(t, feed.Sync(ctx))
	require.Equal(t, []string{"CVE-2026-2001", "CVE-2026-2002", "CVE-2026-2003"}, e.ids(t, "GIT"))
	require.Equal(t, []string{"CVE-2026-2001", "CVE-2026-2002"}, phpIDs())
	delivered := len(e.sink.all())

	// The mapping of CVE-2026-2001 is corrected to a repository outside GitRepos: the new raw is
	// delivered, so its php-src match goes, and the record leaves the GIT cache.
	t1 := now.Add(-10 * time.Minute)
	recs["CVE-2026-2001"] = gitRecord("CVE-2026-2001", "https://github.com/example/other", t1)
	e.srv.set("GIT", &fakeBucket{csv: csvOf(row{t1, "CVE-2026-2001"}, row{tBoot, "CVE-2026-2002"},
		row{tBoot, "CVE-2026-2003"}), records: maps.Clone(recs)})
	require.NoError(t, feed.Sync(ctx))
	got := e.sink.all()[delivered:]
	require.Len(t, got, 1)
	require.Equal(t, "GIT", got[0].Ecosystem)
	require.Equal(t, "CVE-2026-2001", got[0].ID)
	require.Contains(t, string(got[0].Raw), "github.com/example/other")
	require.NotContains(t, string(got[0].Raw), "withdrawn")
	require.Equal(t, []string{"CVE-2026-2002", "CVE-2026-2003"}, e.ids(t, "GIT"))
	require.Equal(t, []string{"CVE-2026-2002"}, phpIDs())
	require.Equal(t, ts(t1), e.meta(t)["wm.GIT"])
	delivered = len(e.sink.all())

	// The same for CVE-2026-2002 with the handler down: its php-src index entry goes at once, and the
	// redelivery from the cache completes the drop.
	t2 := now.Add(-5 * time.Minute)
	recs["CVE-2026-2002"] = gitRecord("CVE-2026-2002", "https://github.com/example/other", t2)
	e.srv.set("GIT", &fakeBucket{csv: csvOf(row{t2, "CVE-2026-2002"}, row{t1, "CVE-2026-2001"},
		row{tBoot, "CVE-2026-2003"}), records: maps.Clone(recs)})
	e.sink.fail = 1
	require.ErrorContains(t, feed.Sync(ctx), "handler unavailable")
	require.Equal(t, "GIT/CVE-2026-2002", e.meta(t)["pending"])
	require.Empty(t, phpIDs())

	require.NoError(t, feed.Sync(ctx))
	got = e.sink.all()[delivered:]
	require.Len(t, got, 1)
	require.Equal(t, "CVE-2026-2002", got[0].ID)
	require.Contains(t, string(got[0].Raw), "github.com/example/other")
	require.Equal(t, []string{"CVE-2026-2003"}, e.ids(t, "GIT"))
	meta := e.meta(t)
	require.NotContains(t, meta, "pending")
	require.Equal(t, ts(t2), meta["wm.GIT"])

	// Once dropped, it is an ordinary GIT record outside GitRepos: a later change is not taken in.
	t3 := now.Add(-time.Minute)
	recs["CVE-2026-2001"] = gitRecord("CVE-2026-2001", "https://github.com/example/third", t3)
	e.srv.set("GIT", &fakeBucket{csv: csvOf(row{t3, "CVE-2026-2001"}, row{t2, "CVE-2026-2002"},
		row{tBoot, "CVE-2026-2003"}), records: maps.Clone(recs)})
	require.NoError(t, feed.Sync(ctx))
	require.Len(t, e.sink.all(), delivered+1)
	require.Equal(t, []string{"CVE-2026-2003"}, e.ids(t, "GIT"))
	require.Equal(t, ts(t3), e.meta(t)["wm.GIT"])
}

func TestOSVBootstrap_GITReloadDropsRemovedRepos(t *testing.T) {
	e := newEnv(t)
	const php, k8s = "github.com/php/php-src", "github.com/kubernetes/kubernetes"
	tBoot := now.Add(-time.Hour)
	e.srv.set("GIT", &fakeBucket{csv: csvOf(row{tBoot, "CVE-2026-3001"}), records: map[string][]byte{
		"CVE-2026-3001": gitRecord("CVE-2026-3001", "https://"+php, tBoot),
		"CVE-2026-3002": gitRecord("CVE-2026-3002", "https://"+k8s, tBoot),
	}})
	e.putMeta(t, map[string]string{"setdiff": ts(now)})
	require.NoError(t, e.feed(func(o *osv.Options) { o.GitRepos = []string{php, k8s} }).Sync(ctx))
	require.Equal(t, []string{"CVE-2026-3001", "CVE-2026-3002"}, e.ids(t, "GIT"))
	delivered := len(e.sink.all())

	// php-src leaves GitRepos: the reload hands its record off once more and drops it.
	require.NoError(t, e.feed(func(o *osv.Options) { o.GitRepos = []string{k8s} }).Sync(ctx))
	require.Equal(t, 2, e.srv.count("GIT/all.zip"))
	var keys []string
	for _, c := range e.sink.all()[delivered:] {
		keys = append(keys, c.Ecosystem+"/"+c.ID)
	}
	slices.Sort(keys)
	require.Equal(t, []string{"GIT/CVE-2026-3001", "GIT/CVE-2026-3002"}, keys)
	require.Contains(t, string(e.sink.lastDelivered(t, "CVE-2026-3001").Raw), php)
	require.Equal(t, []string{"CVE-2026-3002"}, e.ids(t, "GIT"))
	ids, err := e.st.OSVRecordIDsByName(ctx, "GIT", []string{php})
	require.NoError(t, err)
	require.Empty(t, ids)
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
	// the record is cached and pending, so the watermark already covers it
	require.Equal(t, ts(t1), meta["wm.PyPI"])
	require.Equal(t, "PyPI/PYSEC-2026-1", meta["pending"])
	require.Empty(t, e.sink.all())
	gets := e.srv.recordGETs("PyPI")

	require.NoError(t, e.feed().Sync(ctx)) // the record is cached unchanged now, yet still delivered, once
	require.Equal(t, []string{"PyPI/PYSEC-2026-1"}, e.sink.keys())
	require.Equal(t, gets, e.srv.recordGETs("PyPI"), "a pending record is delivered from the cache")
	meta = e.meta(t)
	require.NotContains(t, meta, "pending")
	require.Equal(t, ts(t1), meta["wm.PyPI"])
}

// TestOSVSync_BacklogResumesAfterFailedChunk guards the recovery of a large backlog whose hand-off
// fails part-way, as when the sync timeout cuts it short: the chunks the handler took stay taken,
// and the next Sync delivers only the rest, from the cache, without reading the bucket again.
func TestOSVSync_BacklogResumesAfterFailedChunk(t *testing.T) {
	e := newEnv(t)
	e.inUse(t, python)
	t0, t1 := now.Add(-3*time.Hour), now.Add(-time.Minute)
	const n = 1200
	records := make(map[string][]byte, n)
	var rows []row
	for i := range n {
		id := fmt.Sprintf("GHSA-2026-%05d", i)
		records[id] = pypi(id, "2.0.0", t1)
		rows = append(rows, row{t1, id})
	}
	e.srv.set("PyPI", &fakeBucket{csv: csvOf(rows...), records: records})
	e.putMeta(t, map[string]string{"wm.PyPI": ts(t0), "setdiff": ts(now), "mal.PyPI": ts(now)})
	e.sink.failAt = 2 // the second chunk of 500 fails

	require.ErrorContains(t, e.feed().Sync(ctx), "handler unavailable")
	require.Len(t, e.sink.all(), 500)
	meta := e.meta(t)
	require.Equal(t, ts(t1), meta["wm.PyPI"], "every record is cached and pending: the backlog is not read again")
	require.Len(t, strings.Split(meta["pending"], "\n"), n-500, "the first chunk is no longer pending")
	reads := []int{e.srv.recordGETs("PyPI"), e.srv.count("PyPI/all.zip")}

	require.NoError(t, e.feed().Sync(ctx))
	require.Len(t, e.sink.all(), n, "each record is delivered once")
	require.Len(t, slices.Compact(e.sink.keys()), n)
	require.NotContains(t, e.meta(t), "pending")
	require.Equal(t, reads, []int{e.srv.recordGETs("PyPI"), e.srv.count("PyPI/all.zip")})
}

// TestOSVSync_TimeoutKeepsProgress is the sync timeout cutting a hand-off short: the handler's context
// ends part-way, and the chunks it took are still recorded as no longer pending.
func TestOSVSync_TimeoutKeepsProgress(t *testing.T) {
	e := newEnv(t)
	e.inUse(t, python)
	t0, t1 := now.Add(-3*time.Hour), now.Add(-time.Minute)
	const n = 1200
	records := make(map[string][]byte, n)
	var rows []row
	for i := range n {
		id := fmt.Sprintf("GHSA-2026-%05d", i)
		records[id] = pypi(id, "2.0.0", t1)
		rows = append(rows, row{t1, id})
	}
	e.srv.set("PyPI", &fakeBucket{csv: csvOf(rows...), records: records})
	e.putMeta(t, map[string]string{"wm.PyPI": ts(t0), "setdiff": ts(now), "mal.PyPI": ts(now)})

	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	calls := 0
	f := e.feed(func(o *osv.Options) {
		o.Handler = func(hctx context.Context, recs []osv.Changed) error {
			if calls++; calls == 3 { // the deadline passes during the third chunk
				cancel()
				return hctx.Err()
			}
			return nil
		}
	})
	require.ErrorIs(t, f.Sync(sctx), context.Canceled)
	pending := strings.Split(e.meta(t)["pending"], "\n")
	require.Len(t, pending, n-1000, "the two chunks taken before the deadline are not pending")
	require.Equal(t, "PyPI/GHSA-2026-01000", pending[0])
}

// bigPyPI is a PyPI record padded with details to about size bytes, the way Ubuntu kernel records
// run to hundreds of KB.
func bigPyPI(id string, modified time.Time, size int) []byte {
	return fmt.Appendf(nil, `{"id":%q,"modified":%q,"details":%q,"affected":[{"package":{"ecosystem":"PyPI","name":"r"},`+
		`"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0"}]}]}]}`,
		id, modified.UTC().Format(time.RFC3339Nano), strings.Repeat("x", size))
}

// requireBoundedCalls checks that every handler call holds at most 16 MiB of records, or a single
// record: the record matchers parse all of a call at once.
func requireBoundedCalls(t *testing.T, calls [][]osv.Changed) {
	t.Helper()
	for _, c := range calls {
		size := 0
		for _, r := range c {
			size += len(r.Raw)
		}
		require.True(t, len(c) == 1 || size <= 16<<20, "a handler call of %d records holds %d bytes", len(c), size)
	}
}

// TestOSVSync_LargeRecordsDeliveredInBoundedChunks guards the memory of a hand-off of large records:
// handler calls are cut by size as well as by count, both for a poll and for a redelivery whose
// bucket has no measured record size yet.
func TestOSVSync_LargeRecordsDeliveredInBoundedChunks(t *testing.T) {
	e := newEnv(t)
	e.inUse(t, python)
	t0, t1 := now.Add(-time.Hour), now.Add(-time.Minute)
	const n = 40
	records := map[string][]byte{}
	var rows []row
	for i := range n {
		id := fmt.Sprintf("PYSEC-2026-%03d", i)
		records[id] = bigPyPI(id, t1, 1<<20)
		rows = append(rows, row{t1, id})
	}
	e.srv.set("PyPI", &fakeBucket{csv: csvOf(rows...), records: records})
	e.putMeta(t, map[string]string{"wm.PyPI": ts(t0), "setdiff": ts(now), "mal.PyPI": ts(now)})

	require.NoError(t, e.feed().Sync(ctx))
	require.Len(t, e.sink.all(), n)
	require.Greater(t, len(e.sink.calls), 1)
	requireBoundedCalls(t, e.sink.calls)

	// a redelivery of the same records with no measured size: cut by the records' real size
	pending := e.sink.keys()
	e.sink.calls = nil
	st, err := e.st.FeedState(ctx, feeds.NameOSV)
	require.NoError(t, err)
	delete(st.Meta, "size.PyPI")
	feeds.SetPending(&st, pending)
	require.NoError(t, e.st.PutFeedState(ctx, st))
	require.NoError(t, e.feed().Sync(ctx))
	require.Len(t, e.sink.all(), n)
	requireBoundedCalls(t, e.sink.calls)
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

// TestOSVSetDiff_BoundsRecordReads is the regression for reading every vanished record of a bucket
// at once: a listing that drops 40 records of 1 MiB reads them 16 at a time (16 MiB at the bucket's
// measured size), yet the handler gets the same chunks as from one read of all of them.
func TestOSVSetDiff_BoundsRecordReads(t *testing.T) {
	e := newEnv(t)
	e.inUse(t, python)
	t0 := now.Add(-48 * time.Hour)
	const n = 40
	for i := range n {
		id := fmt.Sprintf("PYSEC-2026-%03d", i)
		e.cache(t, "PyPI", id, t0, bigPyPI(id, t0, 1<<20))
	}
	e.cache(t, "PyPI", "PYSEC-2026-999", t0, pypi("PYSEC-2026-999", "1.0.0", t0))
	e.srv.set("PyPI", &fakeBucket{csv: csvOf(row{t0, "PYSEC-2026-999"})})
	e.putMeta(t, map[string]string{"wm.PyPI": ts(now), "mal.PyPI": ts(now), "size.PyPI": fmt.Sprint(1 << 20),
		"setdiff": ts(now.Add(-8 * 24 * time.Hour))})
	loads := osv.WatchRecordLoads(t)

	require.NoError(t, e.feed().Sync(ctx))
	require.Equal(t, []int{16, 16, 8}, *loads)
	got := e.sink.all()
	require.Len(t, got, n)
	for i, c := range got {
		require.Equal(t, fmt.Sprintf("PYSEC-2026-%03d", i), c.ID)
		require.Contains(t, string(c.Raw), `"withdrawn"`)
	}
	// The chunks one deliver of every withdrawn record makes: at most 500 records and 16 MiB each.
	var want []int
	for rest := got; len(rest) > 0; {
		k, size := 0, 0
		for k < len(rest) && k < 500 && (k == 0 || size+len(rest[k].Raw) <= 16<<20) {
			size += len(rest[k].Raw)
			k++
		}
		want, rest = append(want, k), rest[k:]
	}
	var calls []int
	for _, c := range e.sink.calls {
		calls = append(calls, len(c))
	}
	require.Equal(t, want, calls)
	require.Equal(t, []int{15, 15, 10}, calls, "handler chunks cut across reads")
	requireBoundedCalls(t, e.sink.calls)
	require.Equal(t, []string{"PYSEC-2026-999"}, e.ids(t, "PyPI"))
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

// TestOSVSync_RangedZipReadsOnlyChangedEntries: when one GET per record looks expensive (Ubuntu's
// records average about 500 KB) and only part of the bucket changed, the changed records are read
// with Range requests from their compressed entries in all.zip: no per-record GETs and no download
// of the whole zip.
func TestOSVSync_RangedZipReadsOnlyChangedEntries(t *testing.T) {
	e := newEnv(t)
	e.inUse(t, python)
	t0, t1 := now.Add(-48*time.Hour), now.Add(-time.Minute)
	const total, changed = 2000, 100
	records := make(map[string][]byte, total)
	var rows []row
	for i := range total {
		id := fmt.Sprintf("PYSEC-2026-%05d", i)
		if i < changed {
			records[id] = pypi(id, "2.0.0", t1)
			rows = append(rows, row{t1, id})
		} else {
			records[id] = pypi(id, "1.0.0", t0)
		}
	}
	for i := changed; i < total; i++ {
		id := fmt.Sprintf("PYSEC-2026-%05d", i)
		rows = append(rows, row{t0, id})
	}
	e.srv.set("PyPI", &fakeBucket{csv: csvOf(rows...), records: records})
	e.putMeta(t, map[string]string{"wm.PyPI": ts(now.Add(-time.Hour)), "setdiff": ts(now), "mal.PyPI": ts(now)})

	require.NoError(t, e.feed().Sync(ctx))
	require.Zero(t, e.srv.recordGETs("PyPI"), "no per-record GETs")
	require.Zero(t, e.srv.wholeZips("PyPI"), "no download of all of all.zip")
	require.Less(t, e.srv.zipSent("PyPI"), int64(len(zipOf(records))/2), "only the directory and the changed entries")
	require.Len(t, e.sink.all(), changed)
	require.Len(t, e.ids(t, "PyPI"), changed)
	require.Equal(t, ts(t1), e.meta(t)["wm.PyPI"])
	require.Equal(t, fmt.Sprint(len(records["PYSEC-2026-00000"])), e.meta(t)["size.PyPI"], "the record size is measured")
}

// TestOSVSync_ZipOverCapDoesNotWedge: a burst of changes in a bucket whose all.zip is over the
// download cap (Ubuntu's is at 80% of it) is read with Range requests, or one GET per record when the
// server ignores Range, instead of failing every poll with the watermark stuck.
func TestOSVSync_ZipOverCapDoesNotWedge(t *testing.T) {
	for name, noRange := range map[string]bool{"ranged": false, "no Range support": true} {
		t.Run(name, func(t *testing.T) {
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
			e.srv.set("PyPI", &fakeBucket{csv: csvOf(rows...), records: records, noRange: noRange})
			e.putMeta(t, map[string]string{"setdiff": ts(now), "mal.PyPI": ts(now)})
			osv.SetMaxZipBytes(t, int64(len(zipOf(records))-1))

			require.NoError(t, e.feed().Sync(ctx))
			require.Zero(t, e.srv.wholeZips("PyPI")-map[bool]int{true: 1, false: 0}[noRange], "no download of the whole zip beyond the probe")
			if noRange {
				require.Equal(t, n, e.srv.recordGETs("PyPI"))
			} else {
				require.Zero(t, e.srv.recordGETs("PyPI"))
			}
			require.Len(t, e.ids(t, "PyPI"), n)
			require.Len(t, e.sink.all(), n)
			require.Equal(t, ts(t1), e.meta(t)["wm.PyPI"])
		})
	}
}

var npm = store.EcosystemKey{Ecosystem: "npm"}

func npmRecord(id, name string, modified time.Time) []byte {
	return fmt.Appendf(nil, `{"schema_version":"1.6.0","id":%q,"modified":%q,"published":"2025-09-08T13:00:00Z",`+
		`"summary":"Malicious code in %s (npm)","affected":[{"package":{"ecosystem":"npm","name":%q},"versions":["4.1.1"]}]}`,
		id, modified.UTC().Format(time.RFC3339Nano), name, name)
}

// TestOSVSync_LoadsMaliciousRecordsOnce: a language bucket's first poll only reaches back 72 hours,
// but every MAL- record it lists is loaded once, however old, and handed off: the Grype DB has none,
// and a compromised package version stays urgent. Later syncs do not load them again, and pruning
// keeps them.
func TestOSVSync_LoadsMaliciousRecordsOnce(t *testing.T) {
	e := newEnv(t)
	e.inUse(t, npm)
	old, recent := now.Add(-60*24*time.Hour), now.Add(-time.Hour)
	records := map[string][]byte{
		"MAL-2025-0001":       npmRecord("MAL-2025-0001", "debug", old),
		"MAL-2026-0002":       npmRecord("MAL-2026-0002", "chalk", recent),
		"GHSA-aaaa-bbbb-cccc": record("GHSA-aaaa-bbbb-cccc", "npm", "lodash", "4.17.21", old),
	}
	e.srv.set("npm", &fakeBucket{csv: csvOf(row{recent, "MAL-2026-0002"}, row{old, "MAL-2025-0001"}, row{old, "GHSA-aaaa-bbbb-cccc"}),
		records: records})
	e.putMeta(t, map[string]string{"setdiff": ts(now)})

	f := e.feed()
	require.NoError(t, f.Sync(ctx))
	require.Equal(t, []string{"npm/MAL-2025-0001", "npm/MAL-2026-0002"}, e.sink.keys())
	require.Equal(t, []string{"MAL-2025-0001", "MAL-2026-0002"}, e.ids(t, "npm"), "kept, though older than the retention")
	ids, err := e.st.OSVRecordIDsByName(ctx, "npm", []string{"debug"})
	require.NoError(t, err)
	require.Equal(t, []string{"MAL-2025-0001"}, ids, "indexed for newly catalogued images")
	require.Equal(t, ts(now)[:19]+"Z", e.meta(t)["mal.npm"])
	require.Equal(t, 1, e.srv.count("npm/MAL-2025-0001.json"))

	require.NoError(t, f.Sync(ctx))
	require.Equal(t, 1, e.srv.count("npm/MAL-2025-0001.json"), "loaded once")
	require.Equal(t, []string{"MAL-2025-0001", "MAL-2026-0002"}, e.ids(t, "npm"))
}

// TestOSVRetention_KeepsMaliciousRecords: pruning skips MAL- records however old.
func TestOSVRetention_KeepsMaliciousRecords(t *testing.T) {
	e := newEnv(t)
	e.inUse(t, npm)
	old := now.Add(-90 * 24 * time.Hour)
	e.cache(t, "npm", "MAL-2025-0001", old, npmRecord("MAL-2025-0001", "debug", old))
	e.cache(t, "npm", "GHSA-aaaa-bbbb-cccc", old, record("GHSA-aaaa-bbbb-cccc", "npm", "lodash", "4.17.21", old))
	e.putMeta(t, map[string]string{"setdiff": ts(now), "mal.npm": ts(now)})

	require.NoError(t, e.feed().Sync(ctx))
	require.Equal(t, []string{"MAL-2025-0001"}, e.ids(t, "npm"))
}

// laggingPyPI sets up a PyPI bucket whose all.zip is the export before the newest one, as the OSV
// exporter leaves it for a few seconds after uploading modified_id.csv: changed records were changed
// again (stale in the zip) and one record is new (absent from it). It returns the IDs the newest
// export changed. n records changed at t1, the zip holds them; total is the bucket's size.
func laggingPyPI(e *env, total, n int, gen, zipGen string) (t1, t2 time.Time, newest []string) {
	t0, t1, t2 := now.Add(-48*time.Hour), now.Add(-30*time.Minute), now.Add(-time.Minute)
	records, zipped := map[string][]byte{}, map[string][]byte{}
	var top, mid, old []row
	for i := range total {
		id := fmt.Sprintf("PYSEC-2026-%05d", i)
		switch {
		case i < 3: // changed again by the newest export: the zip has the previous version
			records[id], zipped[id] = pypi(id, "3.0.0", t2), pypi(id, "2.0.0", t1)
			top = append(top, row{t2, id})
			newest = append(newest, id)
		case i < n:
			records[id] = pypi(id, "2.0.0", t1)
			zipped[id] = records[id]
			mid = append(mid, row{t1, id})
		default:
			records[id] = pypi(id, "1.0.0", t0)
			zipped[id] = records[id]
			old = append(old, row{t0, id})
		}
	}
	const added = "PYSEC-2026-NEW00"
	records[added] = pypi(added, "3.0.0", t2)
	top = append(top, row{t2, added})
	newest = append(newest, added)
	e.srv.set("PyPI", &fakeBucket{csv: csvOf(slices.Concat(top, mid, old)...), records: records, zipRecords: zipped,
		gen: gen, zipGen: zipGen})
	slices.Sort(newest)
	return t1, t2, newest
}

// fixedIn returns the fixed version a cached PyPI record names.
func fixedIn(t *testing.T, e *env, id string) string {
	t.Helper()
	raws, err := e.st.OSVRecordsByID(ctx, []string{id})
	require.NoError(t, err)
	require.Len(t, raws, 1, id)
	var r struct {
		Affected []struct {
			Ranges []struct {
				Events []map[string]string `json:"events"`
			} `json:"ranges"`
		} `json:"affected"`
	}
	require.NoError(t, json.Unmarshal(raws[0], &r))
	return r.Affected[0].Ranges[0].Events[1]["fixed"]
}

// TestOSVSync_ZipBehindListingReadsChangesDirectly (R4): all.zip can be the previous export for a few
// seconds after modified_id.csv was uploaded, and a mirror may not say which object is newer. An
// entry older than its listing row, or a listed record absent from the zip, is read with one GET
// (record files are uploaded before the listing), so the watermark never passes a change the zip
// did not hold.
func TestOSVSync_ZipBehindListingReadsChangesDirectly(t *testing.T) {
	for name, tc := range map[string]struct {
		total, changed int
		wm             time.Duration // before now
	}{
		"ranged": {total: 2000, changed: 100, wm: time.Hour},
		"whole":  {total: 5001, changed: 5001, wm: 72 * time.Hour},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.inUse(t, python)
			_, t2, newest := laggingPyPI(e, tc.total, tc.changed, "", "")
			e.putMeta(t, map[string]string{"wm.PyPI": ts(now.Add(-tc.wm)), "setdiff": ts(now), "mal.PyPI": ts(now)})

			require.NoError(t, e.feed().Sync(ctx))
			if name == "whole" {
				require.Equal(t, 1, e.srv.wholeZips("PyPI"))
			} else {
				require.Zero(t, e.srv.wholeZips("PyPI"))
			}
			require.Equal(t, len(newest), e.srv.recordGETs("PyPI"), "only the records the zip lacks are read directly")
			for _, id := range newest {
				require.Equal(t, "3.0.0", fixedIn(t, e, id), id)
			}
			require.Contains(t, e.sink.keys(), "PyPI/PYSEC-2026-NEW00")
			require.Equal(t, ts(t2), e.meta(t)["wm.PyPI"])
		})
	}
}

// TestOSVSync_ZipOlderGenerationWaits (R4): when the bucket says all.zip is older than
// modified_id.csv (GCS generations), a poll that would read the zip waits for the next one rather
// than reading an export it knows is behind, unless the zip has stayed behind for too long.
func TestOSVSync_ZipOlderGenerationWaits(t *testing.T) {
	e := newEnv(t)
	e.inUse(t, python)
	const csvGen, oldZip, newZip = "1763600000000002", "1763600000000001", "1763600000000003"
	_, t2, newest := laggingPyPI(e, 2000, 100, csvGen, oldZip)
	wm := ts(now.Add(-time.Hour))
	e.putMeta(t, map[string]string{"wm.PyPI": wm, "setdiff": ts(now), "mal.PyPI": ts(now)})

	require.NoError(t, e.feed().Sync(ctx), "a zip behind the listing is not a failure")
	require.Empty(t, e.ids(t, "PyPI"))
	require.Empty(t, e.sink.all())
	require.Zero(t, e.srv.recordGETs("PyPI"))
	require.Equal(t, wm, e.meta(t)["wm.PyPI"], "the watermark stays")
	require.Empty(t, e.meta(t)["gen.PyPI"], "the listing is read again next time")

	// The next poll finds the newest export's all.zip.
	e.srv.mu.Lock()
	fb := e.srv.buckets["PyPI"]
	fb.zipRecords, fb.zip, fb.zipGen = nil, nil, newZip
	e.srv.mu.Unlock()
	require.NoError(t, e.feed().Sync(ctx))
	require.Zero(t, e.srv.recordGETs("PyPI"))
	require.Len(t, e.ids(t, "PyPI"), 101)
	for _, id := range newest {
		require.Equal(t, "3.0.0", fixedIn(t, e, id), id)
	}
	require.Equal(t, ts(t2), e.meta(t)["wm.PyPI"])
	require.Equal(t, csvGen, e.meta(t)["gen.PyPI"])
}

// TestOSVSync_ZipBehindTooLongIsReadAnyway (R4): a zip that stays behind its listing (a mirror that
// refreshes it less often) does not hold the watermark for good: past the wait the poll reads it and
// reads what it lacks directly.
func TestOSVSync_ZipBehindTooLongIsReadAnyway(t *testing.T) {
	e := newEnv(t)
	e.inUse(t, python)
	_, t2, newest := laggingPyPI(e, 2000, 100, "1763600000000002", "1763600000000001")
	e.putMeta(t, map[string]string{"wm.PyPI": ts(now.Add(-time.Hour)), "setdiff": ts(now), "mal.PyPI": ts(now)})
	clock := now
	f := e.feed(func(o *osv.Options) { o.Now = func() time.Time { return clock } })

	require.NoError(t, f.Sync(ctx))
	require.Empty(t, e.ids(t, "PyPI"))
	clock = now.Add(29 * time.Minute)
	require.NoError(t, f.Sync(ctx))
	require.Empty(t, e.ids(t, "PyPI"), "still within the wait")
	clock = now.Add(30 * time.Minute)
	require.NoError(t, f.Sync(ctx))
	require.Len(t, e.ids(t, "PyPI"), 101)
	require.Equal(t, len(newest), e.srv.recordGETs("PyPI"))
	for _, id := range newest {
		require.Equal(t, "3.0.0", fixedIn(t, e, id), id)
	}
	require.Equal(t, ts(t2), e.meta(t)["wm.PyPI"])
}

// TestOSVBootstrap_ZipBehindListing (R4): a Go or GIT load whose all.zip is older than the listing
// resumes polling from the newest record the zip held, not from the listing's newest row, so the
// records the zip lacked are read by the next poll.
func TestOSVBootstrap_ZipBehindListing(t *testing.T) {
	e := newEnv(t)
	tOld, tNew := now.Add(-2*time.Hour), now.Add(-time.Minute)
	records := map[string][]byte{
		"GO-2026-0001": record("GO-2026-0001", "Go", "stdlib", "1.22.6", tNew),
		"GO-2026-0002": record("GO-2026-0002", "Go", "golang.org/x/net", "0.33.0", tOld),
		"GO-2026-0003": record("GO-2026-0003", "Go", "golang.org/x/crypto", "0.31.0", tNew),
	}
	zipped := map[string][]byte{
		"GO-2026-0001": record("GO-2026-0001", "Go", "stdlib", "1.22.5", tOld),
		"GO-2026-0002": records["GO-2026-0002"],
	}
	e.srv.set("Go", &fakeBucket{csv: csvOf(row{tNew, "GO-2026-0001"}, row{tNew, "GO-2026-0003"}, row{tOld, "GO-2026-0002"}),
		records: records, zipRecords: zipped})
	e.putMeta(t, map[string]string{"setdiff": ts(now)})

	require.NoError(t, e.feed().Sync(ctx))
	require.Equal(t, ts(tOld), e.meta(t)["wm.Go"], "the newest record all.zip held")
	require.NoError(t, e.feed().Sync(ctx))
	require.Equal(t, []string{"GO-2026-0001", "GO-2026-0002", "GO-2026-0003"}, e.ids(t, "Go"))
	require.Contains(t, string(e.sink.lastDelivered(t, "GO-2026-0001").Raw), `"fixed":"1.22.6"`)
	require.Equal(t, ts(tNew), e.meta(t)["wm.Go"])
}

// rated returns a PyPI GHSA record rated ghsa (database_specific.severity) with a top-level
// severity entry of type Ubuntu scored ubuntu, fixed in 1.2.3.
func rated(id, ghsa, ubuntu string, modified time.Time) []byte {
	return fmt.Appendf(nil, `{"id":%q,"modified":%q,"aliases":["CVE-2026-%s"],"severity":[{"type":"Ubuntu","score":%q}],`+
		`"database_specific":{"severity":%q},"affected":[{"package":{"ecosystem":"PyPI","name":"x-%s"},`+
		`"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.2.3"}]}]}]}`,
		id, modified.UTC().Format(time.RFC3339Nano), id, ubuntu, ghsa, id)
}

// TestAffectedHash_IncludesRatings (F64): the GHSA rating and the top-level severity (the Ubuntu
// priority, CVSS vectors) are part of the hash, so a rating-only update is a change.
func TestAffectedHash_IncludesRatings(t *testing.T) {
	hash := func(raw []byte) string {
		t.Helper()
		h, err := osv.AffectedHash(raw)
		require.NoError(t, err)
		return h
	}
	base := hash(rated("GHSA-1", "MODERATE", "medium", now))
	require.Equal(t, base, hash(rated("GHSA-1", "MODERATE", "medium", now.Add(time.Hour))), "timestamps still do not count")
	require.NotEqual(t, base, hash(rated("GHSA-1", "HIGH", "medium", now)), "GHSA rating")
	require.NotEqual(t, base, hash(rated("GHSA-1", "MODERATE", "high", now)), "Ubuntu priority")
}

// TestOSVSync_RatingOnlyChangeDelivered (F64): a record whose only change is its rating is handed
// off, so findings take the new vendor severity without waiting for the weekly full re-match.
func TestOSVSync_RatingOnlyChangeDelivered(t *testing.T) {
	e := newEnv(t)
	e.inUse(t, python)
	t0, t1 := now.Add(-time.Hour), now.Add(-10*time.Minute)
	records := map[string][]byte{}
	var rows []row
	for _, id := range []string{"GHSA-a", "GHSA-b", "GHSA-c"} {
		e.cache(t, "PyPI", id, t0, rated(id, "MODERATE", "medium", t0))
		records[id] = rated(id, "MODERATE", "medium", t1)
		rows = append(rows, row{t1, id})
	}
	records["GHSA-a"] = rated("GHSA-a", "HIGH", "medium", t1)
	records["GHSA-b"] = rated("GHSA-b", "MODERATE", "high", t1)
	e.srv.set("PyPI", &fakeBucket{csv: csvOf(rows...), records: records})
	e.putMeta(t, map[string]string{"wm.PyPI": ts(t0), "setdiff": ts(now), "hashver": osv.HashVersion})

	require.NoError(t, e.feed().Sync(ctx))
	require.Equal(t, []string{"PyPI/GHSA-a", "PyPI/GHSA-b"}, e.sink.keys())
}

// TestOSVSync_HashVersionUpgradeIsSilent (F64): records cached under the previous hash recipe are
// rehashed on the first sync, without handing anything off, so the upgrade does not re-match the
// cluster; their raw and observation times stay as they were.
func TestOSVSync_HashVersionUpgradeIsSilent(t *testing.T) {
	e := newEnv(t)
	e.inUse(t, python)
	t0, t1 := now.Add(-time.Hour), now.Add(-10*time.Minute)
	records := map[string][]byte{}
	var (
		rows []row
		ids  []string
	)
	for i := range 150 { // more than one rehash page
		id := fmt.Sprintf("GHSA-%03d", i)
		ids = append(ids, id)
		_, err := e.st.PutOSVRecordAt(ctx, "PyPI", id, t0, "v1-"+id, rated(id, "HIGH", "high", t0), t0) // an old recipe's hash
		require.NoError(t, err)
		records[id] = rated(id, "HIGH", "high", t1) // a timestamp-only change
		rows = append(rows, row{t1, id})
	}
	e.srv.set("PyPI", &fakeBucket{csv: csvOf(rows...), records: records})
	e.putMeta(t, map[string]string{"wm.PyPI": ts(t0), "setdiff": ts(now)}) // no "hashver": cached by v0.0.1
	before, err := e.st.OSVRecordsObserved(ctx, ids)
	require.NoError(t, err)

	require.NoError(t, e.feed().Sync(ctx))
	require.Empty(t, e.sink.all(), "an upgrade hands nothing off")
	require.Equal(t, osv.HashVersion, e.meta(t)["hashver"])
	after, err := e.st.OSVRecordsObserved(ctx, ids)
	require.NoError(t, err)
	require.Equal(t, before, after, "observation times are kept")
	raw := rated("GHSA-007", "HIGH", "high", t1)
	h, err := osv.AffectedHash(raw)
	require.NoError(t, err)
	changed, err := e.st.PutOSVRecord(ctx, "PyPI", "GHSA-007", t1, h, raw)
	require.NoError(t, err)
	require.False(t, changed, "the stored hash is the current recipe's")

	// a later rating change is still delivered
	records["GHSA-007"] = rated("GHSA-007", "CRITICAL", "high", now)
	rows = append([]row{{now, "GHSA-007"}}, slices.DeleteFunc(rows, func(r row) bool { return r.id == "GHSA-007" })...)
	e.srv.set("PyPI", &fakeBucket{gen: "2", csv: csvOf(rows...), records: records})
	require.NoError(t, e.feed().Sync(ctx))
	require.Equal(t, []string{"PyPI/GHSA-007"}, e.sink.keys())
}

// TestOSVSync_OverlapTakesLateListedRecords (F65): modified_id.csv can list a record after rows
// newer than it. A poll reads the hour below the watermark again and takes the rows a previous poll
// did not record, without fetching the others again. The first poll after an upgrade only records
// that hour: the polls before took it in.
func TestOSVSync_OverlapTakesLateListedRecords(t *testing.T) {
	e := newEnv(t)
	e.inUse(t, python)
	a, b, c, d := now.Add(-10*time.Minute), now.Add(-30*time.Minute), now.Add(-2*time.Minute), now.Add(-20*time.Minute)
	records := map[string][]byte{
		"PYSEC-a": pypi("PYSEC-a", "1.0", a), "PYSEC-b": pypi("PYSEC-b", "1.0", b),
		"PYSEC-c": pypi("PYSEC-c", "1.0", c), "PYSEC-d": pypi("PYSEC-d", "1.0", d),
	}
	e.putMeta(t, map[string]string{"wm.PyPI": ts(now.Add(-15 * time.Minute)), "setdiff": ts(now), "hashver": osv.HashVersion})
	f := e.feed()

	// After an upgrade: a, above the watermark, is taken; b, in the hour below it, only recorded.
	e.srv.set("PyPI", &fakeBucket{gen: "1", csv: csvOf(row{a, "PYSEC-a"}, row{b, "PYSEC-b"}), records: records})
	require.NoError(t, f.Sync(ctx))
	require.Equal(t, []string{"PyPI/PYSEC-a"}, e.sink.keys())
	require.Zero(t, e.srv.count("PyPI/PYSEC-b.json"))
	require.Equal(t, ts(a), e.meta(t)["wm.PyPI"])

	// d is listed late, older than a, which the last poll read: it is taken, and a and b are not
	// fetched again.
	e.srv.set("PyPI", &fakeBucket{gen: "2", csv: csvOf(row{c, "PYSEC-c"}, row{a, "PYSEC-a"}, row{d, "PYSEC-d"}, row{b, "PYSEC-b"}),
		records: records})
	require.NoError(t, f.Sync(ctx))
	require.Equal(t, []string{"PyPI/PYSEC-a", "PyPI/PYSEC-c", "PyPI/PYSEC-d"}, e.sink.keys())
	require.Equal(t, 1, e.srv.count("PyPI/PYSEC-a.json"))
	require.Zero(t, e.srv.count("PyPI/PYSEC-b.json"))
	require.Equal(t, ts(c), e.meta(t)["wm.PyPI"])

	// The same rows again: nothing is fetched.
	e.srv.set("PyPI", &fakeBucket{gen: "3", csv: csvOf(row{c, "PYSEC-c"}, row{a, "PYSEC-a"}, row{d, "PYSEC-d"}, row{b, "PYSEC-b"}),
		records: records})
	gets := e.srv.recordGETs("PyPI")
	require.NoError(t, f.Sync(ctx))
	require.Equal(t, gets, e.srv.recordGETs("PyPI"))
	require.Len(t, e.sink.all(), 3)
}

// TestOSVSync_MissingRecordRetried (F54): a record modified_id.csv lists but the bucket answers 404
// for is held as missing in the feed's meta and asked for again at later syncs, after the
// watermark has moved past its row, until it is found or a day has passed.
func TestOSVSync_MissingRecordRetried(t *testing.T) {
	e := newEnv(t)
	e.inUse(t, python)
	t1 := now.Add(-10 * time.Minute)
	e.putMeta(t, map[string]string{"wm.PyPI": ts(now.Add(-time.Hour)), "setdiff": ts(now), "hashver": osv.HashVersion})
	listing := csvOf(row{t1, "PYSEC-a"}, row{t1, "PYSEC-b"}, row{t1, "PYSEC-c"})
	records := map[string][]byte{"PYSEC-a": pypi("PYSEC-a", "1.0", t1)} // b and c are not uploaded yet
	e.srv.set("PyPI", &fakeBucket{gen: "1", csv: listing, records: records})
	clock := now
	f := e.feed(func(o *osv.Options) { o.Now = func() time.Time { return clock } })

	require.NoError(t, f.Sync(ctx))
	require.Equal(t, []string{"PyPI/PYSEC-a"}, e.sink.keys())
	require.Equal(t, ts(t1), e.meta(t)["wm.PyPI"], "the watermark moves past the missing rows")
	require.Equal(t, "PYSEC-b "+now.Format(time.RFC3339)+"\nPYSEC-c "+now.Format(time.RFC3339), e.meta(t)["missing.PyPI"])

	// b appears; the listing is unchanged, so only the retry reads it.
	records["PYSEC-b"] = pypi("PYSEC-b", "1.0", t1)
	e.srv.set("PyPI", &fakeBucket{gen: "1", csv: listing, records: records})
	clock = now.Add(5 * time.Minute)
	require.NoError(t, f.Sync(ctx))
	require.Equal(t, []string{"PyPI/PYSEC-a", "PyPI/PYSEC-b"}, e.sink.keys())
	require.Equal(t, "PYSEC-c "+now.Format(time.RFC3339), e.meta(t)["missing.PyPI"], "c keeps when it was first missed")
	require.Equal(t, 2, e.srv.count("PyPI/PYSEC-c.json"))

	// A day after it was first missed, c is given up on.
	clock = now.Add(missingFor)
	require.NoError(t, f.Sync(ctx))
	require.NotContains(t, e.meta(t), "missing.PyPI")
	require.Equal(t, 2, e.srv.count("PyPI/PYSEC-c.json"))
	require.Len(t, e.sink.all(), 2)
}

const missingFor = 24 * time.Hour
