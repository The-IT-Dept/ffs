package cvelist_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/feeds"
	"github.com/the-it-dept/ffs/internal/feeds/cvelist"
	"github.com/the-it-dept/ffs/internal/match/upstream"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

var (
	ctx      = context.Background()
	testdata = os.DirFS("testdata")
)

func fixture(t *testing.T, id string) []byte {
	t.Helper()
	raw, err := fs.ReadFile(testdata, id+".json")
	require.NoError(t, err)
	return raw
}

func parse(t *testing.T, raw []byte) cvelist.Record {
	t.Helper()
	r, err := cvelist.ParseRecord(raw)
	require.NoError(t, err)
	return r
}

// restamp returns raw with cveMetadata.dateUpdated set to updated.
func restamp(t *testing.T, raw []byte, updated string) []byte {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	m["cveMetadata"].(map[string]any)["dateUpdated"] = updated
	out, err := json.Marshal(m)
	require.NoError(t, err)
	return out
}

// record returns a minimal published CVE record.
func record(id, updated string) []byte {
	return fmt.Appendf(nil, `{"dataType":"CVE_RECORD","cveMetadata":{"cveId":%q,"state":"PUBLISHED","assignerShortName":"test",
		"datePublished":"2026-11-01T00:00:00.000Z","dateUpdated":%q},"containers":{"cna":{"title":"Test record %s"}}}`, id, updated, id)
}

type entry struct {
	name string
	body []byte
}

// deltaZip returns a delta zip of records, each named deltaCves/<id>.json, plus any extra entries.
func deltaZip(t *testing.T, records [][]byte, extra ...entry) []byte {
	t.Helper()
	var es []entry
	for _, raw := range records {
		var r struct {
			CVEMetadata struct {
				CVEID string `json:"cveId"`
			} `json:"cveMetadata"`
		}
		require.NoError(t, json.Unmarshal(raw, &r))
		es = append(es, entry{"deltaCves/" + r.CVEMetadata.CVEID + ".json", raw})
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range append(es, extra...) {
		w, err := zw.Create(e.name)
		require.NoError(t, err)
		_, err = w.Write(e.body)
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

func endOfDay(date string) string {
	return "/cve_" + date + "_at_end_of_day/" + date + "_delta_CVEs_at_end_of_day.zip"
}

func hourly(date string, h int) string {
	return fmt.Sprintf("/cve_%s_%02d00Z/%s_delta_CVEs_at_%02d00Z.zip", date, h, date, h)
}

// releaseServer serves release assets by path and 404s the rest, recording every GET.
type releaseServer struct {
	*httptest.Server
	mu     sync.Mutex
	assets map[string][]byte
	gets   []string
}

func newReleaseServer(t *testing.T, assets map[string][]byte) *releaseServer {
	t.Helper()
	s := &releaseServer{assets: assets}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.gets = append(s.gets, r.URL.Path)
		body, ok := s.assets[r.URL.Path]
		s.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *releaseServer) requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.gets)
}

func newStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "ffs.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	return st
}

func setWatermark(t *testing.T, st *store.Store, wm string) {
	t.Helper()
	require.NoError(t, st.PutFeedState(ctx, store.FeedState{Name: feeds.NameCVEList, Watermark: wm}))
}

// handed collects the IDs a feed hands off.
type handed struct {
	mu   sync.Mutex
	ids  []string
	fail error
}

func (h *handed) handle(_ context.Context, ids []string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.fail != nil {
		return h.fail
	}
	h.ids = append(h.ids, ids...)
	return nil
}

func newFeed(st *store.Store, srv *releaseServer, now string, h *handed) *cvelist.Feed {
	at, err := time.Parse(time.RFC3339, now)
	if err != nil {
		panic(err)
	}
	return cvelist.New(cvelist.Options{
		Config:  config.FeedConfig{Enabled: true, URL: srv.URL, Interval: time.Hour, StaleAfter: 6 * time.Hour},
		Store:   st,
		HTTP:    srv.Client(),
		Handler: h.handle,
		Now:     func() time.Time { return at },
	})
}

func feedState(t *testing.T, st *store.Store) store.FeedState {
	t.Helper()
	fst, err := st.FeedState(ctx, feeds.NameCVEList)
	require.NoError(t, err)
	return fst
}

func TestCVEList_ParseSeverityPreference(t *testing.T) {
	php := parse(t, fixture(t, "CVE-2024-11236"))
	require.Equal(t, "CVE-2024-11236", php.ID)
	require.Equal(t, "PUBLISHED", php.State)
	require.Equal(t, "php", php.Assigner)
	require.Equal(t, "Integer overflow in the firebird and dblib quoters causing OOB writes", php.Title)
	require.Equal(t, time.Date(2024, 11, 24, 0, 44, 54, 951e6, time.UTC), php.Published)
	require.Equal(t, time.Date(2025, 11, 3, 21, 51, 54, 520e6, time.UTC), php.Updated)
	require.Equal(t, []string{"https://github.com/php/php-src/security/advisories/GHSA-5hqh-c84r-qjcv"}, php.Links)
	require.Equal(t, model.SeverityCritical, php.Severity)
	require.InDelta(t, 9.8, php.CVSS, 1e-9)
	require.Equal(t, "php", php.SeveritySource)
	require.Len(t, php.Affected, 1)
	require.Equal(t, "PHP Group", php.Affected[0].Vendor)
	require.Equal(t, "8.3.14", php.Affected[0].Ranges.Versions[2].LessThan)

	// The CNA's CVSS 4.0 wins over CISA-ADP's 3.1.
	psf := parse(t, fixture(t, "CVE-2024-12254"))
	require.Equal(t, model.SeverityHigh, psf.Severity)
	require.InDelta(t, 8.7, psf.CVSS, 1e-9)
	require.Equal(t, "PSF", psf.SeveritySource)

	node := parse(t, fixture(t, "CVE-2024-22019"))
	require.Equal(t, model.SeverityHigh, node.Severity)
	require.InDelta(t, 7.5, node.CVSS, 1e-9)
	require.Equal(t, "hackerone", node.SeveritySource)

	adpOnly := parse(t, fixture(t, "CVE-2024-53104"))
	require.Equal(t, model.SeverityHigh, adpOnly.Severity)
	require.InDelta(t, 7.8, adpOnly.CVSS, 1e-9)
	require.Equal(t, "CISA-ADP", adpOnly.SeveritySource)

	none := parse(t, fixture(t, "CVE-2025-59909"))
	require.Equal(t, model.SeverityUnknown, none.Severity)
	require.Zero(t, none.CVSS)
	require.Empty(t, none.SeveritySource)

	// Across metric entries, 4.0 beats 3.1 beats 3.0, and an empty CVSS object is skipped.
	metrics := func(ms ...string) []byte {
		return fmt.Appendf(nil, `{"cveMetadata":{"cveId":"CVE-2026-0001","state":"PUBLISHED","assignerShortName":"cna"},
			"containers":{"cna":{"metrics":[%s]},"adp":[{"providerMetadata":{"shortName":"other"},"metrics":[{"cvssV3_1":{"baseScore":9.9,"baseSeverity":"CRITICAL"}}]}]}}`,
			strings.Join(ms, ","))
	}
	v30 := `{"cvssV3_0":{"baseScore":3.1,"baseSeverity":"LOW"}}`
	v31 := `{"cvssV3_1":{"baseScore":5.3,"baseSeverity":"MEDIUM"}}`
	v40 := `{"cvssV4_0":{"baseScore":7.0,"baseSeverity":"HIGH"}}`
	for _, tc := range []struct {
		metrics []string
		sev     model.Severity
		score   float64
	}{
		{[]string{v30, v31, v40}, model.SeverityHigh, 7.0},
		{[]string{v30, v31, `{"cvssV4_0":{}}`}, model.SeverityMedium, 5.3},
		{[]string{v30}, model.SeverityLow, 3.1},
	} {
		r := parse(t, metrics(tc.metrics...))
		require.Equal(t, tc.sev, r.Severity, tc.metrics)
		require.InDelta(t, tc.score, r.CVSS, 1e-9, tc.metrics)
		require.Equal(t, "cna", r.SeveritySource)
	}
	// Only CISA-ADP is a fallback; another ADP's CVSS is not used.
	r := parse(t, metrics())
	require.Equal(t, model.SeverityUnknown, r.Severity)
	require.Empty(t, r.SeveritySource)

	_, err := cvelist.ParseRecord([]byte(`{"cveMetadata":{}}`))
	require.Error(t, err)
}

func TestCVEList_SyncDeltaChain(t *testing.T) {
	st := newStore(t)
	setWatermark(t, st, "2026-11-18T22:00:00Z")
	srv := newReleaseServer(t, map[string][]byte{
		endOfDay("2026-11-18"): deltaZip(t, [][]byte{
			record("CVE-2026-1001", "2026-11-18T10:00:00.000Z"), // before the overlap
			record("CVE-2026-1006", "2026-11-18T21:00:00.000Z"), // at watermark − 1h
			record("CVE-2026-1002", "2026-11-18T21:05:00.000Z"), // inside the overlap
			record("CVE-2026-1003", "2026-11-18T21:57:30.000Z"), // inside the overlap
			record("CVE-2026-1004", "2026-11-18T23:10:00.000Z"),
		}),
		hourly("2026-11-19", 0): deltaZip(t, nil),
		hourly("2026-11-19", 1): deltaZip(t, [][]byte{record("CVE-2026-1005", "2026-11-19T00:40:00.000Z")}),
	})
	h := &handed{}
	f := newFeed(st, srv, "2026-11-19T01:30:00Z", h)
	require.Equal(t, feeds.NameCVEList, f.Name())
	require.Equal(t, time.Hour, f.Interval())
	require.Equal(t, 6*time.Hour, f.StaleAfter())

	require.NoError(t, f.Sync(ctx))
	require.Equal(t, []string{endOfDay("2026-11-18"), hourly("2026-11-19", 1)}, srv.requests())
	require.Equal(t, []string{"CVE-2026-1002", "CVE-2026-1003", "CVE-2026-1004", "CVE-2026-1005"}, h.ids)
	fst := feedState(t, st)
	require.Equal(t, "2026-11-19T01:00:00Z", fst.Watermark)
	require.Empty(t, feeds.Pending(fst))

	a, ok, err := st.GetAdvisory(ctx, "CVE-2026-1005")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "Test record CVE-2026-1005", a.Title)
	require.Equal(t, time.Date(2026, 11, 19, 0, 40, 0, 0, time.UTC), a.Modified)
	_, ok, err = st.GetAdvisory(ctx, "CVE-2026-1001")
	require.NoError(t, err)
	require.False(t, ok)

	// Nothing newer than the watermark is published: no download, nothing handed off.
	h.ids = nil
	require.NoError(t, newFeed(st, srv, "2026-11-19T01:50:00Z", h).Sync(ctx))
	require.Len(t, srv.requests(), 2)
	require.Empty(t, h.ids)
}

func TestCVEList_HourFallbackOn404(t *testing.T) {
	st := newStore(t)
	setWatermark(t, st, "2026-11-18T23:30:00Z")
	srv := newReleaseServer(t, map[string][]byte{
		endOfDay("2026-11-18"):  deltaZip(t, [][]byte{record("CVE-2026-2001", "2026-11-18T23:45:00.000Z")}),
		hourly("2026-11-19", 0): deltaZip(t, nil),
	})
	h := &handed{}
	require.NoError(t, newFeed(st, srv, "2026-11-19T01:10:00Z", h).Sync(ctx))
	require.Equal(t, []string{endOfDay("2026-11-18"), hourly("2026-11-19", 1), hourly("2026-11-19", 0)}, srv.requests())
	require.Equal(t, []string{"CVE-2026-2001"}, h.ids)
	require.Equal(t, "2026-11-19T00:00:00Z", feedState(t, st).Watermark)
}

func TestCVEList_EndOfDayNotOutYet(t *testing.T) {
	st := newStore(t)
	setWatermark(t, st, "2026-11-18T22:00:00Z")
	srv := newReleaseServer(t, map[string][]byte{
		hourly("2026-11-18", 23): deltaZip(t, [][]byte{record("CVE-2026-3001", "2026-11-18T22:30:00.000Z")}),
		hourly("2026-11-19", 0):  deltaZip(t, nil),
	})
	h := &handed{}
	// Shortly after midnight the end-of-day release is not out: the day's 2300Z delta is read and
	// the walk stops there, so the day's last hour is read once the release appears.
	require.NoError(t, newFeed(st, srv, "2026-11-19T00:35:00Z", h).Sync(ctx))
	require.Equal(t, []string{endOfDay("2026-11-18"), hourly("2026-11-18", 23)}, srv.requests())
	require.Equal(t, []string{"CVE-2026-3001"}, h.ids)
	require.Equal(t, "2026-11-18T23:00:00Z", feedState(t, st).Watermark)

	// A day later the gap is accepted and the walk goes on.
	srv.mu.Lock()
	srv.gets = nil
	srv.assets[endOfDay("2026-11-19")] = deltaZip(t, [][]byte{record("CVE-2026-3002", "2026-11-19T12:00:00.000Z")})
	srv.assets[hourly("2026-11-20", 1)] = deltaZip(t, [][]byte{record("CVE-2026-3003", "2026-11-20T00:20:00.000Z")})
	srv.mu.Unlock()
	h.ids = nil
	require.NoError(t, newFeed(st, srv, "2026-11-20T01:30:00Z", h).Sync(ctx))
	require.Equal(t, []string{endOfDay("2026-11-18"), endOfDay("2026-11-19"), hourly("2026-11-20", 1)}, srv.requests())
	require.Equal(t, []string{"CVE-2026-3002", "CVE-2026-3003"}, h.ids)
	require.Equal(t, "2026-11-20T01:00:00Z", feedState(t, st).Watermark)
}

func TestCVEList_StoresUpstreamRanges(t *testing.T) {
	st := newStore(t)
	setWatermark(t, st, "2026-11-19T00:00:00Z")
	stamp := "2026-11-19T00:45:00.000Z"
	ids := []string{"CVE-2024-11236", "CVE-2024-22019", "CVE-2024-12254", "CVE-2024-46981", "CVE-2024-53104"}
	var recs [][]byte
	for _, id := range ids {
		recs = append(recs, restamp(t, fixture(t, id), stamp))
	}
	srv := newReleaseServer(t, map[string][]byte{hourly("2026-11-19", 1): deltaZip(t, recs)})
	h := &handed{}
	require.NoError(t, newFeed(st, srv, "2026-11-19T01:30:00Z", h).Sync(ctx))
	slices.Sort(ids)
	require.Equal(t, ids, h.ids)

	ranges := func(key string) map[string]upstream.CNARanges {
		raw, err := st.UpstreamRanges(ctx, key)
		require.NoError(t, err)
		out := map[string]upstream.CNARanges{}
		for id, b := range raw {
			var r upstream.CNARanges
			require.NoError(t, json.Unmarshal(b, &r))
			out[id] = r
		}
		return out
	}
	php := ranges("php")
	require.Len(t, php, 1)
	require.Len(t, php["CVE-2024-11236"].Versions, 3)
	affected, fs, fixed := php["CVE-2024-11236"].Affects("8.3.13")
	require.True(t, affected)
	require.Equal(t, model.FixFixed, fs)
	require.Equal(t, []string{"8.3.14"}, fixed)

	node := ranges("node")
	require.Len(t, node["CVE-2024-22019"].Versions, 18)
	affected, _, fixed = node["CVE-2024-22019"].Affects("20.11.0")
	require.True(t, affected)
	require.Equal(t, []string{"20.11.1"}, fixed)

	require.Contains(t, ranges("python"), "CVE-2024-12254")
	redis := ranges("redis")["CVE-2024-46981"]
	affected, _, fixed = redis.Affects("7.4.1")
	require.True(t, affected)
	require.Equal(t, []string{"7.4.2"}, fixed)

	for _, e := range upstream.Map {
		require.NotContains(t, ranges(e.Key), "CVE-2024-53104", e.Key) // Linux is not in the map
	}

	a, ok, err := st.GetAdvisory(ctx, "CVE-2024-11236")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, model.SeverityCritical, a.CNASeverity)
	require.InDelta(t, 9.8, a.CNACVSS, 1e-9)
	require.Equal(t, "php", a.CNASource)
	require.False(t, a.Withdrawn)
}

func TestCVEList_RejectedMarksWithdrawn(t *testing.T) {
	st := newStore(t)
	setWatermark(t, st, "2026-11-18T12:00:00Z")
	published := record("CVE-2025-59909", "2026-11-18T13:00:00.000Z")
	srv := newReleaseServer(t, map[string][]byte{
		hourly("2026-11-18", 14): deltaZip(t, [][]byte{published}),
		endOfDay("2026-11-18"):   deltaZip(t, [][]byte{fixture(t, "CVE-2025-59909")}),
	})
	h := &handed{}
	require.NoError(t, newFeed(st, srv, "2026-11-18T14:30:00Z", h).Sync(ctx))
	a, ok, err := st.GetAdvisory(ctx, "CVE-2025-59909")
	require.NoError(t, err)
	require.True(t, ok)
	require.False(t, a.Withdrawn)

	require.NoError(t, newFeed(st, srv, "2026-11-19T00:50:00Z", h).Sync(ctx))
	a, ok, err = st.GetAdvisory(ctx, "CVE-2025-59909")
	require.NoError(t, err)
	require.True(t, ok)
	require.True(t, a.Withdrawn)
	require.Equal(t, []string{"CVE-2025-59909", "CVE-2025-59909"}, h.ids)
}

func TestCVEList_ZipEntryNamesValidated(t *testing.T) {
	st := newStore(t)
	setWatermark(t, st, "2026-11-19T00:00:00Z")
	stamp := "2026-11-19T00:30:00.000Z"
	oversized := fmt.Appendf(nil, `{"cveMetadata":{"cveId":"CVE-2026-0003","state":"PUBLISHED","dateUpdated":%q},
		"containers":{"cna":{"title":%q}}}`, stamp, strings.Repeat("x", 2<<20))
	srv := newReleaseServer(t, map[string][]byte{hourly("2026-11-19", 1): deltaZip(t,
		[][]byte{record("CVE-2026-0001", stamp)},
		entry{"../x.json", record("CVE-2026-0004", stamp)},
		entry{"deltaCves/notes.txt", record("CVE-2026-0005", stamp)},
		entry{"deltaCves/sub/CVE-2026-0006.json", record("CVE-2026-0006", stamp)},
		entry{"deltaCves/CVE-2026-0007.json", record("CVE-2026-0008", stamp)}, // the id is not the file name
		entry{"deltaCves/CVE-2026-0009.json", []byte("{not json")},
		entry{"deltaCves/CVE-2026-0003.json", oversized},
	)})
	h := &handed{}
	require.NoError(t, newFeed(st, srv, "2026-11-19T01:30:00Z", h).Sync(ctx))
	require.Equal(t, []string{"CVE-2026-0001"}, h.ids)
	for _, id := range []string{"CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005", "CVE-2026-0006", "CVE-2026-0008"} {
		_, ok, err := st.GetAdvisory(ctx, id)
		require.NoError(t, err)
		require.False(t, ok, id)
	}
}

func TestCVEList_HandlerFailureKeepsPending(t *testing.T) {
	st := newStore(t)
	setWatermark(t, st, "2026-11-19T00:00:00Z")
	srv := newReleaseServer(t, map[string][]byte{
		hourly("2026-11-19", 1): deltaZip(t, [][]byte{record("CVE-2026-4001", "2026-11-19T00:30:00.000Z")}),
	})
	h := &handed{fail: errors.New("engine busy")}
	require.Error(t, newFeed(st, srv, "2026-11-19T01:30:00Z", h).Sync(ctx))
	fst := feedState(t, st)
	require.Equal(t, []string{"CVE-2026-4001"}, feeds.Pending(fst))
	require.Equal(t, "2026-11-19T01:00:00Z", fst.Watermark)

	// The next Sync hands the pending IDs off without downloading again.
	h.fail = nil
	require.NoError(t, newFeed(st, srv, "2026-11-19T01:40:00Z", h).Sync(ctx))
	require.Equal(t, []string{"CVE-2026-4001"}, h.ids)
	require.Len(t, srv.requests(), 1)
	require.Empty(t, feeds.Pending(feedState(t, st)))
}

// TestCVEList_RejectedClearsUpstreamRanges: when a CVE with stored CNA ranges is REJECTED, or its
// record stops naming a mapped product, the stored ranges go, so the upstream matcher's ApplyCNA
// drops the matches they made.
func TestCVEList_RejectedClearsUpstreamRanges(t *testing.T) {
	st := newStore(t)
	setWatermark(t, st, "2026-11-18T00:00:00Z")
	rejected := []byte(`{"dataType":"CVE_RECORD","cveMetadata":{"cveId":"CVE-2024-11236","state":"REJECTED",
		"dateUpdated":"2026-11-18T15:00:00.000Z","dateRejected":"2026-11-18T15:00:00.000Z"},
		"containers":{"cna":{"rejectedReasons":[{"lang":"en","value":"Rejected."}]}}}`)
	srv := newReleaseServer(t, map[string][]byte{
		hourly("2026-11-18", 1): deltaZip(t, [][]byte{
			restamp(t, fixture(t, "CVE-2024-11236"), "2026-11-18T00:30:00.000Z"),
			restamp(t, fixture(t, "CVE-2024-22019"), "2026-11-18T00:30:00.000Z"),
		}),
		endOfDay("2026-11-18"): deltaZip(t, [][]byte{rejected, record("CVE-2024-22019", "2026-11-18T16:00:00.000Z")}),
	})
	h := &handed{}
	ranges := func(key string) map[string][]byte {
		raw, err := st.UpstreamRanges(ctx, key)
		require.NoError(t, err)
		return raw
	}

	require.NoError(t, st.PutSBOM(ctx, "sha256:"+strings.Repeat("a", 64), []byte("{}"), []model.Package{{
		Ecosystem: "binary", Classifier: "php-cli-binary", Name: "php-cli", Version: "8.3.13", Path: "/usr/local/bin/php"}}))
	cnaMatches := func() []model.Match {
		ds, err := upstream.New(st).ApplyCNA(ctx, []string{"CVE-2024-11236"})
		require.NoError(t, err)
		require.Len(t, ds, 1)
		return ds[0].Matches
	}

	require.NoError(t, newFeed(st, srv, "2026-11-18T01:30:00Z", h).Sync(ctx))
	require.Contains(t, ranges("php"), "CVE-2024-11236")
	require.Contains(t, ranges("node"), "CVE-2024-22019")
	require.Len(t, cnaMatches(), 1)

	require.NoError(t, newFeed(st, srv, "2026-11-19T00:50:00Z", h).Sync(ctx))
	require.NotContains(t, ranges("php"), "CVE-2024-11236", "a rejected CVE keeps no ranges")
	require.NotContains(t, ranges("node"), "CVE-2024-22019", "a product the record no longer names keeps no ranges")
	require.Empty(t, cnaMatches(), "ApplyCNA drops the rejected CVE's matches")
	a, ok, err := st.GetAdvisory(ctx, "CVE-2024-11236")
	require.NoError(t, err)
	require.True(t, ok)
	require.True(t, a.Withdrawn)
}

// TestCVEList_OverlapSkipsTakenRecords (F69): a delta is read from an hour below the watermark,
// since cvelistV5 commits a record minutes after its dateUpdated and an hourly cut can miss it. A
// record of that hour is taken again only when the stored advisory does not have its update time.
func TestCVEList_OverlapSkipsTakenRecords(t *testing.T) {
	st := newStore(t)
	setWatermark(t, st, "2026-11-19T01:00:00Z")
	stored := func(id string, modified time.Time) {
		t.Helper()
		require.NoError(t, st.UpsertAdvisory(ctx, model.Advisory{ID: id, Modified: modified, Observed: time.Now()}))
	}
	stored("CVE-2026-4001", time.Date(2026, 11, 19, 0, 30, 0, 0, time.UTC)) // this version was taken
	stored("CVE-2026-4003", time.Date(2026, 11, 19, 0, 10, 0, 0, time.UTC)) // an older version was
	srv := newReleaseServer(t, map[string][]byte{
		hourly("2026-11-19", 2): deltaZip(t, [][]byte{
			record("CVE-2026-4000", "2026-11-18T23:30:00.000Z"), // below the overlap
			record("CVE-2026-4001", "2026-11-19T00:30:00.000Z"), // in the overlap, taken already
			record("CVE-2026-4002", "2026-11-19T00:45:00.000Z"), // in the overlap, committed after the 01:00 cut
			record("CVE-2026-4003", "2026-11-19T00:50:00.000Z"), // in the overlap, newer than the stored version
			record("CVE-2026-4004", "2026-11-19T01:30:00.000Z"), // after the watermark
		}),
	})
	h := &handed{}
	require.NoError(t, newFeed(st, srv, "2026-11-19T02:20:00Z", h).Sync(ctx))
	require.Equal(t, []string{"CVE-2026-4002", "CVE-2026-4003", "CVE-2026-4004"}, h.ids)
	require.Equal(t, "2026-11-19T02:00:00Z", feedState(t, st).Watermark)
	a, _, err := st.GetAdvisory(ctx, "CVE-2026-4003")
	require.NoError(t, err)
	require.Equal(t, time.Date(2026, 11, 19, 0, 50, 0, 0, time.UTC), a.Modified)
}

// TestCVEList_OversizedDeltaSkipped (F66): a delta over the size cap is logged, counted and passed
// over, and the feed moves on past its day instead of failing every Sync there.
func TestCVEList_OversizedDeltaSkipped(t *testing.T) {
	cvelist.SetMaxZipBytes(t, 4<<10)
	st := newStore(t)
	setWatermark(t, st, "2026-11-17T22:00:00Z")
	noise := make([]byte, 16<<10) // incompressible, so the zip is over the cap
	for i := 0; i < len(noise); i += sha256.Size {
		sum := sha256.Sum256([]byte{byte(i), byte(i >> 8)})
		copy(noise[i:], sum[:])
	}
	srv := newReleaseServer(t, map[string][]byte{
		endOfDay("2026-11-17"): deltaZip(t, [][]byte{record("CVE-2026-5001", "2026-11-17T23:00:00.000Z")},
			entry{"deltaCves/padding.bin", noise}),
		endOfDay("2026-11-18"):  deltaZip(t, [][]byte{record("CVE-2026-5002", "2026-11-18T12:00:00.000Z")}),
		hourly("2026-11-19", 0): deltaZip(t, nil),
	})
	skipped := func() float64 {
		return testutil.ToFloat64(feeds.Skipped.WithLabelValues(feeds.NameCVEList, feeds.SkipTooLarge))
	}
	before := skipped()
	h := &handed{}
	require.NoError(t, newFeed(st, srv, "2026-11-19T01:30:00Z", h).Sync(ctx))
	require.Equal(t, []string{"CVE-2026-5002"}, h.ids)
	require.Equal(t, "2026-11-19T00:00:00Z", feedState(t, st).Watermark)
	require.InDelta(t, 1, skipped()-before, 1e-9)
	_, ok, err := st.GetAdvisory(ctx, "CVE-2026-5001")
	require.NoError(t, err)
	require.False(t, ok)

	// The feed has moved past the oversized day: it is not fetched again.
	n := len(srv.requests())
	require.NoError(t, newFeed(st, srv, "2026-11-19T01:50:00Z", h).Sync(ctx))
	require.NotContains(t, srv.requests()[n:], endOfDay("2026-11-17"))
	require.InDelta(t, 1, skipped()-before, 1e-9)
}
