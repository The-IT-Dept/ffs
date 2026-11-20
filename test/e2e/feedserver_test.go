//go:build e2e

package e2e

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// feedServer serves fixture copies of the OSV bucket, the cvelistV5 release assets and the CISA KEV
// catalogue, in their upstream URL layouts as of 2026-11-19, so ffs's feeds (Tasks 14, 16 and 17)
// read them as they read the real ones. Any request outside those layouts fails the test.
//
// cvelistV5 deltas. The cvelist feed stops its walk at yesterday while yesterday's end-of-day delta
// is missing (inside a 24h grace), and it never re-reads an hourly delta at or before its
// watermark. So the server publishes every end-of-day delta before cveDay (yesterday when the
// server started) as an empty zip, never cveDay's, and gives each PublishCVE its own hourly delta
// of cveDay (01, 02, ...), cumulative like the real ones. Each published record is then read
// within one feed interval whatever the time of day.
type feedServer struct {
	t   *testing.T
	srv *httptest.Server

	mu      sync.Mutex
	osv     map[string]map[string][]byte // ecosystem → record ID → record
	osvCSV  map[string][]string          // ecosystem → modified_id.csv lines, newest first
	gen     int64                        // x-goog-generation of every modified_id.csv; PublishOSV bumps it
	cveDay  string                       // YYYY-MM-DD
	cves    map[int]map[string][]byte    // hourly delta of cveDay → CVE ID → record (each hour holds only its own)
	kev     []kevEntry
	kevETag int
	log     []served
	changed chan struct{} // closed and replaced on every logged request
}

type kevEntry struct {
	CVEID                      string   `json:"cveID"`
	VendorProject              string   `json:"vendorProject"`
	Product                    string   `json:"product"`
	VulnerabilityName          string   `json:"vulnerabilityName"`
	DateAdded                  string   `json:"dateAdded"`
	ShortDescription           string   `json:"shortDescription"`
	RequiredAction             string   `json:"requiredAction"`
	DueDate                    string   `json:"dueDate"`
	KnownRansomwareCampaignUse string   `json:"knownRansomwareCampaignUse"`
	Notes                      string   `json:"notes"`
	CWEs                       []string `json:"cwes"`
}

// served is one request the server answered.
type served struct {
	at     time.Time
	path   string
	status int
}

var (
	cveTag   = regexp.MustCompile(`^cve_(\d{4}-\d{2}-\d{2})_(\d{2}00Z|at_end_of_day)$`)
	osvIDRec = regexp.MustCompile(`^[A-Za-z0-9._:-]+\.json$`)
)

// startFeedServer starts the server on every interface, so kind and k3s pods reach it through the
// host address, and stops it in t.Cleanup.
func startFeedServer(t *testing.T) *feedServer {
	t.Helper()
	f := &feedServer{
		t:       t,
		osv:     map[string]map[string][]byte{},
		osvCSV:  map[string][]string{},
		gen:     1,
		cveDay:  time.Now().UTC().AddDate(0, 0, -1).Format(time.DateOnly),
		cves:    map[int]map[string][]byte{},
		kevETag: 1,
		changed: make(chan struct{}),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /osv/ecosystems.txt", func(w http.ResponseWriter, r *http.Request) {
		serve(w, r, "ecosystems.txt", []byte("Debian\nGo\nGIT\n"))
	})
	mux.HandleFunc("GET /osv/{eco}/{file}", f.serveOSV)
	mux.HandleFunc("GET /cvelist/download/{tag}/{asset}", f.serveCVE)
	mux.HandleFunc("GET /kev/known_exploited_vulnerabilities.json", f.serveKEV)
	mux.HandleFunc("/", f.unexpected)

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "0.0.0.0:0") //nolint:gosec // G102: cluster pods reach the server through the host's address
	if err != nil {
		t.Fatalf("feed server: %v", err)
	}
	f.srv = httptest.NewUnstartedServer(f.record(mux))
	_ = f.srv.Listener.Close()
	f.srv.Listener = ln
	f.srv.Start()
	t.Cleanup(f.srv.Close)
	return f
}

// BaseURL is the server's base URL as cluster pods reach it, through hostAddr.
func (f *feedServer) BaseURL(hostAddr string) string {
	_, port, _ := net.SplitHostPort(f.srv.Listener.Addr().String())
	return "http://" + net.JoinHostPort(hostAddr, port)
}

// PublishOSV adds or replaces record id in ecosystem directory ecoDir, modified at modified.
func (f *feedServer) PublishOSV(ecoDir string, id string, rec []byte, modified time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.osv[ecoDir] == nil {
		f.osv[ecoDir] = map[string][]byte{}
	}
	f.osv[ecoDir][id] = rec
	line := modified.UTC().Format(time.RFC3339Nano) + "," + id
	f.osvCSV[ecoDir] = append([]string{line}, slices.DeleteFunc(f.osvCSV[ecoDir], func(l string) bool {
		return strings.HasSuffix(l, ","+id)
	})...)
	f.gen++
}

// PublishCVE adds a CVE record in the next hourly delta of cveDay and returns that delta's path.
func (f *feedServer) PublishCVE(id string, rec []byte) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	hour := len(f.cves) + 1
	if hour > 23 {
		f.t.Errorf("feed server: no hourly delta left for %s", id)
	}
	f.cves[hour] = map[string][]byte{id: rec}
	return cveAssetPath(f.cveDay, fmt.Sprintf("%02d00Z", hour))
}

// PublishKEV adds cveID to the KEV catalogue, added on added's date, and changes its ETag.
func (f *feedServer) PublishKEV(cveID string, added time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.kev = append(f.kev, kevEntry{
		CVEID: cveID, VendorProject: "Example", Product: "example", VulnerabilityName: "ffs e2e fixture",
		DateAdded: added.UTC().Format(time.DateOnly), ShortDescription: "ffs e2e fixture",
		RequiredAction: "Apply updates per vendor instructions.", DueDate: added.UTC().AddDate(0, 0, 21).Format(time.DateOnly),
		KnownRansomwareCampaignUse: "Unknown", CWEs: []string{},
	})
	f.kevETag++
}

// WaitServed waits until a 200 for path is served after after.
func (f *feedServer) WaitServed(ctx context.Context, path string, after time.Time) error {
	seen := 0
	for {
		f.mu.Lock()
		got, changed := slices.Clone(f.log[seen:]), f.changed
		seen = len(f.log)
		f.mu.Unlock()
		for _, s := range got {
			if s.path == path && s.status == http.StatusOK && s.at.After(after) {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("feed server: %s not served after %s: %w", path, after.Format(time.RFC3339), ctx.Err())
		case <-changed:
		}
	}
}

// RequestLog renders the last n requests, oldest first.
func (f *feedServer) RequestLog(n int) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var b strings.Builder
	for _, s := range f.log[max(0, len(f.log)-n):] {
		fmt.Fprintf(&b, "%s %d %s\n", s.at.UTC().Format(time.RFC3339Nano), s.status, s.path)
	}
	return b.String()
}

// record logs every answered request.
func (f *feedServer) record(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		f.mu.Lock()
		f.log = append(f.log, served{at: time.Now(), path: r.URL.Path, status: sw.status})
		close(f.changed)
		f.changed = make(chan struct{})
		f.mu.Unlock()
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (s *statusWriter) WriteHeader(code int) {
	if !s.wrote {
		s.status, s.wrote = code, true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	s.wrote = true
	return s.ResponseWriter.Write(b)
}

func (f *feedServer) unexpected(w http.ResponseWriter, r *http.Request) {
	f.t.Errorf("feed server: unexpected request %s", r.URL)
	http.NotFound(w, r)
}

// serveOSV serves modified_id.csv, all.zip and the records of one ecosystem directory. An
// ecosystem with no records has an empty modified_id.csv and an empty all.zip.
func (f *feedServer) serveOSV(w http.ResponseWriter, r *http.Request) {
	eco, file := r.PathValue("eco"), r.PathValue("file")
	f.mu.Lock()
	recs := maps.Clone(f.osv[eco])
	lines := slices.Clone(f.osvCSV[eco])
	gen := f.gen
	f.mu.Unlock()

	switch {
	case file == "modified_id.csv":
		var body []byte
		for _, l := range lines {
			body = append(body, l+"\n"...)
		}
		w.Header().Set("x-goog-generation", strconv.FormatInt(gen, 10))
		serve(w, r, file, body)
	case file == "all.zip":
		entries := map[string][]byte{}
		for id, rec := range recs {
			entries[id+".json"] = rec
		}
		serve(w, r, file, zipOf(f.t, entries))
	case osvIDRec.MatchString(file):
		rec, ok := recs[strings.TrimSuffix(file, ".json")]
		if !ok {
			f.unexpected(w, r)
			return
		}
		serve(w, r, file, rec)
	default:
		f.unexpected(w, r)
	}
}

// serveCVE serves cvelistV5 release assets: the empty end-of-day deltas of the days before cveDay
// and the published hourly deltas of cveDay. Every other release is not out yet (404).
func (f *feedServer) serveCVE(w http.ResponseWriter, r *http.Request) {
	tag, asset := r.PathValue("tag"), r.PathValue("asset")
	m := cveTag.FindStringSubmatch(tag)
	if m == nil {
		f.unexpected(w, r)
		return
	}
	day, when := m[1], m[2]
	if want := cveAssetName(day, when); asset != want {
		f.t.Errorf("feed server: release %s has no asset %s (want %s)", tag, asset, want)
		http.NotFound(w, r)
		return
	}

	entries, ok := f.cveDelta(day, when)
	if !ok {
		http.NotFound(w, r)
		return
	}
	serve(w, r, asset, zipOf(f.t, entries))
}

// cveDelta returns the zip entries of the delta of day at when ("HH00Z" or "at_end_of_day"), and
// whether that release is out.
func (f *feedServer) cveDelta(day, when string) (map[string][]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	entries := map[string][]byte{}
	switch {
	case when == "at_end_of_day" && day < f.cveDay:
		return entries, true
	case when != "at_end_of_day" && day == f.cveDay:
		hour, _ := strconv.Atoi(when[:2])
		if f.cves[hour] == nil {
			return nil, false
		}
		for h, recs := range f.cves { // cumulative, like the real hourly deltas
			if h <= hour {
				for id, rec := range recs {
					entries["deltaCves/"+id+".json"] = rec
				}
			}
		}
		return entries, true
	}
	return nil, false
}

func (f *feedServer) serveKEV(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	vulns := slices.Clone(f.kev)
	etag := f.kevETag
	f.mu.Unlock()
	if vulns == nil {
		vulns = []kevEntry{}
	}
	released := time.Now().UTC()
	body, err := json.Marshal(map[string]any{
		"title":           "CISA Catalog of Known Exploited Vulnerabilities",
		"catalogVersion":  released.Format("2006.01.02"),
		"dateReleased":    released.Format("2006-01-02T15:04:05.000Z"),
		"count":           len(vulns),
		"vulnerabilities": vulns,
	})
	if err != nil {
		f.t.Errorf("feed server: KEV catalogue: %v", err)
	}
	w.Header().Set("ETag", fmt.Sprintf(`"kev-%d"`, etag))
	serve(w, r, "known_exploited_vulnerabilities.json", body)
}

// serve answers through http.ServeContent, so Range and conditional requests work as upstream.
func serve(w http.ResponseWriter, r *http.Request, name string, body []byte) {
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(body))
}

// cveAssetName is the asset of release cve_<day>_<when>: <day>_delta_CVEs_at_HH00Z.zip or
// <day>_delta_CVEs_at_end_of_day.zip.
func cveAssetName(day, when string) string {
	return day + "_delta_CVEs_at_" + strings.TrimPrefix(when, "at_") + ".zip"
}

func cveAssetPath(day, when string) string {
	return "/cvelist/download/cve_" + day + "_" + when + "/" + cveAssetName(day, when)
}

// zipOf returns a zip of entries in name order.
func zipOf(t *testing.T, entries map[string][]byte) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range slices.Sorted(maps.Keys(entries)) {
		w, err := zw.Create(name)
		if err == nil {
			_, err = w.Write(entries[name])
		}
		if err != nil {
			t.Errorf("feed server: zip %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Errorf("feed server: zip: %v", err)
	}
	return buf.Bytes()
}

// debianOSV returns a Debian OSV record in the shape of a real one: it names the source package of
// Debian release (major version, e.g. "12") codename and carries its CVE only in "upstream".
func debianOSV(id, cve, source, fixed, release, codename string, at time.Time) []byte {
	ts := at.UTC().Format(time.RFC3339)
	return mustJSON(map[string]any{
		"schema_version": "1.7.0",
		"id":             id,
		"published":      ts,
		"modified":       ts,
		"upstream":       []string{cve},
		"details":        "ffs e2e fixture",
		"affected": []any{map[string]any{
			"package": map[string]any{
				"name":      source,
				"ecosystem": "Debian:" + release,
				"purl":      "pkg:deb/debian/" + source + "?arch=source&distro=" + codename,
			},
			"ranges": []any{map[string]any{
				"type":   "ECOSYSTEM",
				"events": []any{map[string]any{"introduced": "0"}, map[string]any{"fixed": fixed}},
			}},
		}},
	})
}

// cnaRecord returns a CVE JSON 5.1 record in the shape of a real CNA one, affecting product
// versions from version up to lessThan.
func cnaRecord(cve, vendor, product, repo, version, lessThan string, cvss float64, severity string, at time.Time) []byte {
	ts := at.UTC().Format("2006-01-02T15:04:05.000Z")
	affected := map[string]any{
		"vendor":        vendor,
		"product":       product,
		"defaultStatus": "unaffected",
		"versions": []any{map[string]any{
			"version": version, "lessThan": lessThan, "status": "affected", "versionType": "semver",
		}},
	}
	if repo != "" {
		affected["repo"] = repo
	}
	const org = "00000000-0000-4000-8000-000000000000"
	return mustJSON(map[string]any{
		"dataType":    "CVE_RECORD",
		"dataVersion": "5.1",
		"cveMetadata": map[string]any{
			"cveId": cve, "assignerOrgId": org, "assignerShortName": "ffs-e2e", "state": "PUBLISHED",
			"datePublished": ts, "dateUpdated": ts,
		},
		"containers": map[string]any{"cna": map[string]any{
			"providerMetadata": map[string]any{"orgId": org, "shortName": "ffs-e2e", "dateUpdated": ts},
			"title":            "ffs e2e fixture",
			"descriptions":     []any{map[string]any{"lang": "en", "value": "ffs e2e fixture"}},
			"affected":         []any{affected},
			"metrics": []any{map[string]any{"format": "CVSS", "cvssV3_1": map[string]any{
				"version": "3.1", "baseScore": cvss, "baseSeverity": severity,
			}}},
			"references": []any{map[string]any{"url": "https://example.invalid/" + cve}},
		}},
	})
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
