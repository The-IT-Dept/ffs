// Package epss reads the daily FIRST EPSS scores (spec §6.4). Each advisory in use gets its EPSS
// score and percentile; a score that crosses a priority threshold (spec §6.6) is handed to the
// handler so the engine re-ranks the affected findings.
package epss

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/feeds"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
	"github.com/the-it-dept/ffs/internal/version"
)

// DefaultURL is the scores URL used when Config.URL is empty. It redirects to the day's file.
const DefaultURL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

const (
	maxBytes     = 64 << 20
	maxCSVBytes  = 1 << 30 // decompressed limit
	metaFile     = "file"
	metaScoreDay = "scoreDate"
	cacheRel     = "feeds/epss.csv.gz"
)

// Handler consumes the IDs of advisories whose score crossed a threshold; wiring passes
// engine.OnAdvisoriesEnriched. Until it returns nil the IDs stay pending and the next Sync offers
// them again.
type Handler func(ctx context.Context, ids []string) error

// Options configures a Feed.
type Options struct {
	Config  config.FeedConfig
	Store   *store.Store
	HTTP    *http.Client // nil = feeds.NewHTTPClient(version.UserAgent())
	Handler Handler
	DataDir string // the downloaded scores are cached at DataDir/feeds/epss.csv.gz
	// Thresholds are the scores whose crossing is reported: {Priority.EPSSBump, Priority.EPSSHigh}.
	Thresholds []float64
	Now        func() time.Time // nil = time.Now
}

// Feed is the EPSS feed. It implements feeds.Feed.
type Feed struct{ o Options }

// New returns the EPSS feed.
func New(o Options) *Feed {
	if o.Config.URL == "" {
		o.Config.URL = DefaultURL
	}
	if o.HTTP == nil {
		o.HTTP = feeds.NewHTTPClient(version.UserAgent())
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Feed{o: o}
}

// Name implements feeds.Feed.
func (f *Feed) Name() string { return feeds.NameEPSS }

// Interval implements feeds.Feed.
func (f *Feed) Interval() time.Duration { return f.o.Config.Interval }

// StaleAfter implements feeds.Feed.
func (f *Feed) StaleAfter() time.Duration { return f.o.Config.StaleAfter }

// Sync resolves the current day's file. A new file is downloaded and scored against every advisory
// in use; the advisories whose score crossed a threshold go to the handler with any left pending.
// The same file as last time is not downloaded again: the cached copy scores only advisories that
// came into use since and still have no score.
func (f *Feed) Sync(ctx context.Context) error {
	st, err := f.o.Store.FeedState(ctx, feeds.NameEPSS)
	if err != nil {
		return err
	}
	cache := filepath.Join(f.o.DataDir, cacheRel)
	resp, err := feeds.Fetch(ctx, f.o.HTTP, feeds.Request{URL: f.o.Config.URL, MaxBytes: maxBytes, NoRedirect: true})
	if err != nil {
		return err
	}

	var (
		file     = f.o.Config.URL // the file's identity: its URL after the redirect
		body     []byte
		fresh    = true // the file differs from the one last applied
		zeroOnly bool
	)
	switch {
	case resp.Status >= 200 && resp.Status < 300:
		body = resp.Body
	case resp.Status >= 300 && resp.Status < 400:
		base, err := url.Parse(f.o.Config.URL)
		if err != nil {
			return err
		}
		loc, err := base.Parse(resp.Location)
		if err != nil || resp.Location == "" {
			return fmt.Errorf("epss: GET %s: bad redirect %q", f.o.Config.URL, resp.Location)
		}
		file = loc.String()
		if file == st.Meta[metaFile] {
			fresh, zeroOnly = false, true
			if body, err = os.ReadFile(cache); err != nil { //nolint:gosec // G304: the path is under the configured data directory
				body = nil // cache lost: download the file again and apply it in full
				fresh, zeroOnly = true, false
			}
		}
		if body == nil {
			got, err := feeds.Fetch(ctx, f.o.HTTP, feeds.Request{URL: file, MaxBytes: maxBytes})
			if err != nil {
				return err
			}
			if got.Status != http.StatusOK {
				return fmt.Errorf("epss: GET %s: unexpected status %d", file, got.Status)
			}
			body = got.Body
		}
	default:
		return fmt.Errorf("epss: GET %s: unexpected status %d", f.o.Config.URL, resp.Status)
	}

	reported, scoreDate, err := f.apply(ctx, body, zeroOnly)
	if err != nil {
		return err
	}
	if fresh {
		if err := writeFile(cache, body); err != nil {
			return err
		}
		if scoreDate != "" {
			if st.Meta == nil {
				st.Meta = map[string]string{}
			}
			st.Meta[metaScoreDay] = scoreDate
		}
	}

	set := map[string]bool{}
	for _, id := range feeds.Pending(st) {
		set[id] = true
	}
	for _, id := range reported {
		set[id] = true
	}
	pending := slices.Sorted(maps.Keys(set))
	feeds.SetPending(&st, pending)
	if err := f.o.Store.PutFeedState(ctx, st); err != nil {
		return err
	}
	if len(pending) > 0 {
		if err := f.o.Handler(ctx, pending); err != nil {
			return fmt.Errorf("epss: handler: %w", err)
		}
		feeds.SetPending(&st, nil)
	}
	if fresh {
		if st.Meta == nil {
			st.Meta = map[string]string{}
		}
		st.Meta[metaFile] = file
	}
	return f.o.Store.PutFeedState(ctx, st)
}

// apply reads the gzipped CSV in gz and stores the score of every advisory in use whose stored
// score or percentile differs (with zeroOnly: whose stored score is zero). It returns the IDs whose
// score crossed a threshold and the file's score date.
func (f *Feed) apply(ctx context.Context, gz []byte, zeroOnly bool) (reported []string, scoreDate string, err error) {
	inUse, err := f.o.Store.AdvisoryIDsInUse(ctx)
	if err != nil {
		return nil, "", err
	}
	have, err := f.o.Store.Advisories(ctx, inUse)
	if err != nil {
		return nil, "", err
	}
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, "", fmt.Errorf("epss: scores: %w", err)
	}
	defer func() { _ = zr.Close() }()
	br := bufio.NewReader(io.LimitReader(zr, maxCSVBytes))
	for {
		if b, perr := br.Peek(1); perr != nil || b[0] != '#' {
			break
		}
		line, _ := br.ReadString('\n')
		for part := range strings.SplitSeq(strings.TrimSpace(line), ",") {
			if d, ok := strings.CutPrefix(part, "score_date:"); ok {
				scoreDate = d
			}
		}
	}
	r := csv.NewReader(br)
	r.FieldsPerRecord = 3
	head, err := r.Read()
	if err != nil || head[0] != "cve" || head[1] != "epss" || head[2] != "percentile" {
		return nil, "", fmt.Errorf("epss: scores: unexpected header %v", head)
	}
	for {
		if err := ctx.Err(); err != nil {
			return reported, scoreDate, err
		}
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			return reported, scoreDate, nil
		}
		if err != nil {
			return reported, scoreDate, fmt.Errorf("epss: scores: %w", err)
		}
		a, ok := have[rec[0]]
		if !ok || (zeroOnly && a.EPSS != 0) {
			continue
		}
		score, err1 := strconv.ParseFloat(rec[1], 64)
		pct, err2 := strconv.ParseFloat(rec[2], 64)
		if err1 != nil || err2 != nil || (score == a.EPSS && pct == a.EPSSPercentile) {
			continue
		}
		if err := f.o.Store.SetAdvisoryEPSS(ctx, rec[0], score, pct); err != nil {
			return reported, scoreDate, err
		}
		if f.crossed(a, score) {
			reported = append(reported, rec[0])
		}
	}
}

// crossed reports whether moving a's score to now crosses a threshold.
func (f *Feed) crossed(a model.Advisory, now float64) bool {
	for _, t := range f.o.Thresholds {
		if (a.EPSS < t) != (now < t) {
			return true
		}
	}
	return false
}

// writeFile writes data to path through a temporary file and a rename.
func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".part"
	//nolint:gosec // G703: path is built from the configured data directory and a fixed name
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
