// Package epss reads the daily FIRST EPSS scores (spec §6.4). Each advisory in use gets its EPSS
// score and percentile; a score that crosses a priority threshold (spec §6.6) is handed to the
// handler so the engine re-ranks the affected findings. An advisory first matched between syncs gets
// its score through the engine observer hook, as soon as the match is stored.
package epss

import (
	"bufio"
	"bytes"
	"cmp"
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
	"sync"
	"time"

	"github.com/go-logr/logr"

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
	// Thresholds are the scores whose crossing is reported: priority.EPSSEdges, the entry edges and
	// the leave edges below them.
	Thresholds []float64
	Now        func() time.Time // nil = time.Now
}

// Feed is the EPSS feed. It implements feeds.Feed and engine.Observer.
type Feed struct {
	o Options

	mu     sync.Mutex
	scores scoreTable // every score of the file last applied; nil until read
}

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
		// Scores already written would show no difference next run: keep their crossings pending.
		if len(reported) > 0 {
			set := map[string]bool{}
			for _, id := range append(feeds.Pending(st), reported...) {
				set[id] = true
			}
			feeds.SetPending(&st, slices.Sorted(maps.Keys(set)))
			err = errors.Join(err, f.o.Store.PutFeedState(ctx, st))
		}
		return err
	}
	if fresh {
		if err := feeds.WriteFile(cache, body); err != nil {
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

// apply reads the gzipped CSV in gz, makes it the table MatchesReplaced scores new matches from,
// and stores the score of every advisory in use whose stored score or percentile differs (with
// zeroOnly: whose stored score is zero). It returns the IDs whose score crossed a threshold and the
// file's score date. The table is published before the advisories in use are read, so a match
// stored from then on is covered by MatchesReplaced if this pass misses it.
func (f *Feed) apply(ctx context.Context, gz []byte, zeroOnly bool) (reported []string, scoreDate string, err error) {
	var table scoreTable
	scoreDate, err = readScores(ctx, gz, func(cve string, score, pct float64) error {
		table = table.add(cve, score, pct)
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	table = table.sorted()
	f.mu.Lock()
	f.scores = table
	f.mu.Unlock()

	inUse, err := f.o.Store.AdvisoryIDsInUse(ctx)
	if err != nil {
		return nil, "", err
	}
	have, err := f.o.Store.Advisories(ctx, inUse)
	if err != nil {
		return nil, "", err
	}
	for _, id := range slices.Sorted(maps.Keys(have)) {
		a := have[id]
		e, ok := table.lookup(id)
		if !ok || (zeroOnly && a.EPSS != 0) || (e.epss == a.EPSS && e.pct == a.EPSSPercentile) {
			continue
		}
		if err := f.o.Store.SetAdvisoryEPSS(ctx, id, e.epss, e.pct); err != nil {
			return reported, scoreDate, err
		}
		if f.crossed(a, e.epss) {
			reported = append(reported, id)
		}
	}
	return reported, scoreDate, nil
}

// readScores calls fn with every row of the gzipped CSV in gz whose score and percentile parse, and
// returns the file's score date.
func readScores(ctx context.Context, gz []byte, fn func(cve string, score, pct float64) error) (scoreDate string, err error) {
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return "", fmt.Errorf("epss: scores: %w", err)
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
		return "", fmt.Errorf("epss: scores: unexpected header %v", head)
	}
	for {
		if err := ctx.Err(); err != nil {
			return scoreDate, err
		}
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			return scoreDate, nil
		}
		if err != nil {
			return scoreDate, fmt.Errorf("epss: scores: %w", err)
		}
		score, err1 := strconv.ParseFloat(rec[1], 64)
		pct, err2 := strconv.ParseFloat(rec[2], 64)
		if err1 != nil || err2 != nil {
			continue
		}
		if err := fn(rec[0], score, pct); err != nil {
			return scoreDate, err
		}
	}
}

// MatchesReplaced is the engine.Observer hook. It gives the advisories now matched on digests that
// have no score yet the score of the file last applied, so a new match is ranked with it from its
// first recompute: the engine queues the owners after this returns. Without it the score would
// arrive with the next daily sync and could escalate the finding, alerting twice. Errors are logged:
// the next sync scores them anyway.
func (f *Feed) MatchesReplaced(ctx context.Context, digests []string) {
	if err := f.applyCached(ctx, digests); err != nil {
		logr.FromContextOrDiscard(ctx).Error(err, "applying cached EPSS scores to new matches failed; the next sync applies them")
	}
}

// OwnersRecomputed implements engine.Observer; the feed has nothing to do then.
func (f *Feed) OwnersRecomputed(context.Context, []string) {}

func (f *Feed) applyCached(ctx context.Context, digests []string) error {
	scores := f.cached(ctx)
	if len(scores) == 0 {
		return nil
	}
	ids, err := f.o.Store.AdvisoryIDsOnDigests(ctx, digests)
	if err != nil {
		return err
	}
	ids = slices.DeleteFunc(ids, func(id string) bool { _, ok := scores.lookup(id); return !ok })
	if len(ids) == 0 {
		return nil
	}
	have, err := f.o.Store.Advisories(ctx, ids)
	if err != nil {
		return err
	}
	for _, id := range ids {
		a, ok := have[id]
		if !ok || a.EPSS != 0 || a.EPSSPercentile != 0 {
			continue
		}
		e, _ := scores.lookup(id)
		if err := f.o.Store.SetAdvisoryEPSS(ctx, id, e.epss, e.pct); err != nil {
			return err
		}
	}
	return nil
}

// cached returns the scores of the file last applied, reading the cached copy on first use after a
// restart; nil when there is none yet.
func (f *Feed) cached(ctx context.Context) scoreTable {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.scores == nil {
		gz, err := os.ReadFile(filepath.Join(f.o.DataDir, cacheRel)) //nolint:gosec // G304: the path is under the configured data directory
		if err != nil {
			return nil
		}
		var t scoreTable
		if _, err := readScores(ctx, gz, func(cve string, score, pct float64) error {
			t = t.add(cve, score, pct)
			return nil
		}); err != nil {
			logr.FromContextOrDiscard(ctx).Info("the cached EPSS scores are unreadable; new matches wait for the next sync", "error", err.Error())
		}
		f.scores = t.sorted()
		if f.scores == nil {
			f.scores = scoreTable{} // read once; Sync replaces it
		}
	}
	return f.scores
}

// scoreTable holds every score of a file in about 24 bytes each, sorted by CVE.
type scoreTable []scoreEntry

type scoreEntry struct {
	key       uint64 // cveKey
	epss, pct float64
}

// cveKey packs "CVE-<year>-<number>" into a sortable integer.
func cveKey(id string) (uint64, bool) {
	rest, ok := strings.CutPrefix(id, "CVE-")
	if !ok {
		return 0, false
	}
	y, n, ok := strings.Cut(rest, "-")
	if !ok || len(y) != 4 || len(n) < 4 {
		return 0, false
	}
	year, err1 := strconv.ParseUint(y, 10, 16)
	num, err2 := strconv.ParseUint(n, 10, 32)
	if err1 != nil || err2 != nil {
		return 0, false
	}
	return year<<32 | num, true
}

func (t scoreTable) add(cve string, epss, pct float64) scoreTable {
	if k, ok := cveKey(cve); ok {
		t = append(t, scoreEntry{key: k, epss: epss, pct: pct})
	}
	return t
}

func (t scoreTable) sorted() scoreTable {
	slices.SortFunc(t, func(a, b scoreEntry) int { return cmp.Compare(a.key, b.key) })
	return slices.Clip(t)
}

func (t scoreTable) lookup(cve string) (scoreEntry, bool) {
	k, ok := cveKey(cve)
	if !ok {
		return scoreEntry{}, false
	}
	i, found := slices.BinarySearchFunc(t, k, func(e scoreEntry, k uint64) int { return cmp.Compare(e.key, k) })
	if !found {
		return scoreEntry{}, false
	}
	return t[i], true
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
