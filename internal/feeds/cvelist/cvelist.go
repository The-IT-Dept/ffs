// Package cvelist reads the CVE Program's cvelistV5 delta releases (spec §6.4). Each record it
// takes in stores the advisory with the CNA's severity (or CISA-ADP's), so fast-path findings get a
// severity within the hour instead of waiting for the next Grype DB, and the CNA's affected version
// ranges for the products of the upstream-runtime map (upstream.ForCNA).
//
// Releases are fetched as <base>/<tag>/<asset>; there is no listing. A past day is read from its
// end-of-day delta, today from the latest hourly delta. Hourly deltas are cumulative since 00:00
// UTC, so one zip per day covers it. The first run backfills 30 days of end-of-day deltas.
package cvelist

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/feeds"
	"github.com/the-it-dept/ffs/internal/match/upstream"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
	"github.com/the-it-dept/ffs/internal/version"
)

// DefaultURL is the release asset base used when Config.URL is empty.
const DefaultURL = "https://github.com/CVEProject/cvelistV5/releases/download"

const (
	maxZipBytes         = 64 << 20
	maxRecordBytes      = 2 << 20
	handlerChunk        = 500
	defaultBackfillDays = 30
	// overlap re-reads records updated just before the watermark: a delta cut at HH:00 can miss a
	// record committed in the minutes around it.
	overlap = 5 * time.Minute
	// endOfDayGrace is how long after a day ends the feed waits for its end-of-day delta before
	// accepting what the hourly deltas had. The release normally appears within the hour.
	endOfDayGrace = 24 * time.Hour
	day           = 24 * time.Hour

	stateRejected = "REJECTED"
)

// entryName matches the record entries of a delta zip.
var entryName = regexp.MustCompile(`^deltaCves/(CVE-\d{4}-\d{4,})\.json$`)

// Handler consumes the IDs of the CVE records taken in, at most 500 per call; wiring passes
// engine.OnCNARecords. Until it returns nil the IDs stay pending and the next Sync offers them
// again.
type Handler func(ctx context.Context, ids []string) error

// Options configures a Feed.
type Options struct {
	Config       config.FeedConfig // Config.URL is the release asset base
	Store        *store.Store
	HTTP         *http.Client // nil = feeds.NewHTTPClient(version.UserAgent())
	Handler      Handler
	BackfillDays int              // first-run window; 0 = 30
	Now          func() time.Time // nil = time.Now
}

// Feed is the cvelistV5 feed. It implements feeds.Feed.
type Feed struct {
	o    Options
	base string
}

// New returns the cvelistV5 feed.
func New(o Options) *Feed {
	if o.Config.URL == "" {
		o.Config.URL = DefaultURL
	}
	if o.HTTP == nil {
		o.HTTP = feeds.NewHTTPClient(version.UserAgent())
	}
	if o.BackfillDays <= 0 {
		o.BackfillDays = defaultBackfillDays
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Feed{o: o, base: strings.TrimRight(o.Config.URL, "/")}
}

// Name implements feeds.Feed.
func (f *Feed) Name() string { return feeds.NameCVEList }

// Interval implements feeds.Feed.
func (f *Feed) Interval() time.Duration { return f.o.Config.Interval }

// StaleAfter implements feeds.Feed.
func (f *Feed) StaleAfter() time.Duration { return f.o.Config.StaleAfter }

// Sync reads the deltas from the watermark's day to today, stores the records updated after the
// watermark (less a 5-minute overlap) and hands their IDs, with any left pending, to the handler.
// The watermark becomes the cutoff of the newest delta read: the end of a past day, or the hour of
// today's delta. A past day whose end-of-day delta is not out yet stops the walk at that day's
// latest hourly delta, so its last hours are read again once the release appears, unless the day
// ended more than a day ago. Records and the new watermark are stored before the handler runs, with
// the IDs pending, so a handler failure redelivers them without downloading again. A failed
// download keeps what came before it.
func (f *Feed) Sync(ctx context.Context) error {
	st, err := f.o.Store.FeedState(ctx, feeds.NameCVEList)
	if err != nil {
		return err
	}
	now := f.o.Now().UTC()
	wm, err := time.Parse(time.RFC3339, st.Watermark)
	if err != nil {
		wm = now.Add(-time.Duration(f.o.BackfillDays) * day)
	}
	wm = wm.UTC()

	ids := map[string]bool{}
	for _, id := range feeds.Pending(st) {
		ids[id] = true
	}
	covered := wm
	today := startOfDay(now)
	var syncErr error
	for d := startOfDay(wm); !d.After(today); d = d.Add(day) {
		if err := ctx.Err(); err != nil {
			syncErr = err
			break
		}
		got, err := f.fetchDay(ctx, d, wm, now)
		if err != nil {
			syncErr = err
			break
		}
		if got.body != nil {
			taken, err := f.ingest(ctx, got.body, wm.Add(-overlap))
			for _, id := range taken {
				ids[id] = true
			}
			if err != nil {
				syncErr = fmt.Errorf("cvelist: %s: %w", got.url, err)
				break
			}
			if got.cutoff.After(covered) {
				covered = got.cutoff
			}
		}
		if got.missingEndOfDay {
			if now.Before(d.Add(day + endOfDayGrace)) {
				break
			}
			logr.FromContextOrDiscard(ctx).Info("cvelistV5 end-of-day delta is missing; continuing without it",
				"day", d.Format(time.DateOnly))
		}
	}

	st.Watermark = covered.Format(time.RFC3339)
	pending := slices.Sorted(maps.Keys(ids))
	feeds.SetPending(&st, pending)
	if err := f.o.Store.PutFeedState(ctx, st); err != nil {
		return errors.Join(syncErr, err)
	}
	for chunk := range slices.Chunk(pending, handlerChunk) {
		if err := f.o.Handler(ctx, chunk); err != nil {
			return errors.Join(syncErr, fmt.Errorf("cvelist: handler: %w", err))
		}
	}
	if len(pending) > 0 {
		feeds.SetPending(&st, nil)
		if err := f.o.Store.PutFeedState(ctx, st); err != nil {
			return errors.Join(syncErr, err)
		}
	}
	return syncErr
}

// dayDelta is the delta read for one day.
type dayDelta struct {
	body   []byte    // nil when nothing newer than the watermark was found
	url    string    // where body came from
	cutoff time.Time // the time body covers the day up to
	// missingEndOfDay reports a past day whose end-of-day delta is not published.
	missingEndOfDay bool
}

// fetchDay reads the delta covering day d beyond wm: for a past day its end-of-day delta, or when
// that is not published its latest hourly one; for today the latest hourly delta. Hourly deltas at
// or before wm are not read.
func (f *Feed) fetchDay(ctx context.Context, d, wm, now time.Time) (dayDelta, error) {
	date := d.Format(time.DateOnly)
	last := now.Hour()
	var out dayDelta
	if d.Before(startOfDay(now)) {
		if !wm.Before(d.Add(day)) {
			return out, nil
		}
		url := fmt.Sprintf("%s/cve_%s_at_end_of_day/%s_delta_CVEs_at_end_of_day.zip", f.base, date, date)
		body, err := f.get(ctx, url)
		if err == nil {
			return dayDelta{body: body, url: url, cutoff: d.Add(day)}, nil
		}
		if !errors.Is(err, feeds.ErrNotFound) {
			return out, err
		}
		out.missingEndOfDay, last = true, 23
	}
	for h := last; h >= 0; h-- {
		cutoff := d.Add(time.Duration(h) * time.Hour)
		if !cutoff.After(wm) {
			break
		}
		url := fmt.Sprintf("%s/cve_%s_%02d00Z/%s_delta_CVEs_at_%02d00Z.zip", f.base, date, h, date, h)
		body, err := f.get(ctx, url)
		if errors.Is(err, feeds.ErrNotFound) {
			continue
		}
		if err != nil {
			return out, err
		}
		out.body, out.url, out.cutoff = body, url, cutoff
		return out, nil
	}
	return out, nil
}

func (f *Feed) get(ctx context.Context, url string) ([]byte, error) {
	resp, err := feeds.Fetch(ctx, f.o.HTTP, feeds.Request{URL: url, MaxBytes: maxZipBytes})
	if err != nil {
		return nil, err
	}
	if resp.Status != http.StatusOK {
		return nil, fmt.Errorf("cvelist: GET %s: unexpected status %d", url, resp.Status)
	}
	return resp.Body, nil
}

// ingest stores the records of a delta zip updated after since (or with no update time) and
// returns their IDs. Entries other than deltaCves/CVE-*.json of at most 2 MiB, records that do not
// parse and records whose ID is not their file name are skipped.
func (f *Feed) ingest(ctx context.Context, body []byte, since time.Time) ([]string, error) {
	// Insecure entry names are not an error here: entryName admits only deltaCves/CVE-*.json.
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil && !errors.Is(err, zip.ErrInsecurePath) {
		return nil, err
	}
	log := logr.FromContextOrDiscard(ctx)
	var ids []string
	for _, zf := range zr.File {
		if err := ctx.Err(); err != nil {
			return ids, err
		}
		m := entryName.FindStringSubmatch(zf.Name)
		if m == nil || !zf.Mode().IsRegular() {
			continue
		}
		raw, err := readEntry(zf)
		if errors.Is(err, feeds.ErrTooLarge) {
			log.Info("skipping an oversized CVE record", "entry", zf.Name)
			continue
		}
		if err != nil {
			return ids, fmt.Errorf("%s: %w", zf.Name, err)
		}
		rec, err := ParseRecord(raw)
		if err == nil && rec.ID != m[1] {
			err = fmt.Errorf("record has id %q", rec.ID)
		}
		if err != nil {
			log.Info("skipping an unreadable CVE record", "entry", zf.Name, "error", err.Error())
			continue
		}
		if !rec.Updated.IsZero() && !rec.Updated.After(since) {
			continue
		}
		if err := f.put(ctx, rec); err != nil {
			return ids, err
		}
		ids = append(ids, rec.ID)
	}
	return ids, nil
}

// put stores the advisory of rec and, per mapped product, its affected ranges (entries naming the
// same product merged). The ranges replace every range stored for the CVE, so a product the record
// no longer names, or a REJECTED record, leaves none behind for the upstream matcher.
func (f *Feed) put(ctx context.Context, rec Record) error {
	if err := f.o.Store.UpsertAdvisory(ctx, model.Advisory{
		ID:          rec.ID,
		Title:       rec.Title,
		Published:   rec.Published,
		Modified:    rec.Updated,
		Links:       rec.Links,
		CNASeverity: rec.Severity,
		CNACVSS:     rec.CVSS,
		CNASource:   rec.SeveritySource,
		Withdrawn:   rec.State == stateRejected,
	}); err != nil {
		return err
	}
	byKey := map[string]upstream.CNARanges{}
	for _, a := range rec.Affected {
		e, ok := upstream.ForCNA(a.Vendor, a.Product)
		if !ok || rec.State == stateRejected {
			continue
		}
		r := byKey[e.Key]
		if r.DefaultStatus == "" {
			r.DefaultStatus = a.Ranges.DefaultStatus
		}
		r.Versions = append(r.Versions, a.Ranges.Versions...)
		byKey[e.Key] = r
	}
	byProduct := make(map[string][]byte, len(byKey))
	for key, r := range byKey {
		raw, err := json.Marshal(r)
		if err != nil {
			return err
		}
		byProduct[key] = raw
	}
	return f.o.Store.ReplaceUpstreamRanges(ctx, rec.ID, byProduct)
}

// readEntry reads a zip entry of at most maxRecordBytes.
func readEntry(zf *zip.File) ([]byte, error) {
	if zf.UncompressedSize64 > maxRecordBytes {
		return nil, feeds.ErrTooLarge
	}
	rc, err := zf.Open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	raw, err := io.ReadAll(io.LimitReader(rc, maxRecordBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxRecordBytes {
		return nil, feeds.ErrTooLarge
	}
	return raw, nil
}

// startOfDay returns 00:00 UTC of t's UTC day.
func startOfDay(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}
