// Package osv is the fast path for new and changed advisories. It polls the OSV.dev bucket for the
// ecosystems present in the inventory (plus Go and GIT), reads each bucket's modified_id.csv down
// to its watermark, caches the changed records locally and hands a record to the handler only when
// its affected set, aliases or withdrawn time changed: most modifications only touch timestamps.
// A cached GIT record that stops referencing the GitRepos repositories is handed off once more
// and then dropped from the cache. A weekly set-diff withdraws records that left the bucket, and
// records outside Go and GIT are pruned after 14 days unless the osv source still matches them.
package osv

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

	"github.com/go-logr/logr"
	"golang.org/x/sync/errgroup"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/feeds"
	"github.com/the-it-dept/ffs/internal/store"
	"github.com/the-it-dept/ffs/internal/version"
)

// DefaultURL is the bucket base used when Config.URL is empty.
const DefaultURL = "https://osv-vulnerabilities.storage.googleapis.com"

const (
	maxRecordBytes   = 4 << 20
	handlerChunk     = 500
	fetchConcurrency = 8
	fetchChunk       = 32 // records fetched concurrently, then stored, to bound memory
	firstPollWindow  = 72 * time.Hour
	setDiffInterval  = 7 * 24 * time.Hour
	retention        = 14 * 24 * time.Hour

	metaWatermark   = "wm."   // + bucket: RFC 3339 time of the newest row handed off
	metaGeneration  = "gen."  // + bucket: x-goog-generation of modified_id.csv when last read
	metaBootstrap   = "boot." // + bucket (Go, GIT): when all.zip was loaded
	metaRecordBytes = "size." // + bucket: average uncompressed size of its records, measured
	metaGitRepos    = "repos.GIT"
	metaSetDiff     = "setdiff"
)

// maxZipBytes bounds a download of all of all.zip. A bigger one is read with Range requests or one
// GET per record instead. A variable so tests can lower it.
var maxZipBytes int64 = 1 << 30

// Changed is a new or changed OSV record. Ecosystem is the bucket it came from ("Debian", "PyPI",
// "Go", "GIT", ...).
type Changed struct {
	Ecosystem, ID string
	Raw           []byte
}

// Handler consumes changed records, at most 500 per call. Until it returns nil the records stay
// pending and the next Sync offers them again.
type Handler func(ctx context.Context, recs []Changed) error

// Options configures a Feed.
type Options struct {
	Config  config.FeedConfig // Config.URL is the bucket base
	Store   *store.Store
	HTTP    *http.Client // nil = feeds.NewHTTPClient(version.UserAgent())
	Handler Handler
	DataDir string // all.zip downloads go to DataDir/osv
	// GitRepos are the repositories (NormalizeRepo form) whose GIT records are kept; wiring passes
	// upstream.Repos() and k8s.Repo.
	GitRepos   []string
	Chainguard bool             // also poll the Wolfi and Chainguard buckets
	Now        func() time.Time // nil = time.Now
}

// Feed is the OSV feed. It implements feeds.Feed.
type Feed struct {
	o        Options
	base     string
	gitRepos map[string]bool
	reposKey string // fingerprint of gitRepos; a change reloads the GIT bucket
}

// New returns the OSV feed.
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
	f := &Feed{o: o, base: strings.TrimRight(o.Config.URL, "/"), gitRepos: make(map[string]bool, len(o.GitRepos))}
	for _, r := range o.GitRepos {
		f.gitRepos[NormalizeRepo(r)] = true
	}
	sum := sha256.Sum256([]byte(strings.Join(slices.Sorted(maps.Keys(f.gitRepos)), "\n")))
	f.reposKey = hex.EncodeToString(sum[:8])
	return f
}

// Name implements feeds.Feed.
func (f *Feed) Name() string { return feeds.NameOSV }

// Interval implements feeds.Feed.
func (f *Feed) Interval() time.Duration { return f.o.Config.Interval }

// StaleAfter implements feeds.Feed.
func (f *Feed) StaleAfter() time.Duration { return f.o.Config.StaleAfter }

// recKey names a cached record. Pending records are stored as "bucket/id": neither bucket names
// nor record IDs (which are file names in the bucket) contain "/".
type recKey struct{ bucket, id string }

func (k recKey) String() string { return k.bucket + "/" + k.id }

// Sync hands off any pending records, polls (or, for Go and GIT, first loads) every bucket in use,
// runs the weekly set-diff and prunes old records. A failing bucket does not stop the others,
// unless it failed with records pending (a handler error, say): those must be handed off before
// anything else is taken in.
func (f *Feed) Sync(ctx context.Context) error {
	st, err := f.o.Store.FeedState(ctx, feeds.NameOSV)
	if err != nil {
		return err
	}
	if st.Meta == nil {
		st.Meta = map[string]string{}
	}
	if err := f.redeliver(ctx, &st); err != nil {
		return err
	}
	buckets, err := f.buckets(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, b := range buckets {
		if err := ctx.Err(); err != nil {
			return errors.Join(append(errs, err)...)
		}
		if f.needsBootstrap(st, b) {
			err = f.bootstrap(ctx, &st, b)
		} else {
			err = f.poll(ctx, &st, b)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("osv: bucket %s: %w", b, err))
			if len(feeds.Pending(st)) > 0 {
				return errors.Join(errs...)
			}
		}
	}
	errs = append(errs, f.setDiff(ctx, &st, buckets), f.prune(ctx))
	return errors.Join(errs...)
}

// buckets returns the sorted buckets to poll: those of the ecosystems in use, plus Go and GIT.
func (f *Feed) buckets(ctx context.Context) ([]string, error) {
	keys, err := f.o.Store.EcosystemsInUse(ctx)
	if err != nil {
		return nil, err
	}
	out := []string{BucketGIT, BucketGo}
	for _, k := range keys {
		if b := BucketFor(k, f.o.Chainguard); b != "" && !slices.Contains(out, b) {
			out = append(out, b)
		}
	}
	slices.Sort(out)
	return out, nil
}

// needsBootstrap reports whether b is Go or GIT and its all.zip has not been loaded, or, for GIT,
// was loaded for a different set of repositories.
func (f *Feed) needsBootstrap(st store.FeedState, b string) bool {
	switch b {
	case BucketGo:
		return st.Meta[metaBootstrap+b] == ""
	case BucketGIT:
		return st.Meta[metaBootstrap+b] == "" || st.Meta[metaGitRepos] != f.reposKey
	}
	return false
}

func (f *Feed) save(ctx context.Context, st *store.FeedState) error {
	return f.o.Store.PutFeedState(ctx, *st)
}

// redeliver hands off the records a previous Sync left pending.
func (f *Feed) redeliver(ctx context.Context, st *store.FeedState) error {
	pending := feeds.Pending(*st)
	if len(pending) == 0 {
		return nil
	}
	keys := make([]recKey, 0, len(pending))
	for _, s := range pending {
		if b, id, ok := strings.Cut(s, "/"); ok && b != "" && id != "" {
			keys = append(keys, recKey{b, id})
		}
	}
	// A crash can separate a record's write from its index names: rewrite them from the record.
	if err := f.deliverKeys(ctx, keys, true); err != nil {
		return err
	}
	feeds.SetPending(st, nil)
	return f.save(ctx, st)
}

// poll reads b's modified_id.csv down to the watermark and hands off the records whose affected
// set changed. The watermark and generation advance only once the handler has taken them.
func (f *Feed) poll(ctx context.Context, st *store.FeedState, b string) error {
	rd := newCSVReader(f.o.HTTP, f.bucketURL(b, "modified_id.csv"))
	rows, err := rd.next(ctx)
	if err != nil {
		return err
	}
	if rd.gen != "" && rd.gen == st.Meta[metaGeneration+b] {
		return nil
	}
	wm := f.watermark(*st, b)
	newest := wm
	seen := map[string]bool{}
	var ids []string
	for {
		stop := false
		for _, row := range rows {
			if row.ts.After(newest) {
				newest = row.ts
			}
			if !row.ts.After(wm) {
				stop = true
				break
			}
			if row.id == "" || SkipID(b, row.id) || seen[row.id] {
				continue
			}
			seen[row.id] = true
			ids = append(ids, row.id)
		}
		if stop || rd.done {
			break
		}
		if rows, err = rd.next(ctx); err != nil {
			return err
		}
	}

	changed, takeErr := f.take(ctx, st, b, ids)
	if err := f.handOff(ctx, st, changed); err != nil {
		return errors.Join(takeErr, err)
	}
	if takeErr != nil { // the watermark stays, so the rest is read again next time
		return errors.Join(takeErr, f.save(ctx, st))
	}
	if newest.After(wm) {
		st.Meta[metaWatermark+b] = newest.Format(time.RFC3339Nano)
	}
	setMeta(st, metaGeneration+b, rd.gen)
	return f.save(ctx, st)
}

// watermark returns b's watermark, or now − 72h before its first poll.
func (f *Feed) watermark(st store.FeedState, b string) time.Time {
	if t, err := time.Parse(time.RFC3339Nano, st.Meta[metaWatermark+b]); err == nil {
		return t
	}
	return f.o.Now().UTC().Add(-firstPollWindow)
}

// take fetches and caches the records ids of b, returning the ones to hand off: those whose
// affected hash changed and dropped GIT records (see put); on an error, those so far, which the
// caller still hands off. It reads them the cheapest way (see choose): one GET each, Range reads of
// their entries in all.zip, or all of all.zip. Every candidate is pending while the cache is
// written, so a crash between a record's write and its hand-off cannot lose it.
func (f *Feed) take(ctx context.Context, st *store.FeedState, b string, ids []string) ([]recKey, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	gitCached, err := f.gitCached(ctx, b)
	if err != nil {
		return nil, err
	}
	how, probe, err := f.plan(ctx, *st, b, len(ids))
	if err != nil {
		return nil, err
	}
	keys := make([]recKey, len(ids))
	for i, id := range ids {
		keys[i] = recKey{b, id}
	}
	setPending(st, keys)
	if err := f.save(ctx, st); err != nil {
		return nil, err
	}

	want := func() map[string]bool {
		m := make(map[string]bool, len(ids))
		for _, id := range ids {
			m[id] = true
		}
		return m
	}
	var (
		out   []recKey
		sizes sizeStats
	)
	switch how {
	case wholeZip:
		var path string
		if path, err = f.downloadZip(ctx, b); err != nil {
			return nil, err
		}
		defer func() { _ = os.Remove(path) }()
		out, sizes, err = f.storeZip(ctx, b, path, want(), gitCached)
	case rangedZip:
		out, sizes, err = f.storeRanged(ctx, b, probe, want(), gitCached)
	default:
		out, sizes, err = f.storeRecords(ctx, b, ids, gitCached)
	}
	learnRecordBytes(st, b, sizes)
	return out, err
}

// plan picks how take reads n records of b. all.zip is probed only when one GET per record looks
// expensive; a bucket without all.zip is read one GET per record.
func (f *Feed) plan(ctx context.Context, st store.FeedState, b string, n int) (transport, zipProbe, error) {
	recordBytes := recordBytesOf(st, b)
	if int64(n)*(recordBytes+requestOverhead) <= probeAbove {
		return perRecord, zipProbe{}, nil
	}
	p, err := probeZip(ctx, f.o.HTTP, f.bucketURL(b, "all.zip"))
	switch {
	case errors.Is(err, feeds.ErrNotFound):
		return perRecord, p, nil
	case err != nil:
		return perRecord, p, err
	}
	how := choose(n, recordBytes, p)
	logr.FromContextOrDiscard(ctx).V(1).Info("reading OSV records", "bucket", b, "records", n, "transport", how.String(),
		"recordBytes", recordBytes, "zipBytes", p.size, "rangeReads", p.ranged)
	return how, p, nil
}

// sizeStats sums the uncompressed sizes of the records a take read.
type sizeStats struct{ n, bytes int64 }

func (s *sizeStats) add(n int) { s.n, s.bytes = s.n+1, s.bytes+int64(n) }

// recordBytesOf returns the measured average record size of b, or defaultRecordBytes.
func recordBytesOf(st store.FeedState, b string) int64 {
	if v, err := strconv.ParseInt(st.Meta[metaRecordBytes+b], 10, 64); err == nil && v > 0 {
		return v
	}
	return defaultRecordBytes
}

// learnRecordBytes folds the sizes a take read into b's average, weighting a read of 100 records or
// more fully. The caller saves st.
func learnRecordBytes(st *store.FeedState, b string, s sizeStats) {
	if s.n == 0 {
		return
	}
	mean := s.bytes / s.n
	if v, err := strconv.ParseInt(st.Meta[metaRecordBytes+b], 10, 64); err == nil && v > 0 {
		w := min(s.n, 100)
		mean = (v*(100-w) + mean*w) / 100
	}
	st.Meta[metaRecordBytes+b] = strconv.FormatInt(max(mean, 1), 10)
}

// storeRecords GETs the records ids of b, fetchChunk at a time, and caches each (see put).
func (f *Feed) storeRecords(ctx context.Context, b string, ids []string, gitCached map[string]bool) ([]recKey, sizeStats, error) {
	var (
		out   []recKey
		sizes sizeStats
	)
	for chunk := range slices.Chunk(ids, fetchChunk) {
		raws, err := f.fetchRecords(ctx, b, chunk)
		if err != nil {
			return out, sizes, err
		}
		for i, raw := range raws {
			if raw == nil {
				continue
			}
			sizes.add(len(raw))
			res, err := f.put(ctx, b, chunk[i], raw, gitCached)
			if err != nil {
				return out, sizes, err
			}
			if res == putChanged || res == putDropped {
				out = append(out, recKey{b, chunk[i]})
			}
		}
	}
	return out, sizes, nil
}

// storeRanged reads the entries of the probed all.zip of b that want names with Range requests,
// rangedChunk at a time, and caches each (see put).
func (f *Feed) storeRanged(ctx context.Context, b string, p zipProbe, want, gitCached map[string]bool) ([]recKey, sizeStats, error) {
	log := logr.FromContextOrDiscard(ctx)
	var sizes sizeStats
	z, err := openRemoteZip(ctx, f.o.HTTP, f.bucketURL(b, "all.zip"), p)
	if err != nil {
		return nil, sizes, err
	}
	var files []*zip.File
	for _, zf := range z.zr.File {
		id := zipEntryID(b, zf, want)
		switch {
		case id == "":
		case zf.UncompressedSize64 > maxRecordBytes:
			log.Info("skipping an oversized OSV record", "bucket", b, "id", id)
		default:
			files = append(files, zf)
		}
	}
	var out []recKey
	for chunk := range slices.Chunk(files, rangedChunk) {
		raws := make([][]byte, len(chunk))
		g, gctx := errgroup.WithContext(ctx)
		g.SetLimit(rangedConcurrency)
		for i, zf := range chunk {
			g.Go(func() error {
				if err := gctx.Err(); err != nil {
					return err
				}
				raw, err := z.read(zf)
				raws[i] = raw
				return err
			})
		}
		if err := g.Wait(); err != nil {
			return out, sizes, fmt.Errorf("osv: %s all.zip: %w", b, err)
		}
		for i, raw := range raws {
			sizes.add(len(raw))
			id := strings.TrimSuffix(chunk[i].Name, ".json")
			res, err := f.put(ctx, b, id, raw, gitCached)
			if err != nil {
				return out, sizes, err
			}
			if res == putChanged || res == putDropped {
				out = append(out, recKey{b, id})
			}
		}
	}
	return out, sizes, nil
}

// gitCached returns the IDs held in the GIT cache when b is GIT, else nil. put needs them to notice
// a cached GIT record that no longer references a GitRepos repository.
func (f *Feed) gitCached(ctx context.Context, b string) (map[string]bool, error) {
	if b != BucketGIT {
		return nil, nil
	}
	ids, err := f.o.Store.OSVRecordIDs(ctx, b)
	if err != nil {
		return nil, err
	}
	m := make(map[string]bool, len(ids))
	for _, id := range ids {
		m[id] = true
	}
	return m, nil
}

// fetchRecords GETs <b>/<id>.json for each id, 8 at a time. A missing or oversized record is
// skipped (nil).
func (f *Feed) fetchRecords(ctx context.Context, b string, ids []string) ([][]byte, error) {
	log := logr.FromContextOrDiscard(ctx)
	out := make([][]byte, len(ids))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(fetchConcurrency)
	for i, id := range ids {
		g.Go(func() error {
			resp, err := feeds.Fetch(gctx, f.o.HTTP, feeds.Request{URL: f.bucketURL(b, id+".json"), MaxBytes: maxRecordBytes})
			switch {
			case errors.Is(err, feeds.ErrNotFound):
				return nil
			case errors.Is(err, feeds.ErrTooLarge):
				log.Info("skipping an oversized OSV record", "bucket", b, "id", id)
				return nil
			case err != nil:
				return err
			}
			out[i] = resp.Body
			return nil
		})
	}
	return out, g.Wait()
}

// putResult is what put did with a record.
type putResult uint8

const (
	putSkipped   putResult = iota // unreadable, not the requested ID, or an uncached GIT record outside GitRepos
	putUnchanged                  // cached, with the affected hash it already had
	putChanged                    // new, or its affected hash changed; its index names were rewritten
	putDropped                    // a cached GIT record that no longer references a GitRepos repository
)

// put caches one record of b. A GIT record that references no GitRepos repository is skipped,
// unless the GIT cache holds it (gitCached): its repository mapping changed, and the cached copy
// would keep matching the old repository for good. The new raw then replaces the cached one with
// no index names, and deliverKeys hands it off and deletes it from the cache.
func (f *Feed) put(ctx context.Context, b, id string, raw []byte, gitCached map[string]bool) (putResult, error) {
	info, err := parseRecord(raw)
	if err == nil && info.ID != id {
		err = fmt.Errorf("osv: record %s has id %q", id, info.ID)
	}
	var hash string
	if err == nil {
		hash, err = AffectedHash(raw)
	}
	if err != nil {
		logr.FromContextOrDiscard(ctx).Info("skipping an unreadable OSV record", "bucket", b, "id", id, "error", err.Error())
		return putSkipped, nil
	}
	modified := info.modified(f.o.Now().UTC())
	if b == BucketGIT && !f.tracked(info) {
		if !gitCached[id] {
			return putSkipped, nil
		}
		if _, err := f.o.Store.PutOSVRecord(ctx, b, id, modified, hash, raw); err != nil {
			return putSkipped, err
		}
		return putDropped, f.o.Store.PutOSVRecordNames(ctx, b, id, nil)
	}
	changed, err := f.o.Store.PutOSVRecord(ctx, b, id, modified, hash, raw)
	switch {
	case err != nil:
		return putSkipped, err
	case !changed:
		return putUnchanged, nil
	}
	return putChanged, f.o.Store.PutOSVRecordNames(ctx, b, id, info.names(b))
}

// tracked reports whether a GIT record references one of the GitRepos repositories.
func (f *Feed) tracked(info recordInfo) bool {
	return slices.ContainsFunc(info.gitRepos(), func(r string) bool { return f.gitRepos[r] })
}

// downloadZip downloads <b>/all.zip to DataDir/osv/<b>-all.zip and returns its path.
func (f *Feed) downloadZip(ctx context.Context, b string) (string, error) {
	dir := filepath.Join(f.o.DataDir, "osv")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	path := filepath.Join(dir, b+"-all.zip")
	if _, err := feeds.Download(ctx, f.o.HTTP, f.bucketURL(b, "all.zip"), path, maxZipBytes, nil); err != nil {
		return "", err
	}
	return path, nil
}

// zipEntryID returns the record ID of zf, an entry of b's all.zip, when it is a plain "<id>.json"
// file that want names (every one when want is nil) and not a notice; else "".
func zipEntryID(b string, zf *zip.File, want map[string]bool) string {
	id, ok := strings.CutSuffix(zf.Name, ".json")
	if !ok || id == "" || strings.ContainsAny(zf.Name, `/\`) || !zf.Mode().IsRegular() ||
		(want != nil && !want[id]) || SkipID(b, id) {
		return ""
	}
	return id
}

// storeZip caches the records in the all.zip at path: those named in want, or every record when
// want is nil. It returns the records to hand off: the changed and dropped ones (see put), or with
// want nil (a bootstrap, which may be re-running after a crash) every cached one, including on an
// error those so far. Entries other than plain "<id>.json" files of at most 4 MiB are ignored.
func (f *Feed) storeZip(ctx context.Context, b, path string, want, gitCached map[string]bool) ([]recKey, sizeStats, error) {
	var sizes sizeStats
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, sizes, fmt.Errorf("osv: %s all.zip: %w", b, err)
	}
	defer func() { _ = zr.Close() }()
	var out []recKey
	for _, zf := range zr.File {
		if err := ctx.Err(); err != nil {
			return out, sizes, err
		}
		id := zipEntryID(b, zf, want)
		if id == "" {
			continue
		}
		raw, err := readEntry(zf)
		if errors.Is(err, feeds.ErrTooLarge) {
			logr.FromContextOrDiscard(ctx).Info("skipping an oversized OSV record", "bucket", b, "id", id)
			continue
		}
		if err != nil {
			return out, sizes, fmt.Errorf("osv: %s all.zip %s: %w", b, zf.Name, err)
		}
		sizes.add(len(raw))
		res, err := f.put(ctx, b, id, raw, gitCached)
		if err != nil {
			return out, sizes, err
		}
		if res == putChanged || res == putDropped || (want == nil && res == putUnchanged) {
			out = append(out, recKey{b, id})
		}
	}
	return out, sizes, nil
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

// bootstrap loads all of Go or GIT from all.zip (GIT filtered to GitRepos) and hands off every kept
// record, and, on a GIT reload, every cached one the filter now drops. The watermark is the newest
// modified_id.csv row read before the download, or now for an empty listing, so polling resumes
// with nothing missed.
func (f *Feed) bootstrap(ctx context.Context, st *store.FeedState, b string) error {
	now := f.o.Now().UTC()
	rd := newCSVReader(f.o.HTTP, f.bucketURL(b, "modified_id.csv"))
	rows, err := rd.next(ctx)
	if err != nil {
		return err
	}
	wm := now
	if len(rows) > 0 {
		wm = rows[0].ts
	}
	gitCached, err := f.gitCached(ctx, b)
	if err != nil {
		return err
	}
	path, err := f.downloadZip(ctx, b)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(path) }()
	keys, _, err := f.storeZip(ctx, b, path, nil, gitCached)
	if err != nil {
		return err
	}
	// The load is complete: record it with the records pending in one write, so a handler failure
	// redelivers them without downloading all.zip again.
	st.Meta[metaBootstrap+b] = now.Format(time.RFC3339)
	st.Meta[metaWatermark+b] = wm.Format(time.RFC3339Nano)
	setMeta(st, metaGeneration+b, rd.gen)
	if b == BucketGIT {
		st.Meta[metaGitRepos] = f.reposKey
	}
	if err := f.handOff(ctx, st, keys); err != nil {
		return err
	}
	return f.save(ctx, st)
}

// handOff records keys as pending and delivers them; on success it clears pending (the caller
// saves). With no keys it only clears pending.
func (f *Feed) handOff(ctx context.Context, st *store.FeedState, keys []recKey) error {
	if len(keys) > 0 {
		setPending(st, keys)
		if err := f.save(ctx, st); err != nil {
			return err
		}
		if err := f.deliverKeys(ctx, keys, false); err != nil {
			return err
		}
	}
	feeds.SetPending(st, nil)
	return nil
}

// deliverKeys hands the cached records of keys to the handler in chunks of 500, skipping records no
// longer cached. With refreshNames it first rewrites each record's index names. A GIT record that
// references no GitRepos repository is a drop (see put): once the handler has taken it, it is
// deleted from the cache. Deciding this from the cached raw lets a redelivery finish a drop.
func (f *Feed) deliverKeys(ctx context.Context, keys []recKey, refreshNames bool) error {
	for chunk := range slices.Chunk(keys, handlerChunk) {
		ids := make([]string, len(chunk))
		for i, k := range chunk {
			ids[i] = k.id
		}
		raws, err := f.o.Store.OSVRecordsByID(ctx, ids)
		if err != nil {
			return err
		}
		byID := make(map[string]recordInfo, len(raws))
		rawByID := make(map[string][]byte, len(raws))
		for _, raw := range raws {
			if info, err := parseRecord(raw); err == nil {
				byID[info.ID], rawByID[info.ID] = info, raw
			}
		}
		recs := make([]Changed, 0, len(chunk))
		var drops []string
		for _, k := range chunk {
			raw, ok := rawByID[k.id]
			if !ok {
				continue
			}
			info := byID[k.id]
			drop := k.bucket == BucketGIT && !f.tracked(info)
			if drop {
				drops = append(drops, k.id)
			}
			if refreshNames {
				var names []string
				if !drop {
					names = info.names(k.bucket)
				}
				if err := f.o.Store.PutOSVRecordNames(ctx, k.bucket, k.id, names); err != nil {
					return err
				}
			}
			recs = append(recs, Changed{Ecosystem: k.bucket, ID: k.id, Raw: raw})
		}
		if err := f.deliver(ctx, recs); err != nil {
			return err
		}
		if len(drops) > 0 {
			if err := f.o.Store.DeleteOSVRecords(ctx, BucketGIT, drops); err != nil {
				return err
			}
		}
	}
	return nil
}

// deliver calls the handler with recs in chunks of 500.
func (f *Feed) deliver(ctx context.Context, recs []Changed) error {
	for chunk := range slices.Chunk(recs, handlerChunk) {
		if err := f.o.Handler(ctx, chunk); err != nil {
			return fmt.Errorf("osv: handler: %w", err)
		}
	}
	return nil
}

// setDiff runs weekly. It reads each polled bucket's whole modified_id.csv and withdraws the cached
// records no longer listed: each is delivered with a "withdrawn" time (unless it is still cached and
// listed in another polled bucket, whose copy is delivered instead), then removed from the cache.
func (f *Feed) setDiff(ctx context.Context, st *store.FeedState, buckets []string) error {
	now := f.o.Now().UTC()
	if last, err := time.Parse(time.RFC3339, st.Meta[metaSetDiff]); err == nil && now.Sub(last) < setDiffInterval {
		return nil
	}
	log := logr.FromContextOrDiscard(ctx)
	cached := map[string]map[string]bool{} // bucket → cached IDs still listed
	vanished := map[string][]string{}
	for _, b := range buckets {
		ids, err := f.o.Store.OSVRecordIDs(ctx, b)
		if err != nil {
			return err
		}
		if len(ids) == 0 {
			continue
		}
		listed, err := listIDs(ctx, f.o.HTTP, f.bucketURL(b, "modified_id.csv"))
		if err != nil {
			return fmt.Errorf("osv: set-diff %s: %w", b, err)
		}
		if len(listed) == 0 { // an empty listing is a broken mirror, not a mass withdrawal
			log.Info("OSV bucket listing is empty; not withdrawing its cached records", "bucket", b)
			continue
		}
		cached[b] = map[string]bool{}
		for _, id := range ids {
			if listed[id] {
				cached[b][id] = true
			} else {
				vanished[b] = append(vanished[b], id)
			}
		}
	}

	var recs []Changed
	for _, b := range slices.Sorted(maps.Keys(vanished)) {
		raws, err := f.o.Store.OSVRecordsByID(ctx, vanished[b])
		if err != nil {
			return err
		}
		for _, raw := range raws {
			info, err := parseRecord(raw)
			if err != nil {
				continue
			}
			if other := listedElsewhere(cached, b, info.ID); other != "" {
				recs = append(recs, Changed{Ecosystem: other, ID: info.ID, Raw: raw})
				continue
			}
			w, err := withdraw(raw, now)
			if err != nil {
				continue
			}
			recs = append(recs, Changed{Ecosystem: b, ID: info.ID, Raw: w})
		}
	}
	if err := f.deliver(ctx, recs); err != nil {
		return err
	}
	for b, ids := range vanished {
		if err := f.o.Store.DeleteOSVRecords(ctx, b, ids); err != nil {
			return err
		}
	}
	st.Meta[metaSetDiff] = now.Format(time.RFC3339)
	return f.save(ctx, st)
}

// listedElsewhere returns a bucket other than b that still caches and lists id, or "".
func listedElsewhere(cached map[string]map[string]bool, b, id string) string {
	for _, other := range slices.Sorted(maps.Keys(cached)) {
		if other != b && cached[other][id] {
			return other
		}
	}
	return ""
}

// withdraw returns raw with a top-level "withdrawn" of now, unless it already has one.
func withdraw(raw []byte, now time.Time) ([]byte, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	if _, ok := m["withdrawn"]; ok {
		return raw, nil
	}
	ts, err := json.Marshal(now.Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	m["withdrawn"] = ts
	return json.Marshal(m)
}

// prune drops records older than the retention from every bucket except Go and GIT, whose cache is
// loaded whole and kept.
func (f *Feed) prune(ctx context.Context) error {
	cutoff := f.o.Now().UTC().Add(-retention)
	for _, b := range knownBuckets() {
		if b == BucketGo || b == BucketGIT {
			continue
		}
		if _, err := f.o.Store.PruneOSVRecords(ctx, b, cutoff); err != nil {
			return fmt.Errorf("osv: prune %s: %w", b, err)
		}
	}
	return nil
}

func (f *Feed) bucketURL(b, file string) string {
	return f.base + "/" + url.PathEscape(b) + "/" + url.PathEscape(file)
}

// setPending stores keys as the feed's pending records.
func setPending(st *store.FeedState, keys []recKey) {
	s := make([]string, len(keys))
	for i, k := range keys {
		s[i] = k.String()
	}
	feeds.SetPending(st, s)
}

// setMeta sets st.Meta[k] to v, deleting the key when v is empty.
func setMeta(st *store.FeedState, k, v string) {
	if v == "" {
		delete(st.Meta, k)
		return
	}
	st.Meta[k] = v
}
