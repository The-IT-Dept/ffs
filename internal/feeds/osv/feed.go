// Package osv is the fast path for new and changed advisories. It polls the OSV.dev bucket for the
// ecosystems present in the inventory (plus Go and GIT), reads each bucket's modified_id.csv down
// to its watermark, caches the changed records locally and hands a record to the handler only when
// its affected set, aliases or withdrawn time changed: most modifications only touch timestamps.
// A cached GIT record that stops referencing the GitRepos repositories is handed off once more
// and then dropped from the cache. A weekly set-diff withdraws records that left the bucket, and
// records outside Go and GIT are pruned after 14 days unless the osv source still matches them.
// Malicious-package records (MAL-) are the exception: the Grype DB carries none, so each language
// bucket loads all of its MAL- records once and keeps them.
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
	"iter"
	"maps"
	"net/http"
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

	metaWatermark   = "wm."        // + bucket: RFC 3339 time of the newest row handed off
	metaGeneration  = "gen."       // + bucket: x-goog-generation of modified_id.csv when last read
	metaBootstrap   = "boot."      // + bucket (Go, GIT): when all.zip was loaded
	metaRecordBytes = "size."      // + bucket: average uncompressed size of its records, measured
	metaMalicious   = "mal."       // + language bucket: when all of its MAL- records were loaded
	metaZipBehind   = "zipbehind." // + bucket: when its all.zip was first seen older than modified_id.csv
	metaGitRepos    = "repos.GIT"
	metaSetDiff     = "setdiff"
)

// handlerBytes bounds the uncompressed records of one handler call and of one read of cached records
// for it: the record matchers parse every record of a call, and an Ubuntu record averages over
// 400 KB, so 500 of them took gigabytes.
const handlerBytes = 16 << 20

// zipBehindWait is how long polls of a bucket wait for its all.zip to catch up with its
// modified_id.csv. The OSV exporter uploads all.zip seconds after the listing; a zip still behind
// after this (a mirror that refreshes it less often) is read anyway, and what it lacks is read one
// record at a time.
const zipBehindWait = 30 * time.Minute

// errZipBehind means a bucket's all.zip is older than the modified_id.csv being polled: the poll
// waits for the next one rather than read records the zip may not hold yet.
var errZipBehind = errors.New("osv: all.zip is older than modified_id.csv")

// maxZipBytes bounds a download of all of all.zip. A bigger one is read with Range requests or one
// GET per record instead. A variable so tests can lower it.
var maxZipBytes int64 = 1 << 30

// Changed is a new or changed OSV record. Ecosystem is the bucket it came from ("Debian", "PyPI",
// "Go", "GIT", ...).
type Changed struct {
	Ecosystem, ID string
	Raw           []byte
}

// Handler consumes changed records, at most 500 and about 16 MiB of them per call. Until it returns
// nil the records stay pending and the next Sync offers them again.
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
	objects  objectBase
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
	f := &Feed{o: o, objects: parseObjectBase(o.Config.URL), gitRepos: make(map[string]bool, len(o.GitRepos))}
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
		if err == nil && needsMalicious(st, b) {
			err = f.loadMalicious(ctx, &st, b)
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

// needsMalicious reports whether b is a language bucket whose MAL- records have not been loaded.
// Go is loaded whole by its bootstrap.
func needsMalicious(st store.FeedState, b string) bool {
	return b != BucketGo && languageBuckets[bucketSyftTypes[b]] == b && st.Meta[metaMalicious+b] == ""
}

// loadMalicious caches every MAL- record that b's modified_id.csv lists and the cache lacks, and
// hands them off. Polls only reach back to the first poll's window and other records are pruned, but
// a known-malicious package version stays dangerous however old its record is (spec §6.4), and the
// Grype DB has no MAL- records. It runs once per bucket; pruning keeps MAL- records.
func (f *Feed) loadMalicious(ctx context.Context, st *store.FeedState, b string) error {
	listed, err := listIDs(ctx, f.o.HTTP, f.bucketURL(b, "modified_id.csv"))
	if err != nil {
		return err
	}
	cached, err := f.o.Store.OSVRecordIDs(ctx, b)
	if err != nil {
		return err
	}
	have := make(map[string]bool, len(cached))
	for _, id := range cached {
		have[id] = true
	}
	want := map[string]time.Time{}
	for id, modified := range listed {
		if strings.HasPrefix(id, "MAL-") && !have[id] {
			want[id] = modified
		}
	}
	changed, takeErr := f.take(ctx, st, b, want, "")
	if takeErr == nil {
		// Every record is cached and the changed ones are pending (see handOff), in the same write.
		st.Meta[metaMalicious+b] = f.o.Now().UTC().Format(time.RFC3339)
	}
	if err := f.handOff(ctx, st, changed); err != nil {
		return errors.Join(takeErr, err)
	}
	if takeErr != nil { // not marked loaded: the next Sync takes the rest
		return errors.Join(takeErr, f.save(ctx, st))
	}
	return f.save(ctx, st)
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
	if err := f.deliverKeys(ctx, st, keys, true); err != nil {
		return err
	}
	feeds.SetPending(st, nil)
	return f.save(ctx, st)
}

// poll reads b's modified_id.csv down to the watermark and hands off the records whose affected
// set changed. Once every listed record is cached, the watermark and generation advance in the same
// write that records the changed ones as pending, before they are handed off: a hand-off cut short
// resumes from pending (redeliver) instead of reading the backlog again.
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
	want := map[string]time.Time{} // ID → modified time of its newest row
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
			if _, dup := want[row.id]; row.id == "" || SkipID(b, row.id) || dup {
				continue
			}
			want[row.id] = row.ts
		}
		if stop || rd.done {
			break
		}
		if rows, err = rd.next(ctx); err != nil {
			return err
		}
	}

	changed, takeErr := f.take(ctx, st, b, want, rd.gen)
	if errors.Is(takeErr, errZipBehind) { // nothing taken; the listing is read again next time
		logr.FromContextOrDiscard(ctx).V(1).Info("OSV all.zip is older than modified_id.csv; polling again next time", "bucket", b)
		return f.save(ctx, st)
	}
	if takeErr == nil {
		if newest.After(wm) {
			st.Meta[metaWatermark+b] = newest.Format(time.RFC3339Nano)
		}
		setMeta(st, metaGeneration+b, rd.gen)
		delete(st.Meta, metaZipBehind+b)
	}
	if err := f.handOff(ctx, st, changed); err != nil {
		return errors.Join(takeErr, err)
	}
	if takeErr != nil { // the watermark stays, so the rest is read again next time
		return errors.Join(takeErr, f.save(ctx, st))
	}
	return f.save(ctx, st)
}

// watermark returns b's watermark, or now − 72h before its first poll.
func (f *Feed) watermark(st store.FeedState, b string) time.Time {
	if t, err := time.Parse(time.RFC3339Nano, st.Meta[metaWatermark+b]); err == nil {
		return t
	}
	return f.o.Now().UTC().Add(-firstPollWindow)
}

// take fetches and caches the records of b that want names, returning the ones to hand off: those
// whose affected hash changed and dropped GIT records (see put); on an error, those so far, which
// the caller still hands off. want maps each ID to the modified time modified_id.csv lists for it
// (zero: not known). It reads them the cheapest way (see choose): one GET each, Range reads of
// their entries in all.zip, or all of all.zip. all.zip can be an export older than the listing, so
// an entry older than its listed time, or a listed record the zip lacks, is then read with one GET:
// record files are uploaded before the listing. When csvGen and the zip's generation show the zip
// is older than the listing, take returns errZipBehind instead, having read nothing, until the zip
// has been behind for zipBehindWait (see plan). Every candidate is pending while the cache is
// written, so a crash between a record's write and its hand-off cannot lose it.
func (f *Feed) take(ctx context.Context, st *store.FeedState, b string, want map[string]time.Time, csvGen string) ([]recKey, error) {
	if len(want) == 0 {
		return nil, nil
	}
	ids := slices.Sorted(maps.Keys(want))
	gitCached, err := f.gitCached(ctx, b)
	if err != nil {
		return nil, err
	}
	how, probe, err := f.plan(ctx, st, b, len(ids), csvGen)
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

	var (
		out    []recKey
		stats  readStats
		behind []string // listed records the zip held only an older version of, or lacked
	)
	switch how {
	case wholeZip:
		var path string
		if path, err = f.downloadZip(ctx, b); err != nil {
			return nil, err
		}
		defer func() { _ = os.Remove(path) }()
		out, stats, behind, err = f.storeZip(ctx, b, path, want, gitCached)
	case rangedZip:
		out, stats, behind, err = f.storeRanged(ctx, b, probe, want, gitCached)
	default:
		out, stats, err = f.storeRecords(ctx, b, ids, gitCached)
	}
	if err == nil && len(behind) > 0 {
		logr.FromContextOrDiscard(ctx).Info("OSV all.zip is older than modified_id.csv for some records; reading them one at a time",
			"bucket", b, "records", len(behind))
		var (
			more  []recKey
			extra readStats
		)
		more, extra, err = f.storeRecords(ctx, b, behind, gitCached)
		out = append(out, more...)
		stats.n, stats.bytes = stats.n+extra.n, stats.bytes+extra.bytes
	}
	learnRecordBytes(st, b, stats)
	return out, err
}

// zipBehind reports whether all.zip, of version zipVersion, is known to be older than the
// modified_id.csv of generation csvGen: both are GCS generations (object creation times in
// microseconds) and the zip's is the smaller. A version that is not a generation (an ETag) proves
// nothing.
func zipBehind(zipVersion, csvGen string) bool {
	z, zerr := strconv.ParseInt(zipVersion, 10, 64)
	c, cerr := strconv.ParseInt(csvGen, 10, 64)
	return zerr == nil && cerr == nil && z < c
}

// plan picks how take reads n records of b. all.zip is probed only when one GET per record looks
// expensive; a bucket without all.zip is read one GET per record. A zip older than the listing of
// generation csvGen (see zipBehind) gives errZipBehind, until it has been behind for zipBehindWait.
func (f *Feed) plan(ctx context.Context, st *store.FeedState, b string, n int, csvGen string) (transport, zipProbe, error) {
	recordBytes := recordBytesOf(*st, b)
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
	if zipBehind(p.version, csvGen) {
		now := f.o.Now().UTC()
		since, err := time.Parse(time.RFC3339, st.Meta[metaZipBehind+b])
		if err != nil {
			since = now
			st.Meta[metaZipBehind+b] = now.Format(time.RFC3339)
		}
		if now.Sub(since) < zipBehindWait {
			return perRecord, p, errZipBehind
		}
	}
	how := choose(n, recordBytes, p)
	logr.FromContextOrDiscard(ctx).V(1).Info("reading OSV records", "bucket", b, "records", n, "transport", how.String(),
		"recordBytes", recordBytes, "zipBytes", p.size, "rangeReads", p.ranged)
	return how, p, nil
}

// readStats sums the uncompressed sizes of the records a take read, and keeps the newest modified
// time among them.
type readStats struct {
	n, bytes int64
	newest   time.Time
}

func (s *readStats) add(n int, modified time.Time) {
	s.n, s.bytes = s.n+1, s.bytes+int64(n)
	if modified.After(s.newest) {
		s.newest = modified
	}
}

// recordBytesOf returns the measured average record size of b, or defaultRecordBytes.
func recordBytesOf(st store.FeedState, b string) int64 {
	if v, err := strconv.ParseInt(st.Meta[metaRecordBytes+b], 10, 64); err == nil && v > 0 {
		return v
	}
	return defaultRecordBytes
}

// learnRecordBytes folds the sizes a take read into b's average, weighting a read of 100 records or
// more fully. The caller saves st.
func learnRecordBytes(st *store.FeedState, b string, s readStats) {
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
func (f *Feed) storeRecords(ctx context.Context, b string, ids []string, gitCached map[string]bool) ([]recKey, readStats, error) {
	var (
		out   []recKey
		sizes readStats
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
			res, modified, err := f.put(ctx, b, chunk[i], raw, gitCached, time.Time{})
			sizes.add(len(raw), modified)
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
// rangedChunk at a time, and caches each (see put). It also returns, sorted, the IDs want names
// that the zip lacks or holds only in a version older than want's time (see put).
func (f *Feed) storeRanged(ctx context.Context, b string, p zipProbe, want map[string]time.Time, gitCached map[string]bool) ([]recKey, readStats, []string, error) {
	log := logr.FromContextOrDiscard(ctx)
	var sizes readStats
	z, err := openRemoteZip(ctx, f.o.HTTP, f.bucketURL(b, "all.zip"), p)
	if err != nil {
		return nil, sizes, nil, err
	}
	var files []*zip.File
	found := make(map[string]bool, len(want))
	for _, zf := range z.zr.File {
		id := zipEntryID(b, zf, want)
		switch {
		case id == "":
		case zf.UncompressedSize64 > maxRecordBytes:
			found[id] = true
			log.Info("skipping an oversized OSV record", "bucket", b, "id", id)
		default:
			found[id] = true
			files = append(files, zf)
		}
	}
	var (
		out    []recKey
		behind []string
	)
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
			return out, sizes, nil, fmt.Errorf("osv: %s all.zip: %w", b, err)
		}
		for i, raw := range raws {
			id := strings.TrimSuffix(chunk[i].Name, ".json")
			res, modified, err := f.put(ctx, b, id, raw, gitCached, want[id])
			sizes.add(len(raw), modified)
			if err != nil {
				return out, sizes, nil, err
			}
			switch res {
			case putChanged, putDropped:
				out = append(out, recKey{b, id})
			case putStale:
				behind = append(behind, id)
			}
		}
	}
	return out, sizes, lacking(want, found, behind), nil
}

// lacking returns behind plus the IDs want names that found does not, sorted.
func lacking(want map[string]time.Time, found map[string]bool, behind []string) []string {
	for id := range want {
		if !found[id] {
			behind = append(behind, id)
		}
	}
	slices.Sort(behind)
	return behind
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
	putStale                      // older than the version the listing names: not cached
)

// put caches one record of b and returns its modified time. A record older than notBefore (when
// set: the time modified_id.csv lists for it, compared to the second) is an older version than the
// listing names, read from an all.zip behind it: it is not cached (putStale), and the caller reads
// the record again directly. A GIT record that references no GitRepos repository is skipped,
// unless the GIT cache holds it (gitCached): its repository mapping changed, and the cached copy
// would keep matching the old repository for good. The new raw then replaces the cached one with
// no index names, and deliverKeys hands it off and deletes it from the cache.
func (f *Feed) put(ctx context.Context, b, id string, raw []byte, gitCached map[string]bool, notBefore time.Time) (putResult, time.Time, error) {
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
		return putSkipped, time.Time{}, nil
	}
	modified := info.modified(f.o.Now().UTC())
	if !notBefore.IsZero() && modified.Truncate(time.Second).Before(notBefore.Truncate(time.Second)) {
		return putStale, modified, nil
	}
	if b == BucketGIT && !f.tracked(info) {
		if !gitCached[id] {
			return putSkipped, modified, nil
		}
		if _, err := f.o.Store.PutOSVRecord(ctx, b, id, modified, hash, raw); err != nil {
			return putSkipped, modified, err
		}
		return putDropped, modified, f.o.Store.PutOSVRecordNames(ctx, b, id, nil)
	}
	changed, err := f.o.Store.PutOSVRecord(ctx, b, id, modified, hash, raw)
	switch {
	case err != nil:
		return putSkipped, modified, err
	case !changed:
		return putUnchanged, modified, nil
	}
	return putChanged, modified, f.o.Store.PutOSVRecordNames(ctx, b, id, info.names(b))
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
func zipEntryID(b string, zf *zip.File, want map[string]time.Time) string {
	id, ok := strings.CutSuffix(zf.Name, ".json")
	if !ok || id == "" || strings.ContainsAny(zf.Name, `/\`) || !zf.Mode().IsRegular() || SkipID(b, id) {
		return ""
	}
	if _, wanted := want[id]; want != nil && !wanted {
		return ""
	}
	return id
}

// storeZip caches the records in the all.zip at path: those named in want, or every record when
// want is nil. It returns the records to hand off: the changed and dropped ones (see put), or with
// want nil (a bootstrap, which may be re-running after a crash) every cached one, including on an
// error those so far. With want set it also returns, sorted, the IDs want names that the zip lacks
// or holds only in a version older than want's time (see put). Entries other than plain
// "<id>.json" files of at most 4 MiB are ignored.
func (f *Feed) storeZip(ctx context.Context, b, path string, want map[string]time.Time, gitCached map[string]bool) ([]recKey, readStats, []string, error) {
	var sizes readStats
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, sizes, nil, fmt.Errorf("osv: %s all.zip: %w", b, err)
	}
	defer func() { _ = zr.Close() }()
	var (
		out    []recKey
		behind []string
	)
	found := make(map[string]bool, len(want))
	for _, zf := range zr.File {
		if err := ctx.Err(); err != nil {
			return out, sizes, nil, err
		}
		id := zipEntryID(b, zf, want)
		if id == "" {
			continue
		}
		found[id] = true
		raw, err := readEntry(zf)
		if errors.Is(err, feeds.ErrTooLarge) {
			logr.FromContextOrDiscard(ctx).Info("skipping an oversized OSV record", "bucket", b, "id", id)
			continue
		}
		if err != nil {
			return out, sizes, nil, fmt.Errorf("osv: %s all.zip %s: %w", b, zf.Name, err)
		}
		res, modified, err := f.put(ctx, b, id, raw, gitCached, want[id])
		sizes.add(len(raw), modified)
		if err != nil {
			return out, sizes, nil, err
		}
		switch {
		case res == putChanged || res == putDropped || (want == nil && res == putUnchanged):
			out = append(out, recKey{b, id})
		case res == putStale:
			behind = append(behind, id)
		}
	}
	if want == nil {
		return out, sizes, nil, nil
	}
	return out, sizes, lacking(want, found, behind), nil
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
// with nothing missed. all.zip can be an export older than that listing (the exporter uploads it
// after modified_id.csv): the watermark is then the newest record the zip held, and the listing's
// generation is not recorded, so the next poll reads what the zip lacked.
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
	keys, read, _, err := f.storeZip(ctx, b, path, nil, gitCached)
	if err != nil {
		return err
	}
	gen := rd.gen
	if !read.newest.IsZero() && read.newest.Before(wm) {
		wm, gen = read.newest, ""
	}
	// The load is complete: record it with the records pending in one write, so a handler failure
	// redelivers them without downloading all.zip again.
	st.Meta[metaBootstrap+b] = now.Format(time.RFC3339)
	st.Meta[metaWatermark+b] = wm.Format(time.RFC3339Nano)
	setMeta(st, metaGeneration+b, gen)
	if b == BucketGIT {
		st.Meta[metaGitRepos] = f.reposKey
	}
	if err := f.handOff(ctx, st, keys); err != nil {
		return err
	}
	return f.save(ctx, st)
}

// handOff records keys as pending, with whatever else st holds, and delivers them; on success it
// clears pending (the caller saves). With no keys it only clears pending.
func (f *Feed) handOff(ctx context.Context, st *store.FeedState, keys []recKey) error {
	if len(keys) > 0 {
		setPending(st, keys)
		if err := f.save(ctx, st); err != nil {
			return err
		}
		if err := f.deliverKeys(ctx, st, keys, false); err != nil {
			return err
		}
	}
	feeds.SetPending(st, nil)
	return nil
}

// deliverKeys hands the cached records of keys, which st holds as pending, to the handler in chunks
// (see keyChunks), skipping records no longer cached. Once the handler has taken a chunk, pending is cut to
// the keys after it and saved, so a failure part-way loses none of the progress before it. With
// refreshNames it first rewrites each record's index names. A GIT record that references no
// GitRepos repository is a drop (see put): once the handler has taken it, it is deleted from the
// cache. Deciding this from the cached raw lets a redelivery finish a drop.
func (f *Feed) deliverKeys(ctx context.Context, st *store.FeedState, keys []recKey, refreshNames bool) error {
	done := 0
	for chunk := range keyChunks(*st, keys) {
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
		done += len(chunk)
		setPending(st, keys[done:])
		if err := f.save(ctx, st); err != nil {
			return err
		}
	}
	return nil
}

// deliver calls the handler with recs in chunks of at most 500 records and handlerBytes, except
// that a single larger record is a chunk of its own.
func (f *Feed) deliver(ctx context.Context, recs []Changed) error {
	for len(recs) > 0 {
		n, size := 0, 0
		for n < len(recs) && n < handlerChunk && (n == 0 || size+len(recs[n].Raw) <= handlerBytes) {
			size += len(recs[n].Raw)
			n++
		}
		if err := f.o.Handler(ctx, recs[:n]); err != nil {
			return fmt.Errorf("osv: handler: %w", err)
		}
		recs = recs[n:]
	}
	return nil
}

// keyChunks splits keys into consecutive chunks of at most 500 keys whose records are estimated, at
// their bucket's measured average size (see recordBytesOf), to total at most handlerBytes; a chunk
// always holds at least one key.
func keyChunks(st store.FeedState, keys []recKey) iter.Seq[[]recKey] {
	return func(yield func([]recKey) bool) {
		avg := map[string]int64{}
		for len(keys) > 0 {
			n, size := 0, int64(0)
			for n < len(keys) && n < handlerChunk {
				b := keys[n].bucket
				if _, ok := avg[b]; !ok {
					avg[b] = recordBytesOf(st, b)
				}
				if n > 0 && size+avg[b] > handlerBytes {
					break
				}
				size += avg[b]
				n++
			}
			if !yield(keys[:n:n]) {
				return
			}
			keys = keys[n:]
		}
	}
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
			if _, ok := listed[id]; ok {
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
// loaded whole and kept. The store keeps MAL- records (see loadMalicious).
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

// bucketURL returns the URL of file in bucket b. Every object the feed reads is named through it.
func (f *Feed) bucketURL(b, file string) string { return f.objects.url(b, file) }

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
