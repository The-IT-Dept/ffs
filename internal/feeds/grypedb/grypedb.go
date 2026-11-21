// Package grypedb keeps the Grype vulnerability database current: it polls latest.json, downloads
// and verifies a new build, installs it beside the current one, diffs the two (or, in a small
// cluster, skips the diff for a full re-match) and hands the result to a handler before making the
// new build current.
package grypedb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/go-logr/logr"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/feeds"
	"github.com/the-it-dept/ffs/internal/store"
	"github.com/the-it-dept/ffs/internal/version"
)

var (
	// ErrChecksum means the downloaded archive does not match the sha256 in latest.json.
	ErrChecksum = errors.New("grypedb: archive checksum mismatch")
	// ErrUnsafeArchive means the archive holds an entry other than the expected regular files.
	ErrUnsafeArchive = errors.New("grypedb: unsafe archive entry")
)

// DefaultURL is the latest.json listing used when Config.URL is empty.
const DefaultURL = "https://grype.anchore.io/databases/v6/latest.json"

const (
	maxListingBytes int64 = 1 << 20
	maxArchiveBytes int64 = 1 << 30
	fullInterval          = 7 * 24 * time.Hour
	dirLayout             = "20060102T150405Z"
	downloadDir           = ".download"
	stagingDir            = ".staging"
	diffOldDir            = ".diff-old"
	metaCurrent           = "current"
	metaLastFull          = "lastFull"
)

var checksumRE = regexp.MustCompile(`^sha256:[0-9a-fA-F]{64}$`)

// PackageKey is a package whose vulnerability records changed between two builds. Both fields are
// lowercased; Ecosystem "cpe" means Name is a CPE product.
type PackageKey struct{ Ecosystem, Name string }

// Update describes a newly installed build.
type Update struct {
	Path    string // DB directory holding vulnerability.db
	Built   time.Time
	Changed []PackageKey // packages whose records changed since the previous build; empty when Full
	// Full re-matches everything: on the first install, when the last full re-match is over 7 days
	// old, and when fewer SBOMs are catalogued than Options.DiffMinImages.
	Full bool
}

// Handler consumes an Update. Until it returns nil the build is not current and the next Sync
// offers it again.
type Handler func(ctx context.Context, u Update) error

// Options configures a Feed.
type Options struct {
	Config  config.FeedConfig
	DataDir string // the DB directories live in DataDir/grypedb
	Store   *store.Store
	HTTP    *http.Client // nil = feeds.NewHTTPClient(version.UserAgent())
	Handler Handler
	Now     func() time.Time // nil = time.Now
	// Diff diffs a copy of the current build against a new one; nil diffs in this process (Diff).
	// The controller passes ExecDiffer.
	Diff Differ
	// DiffMinImages is the number of catalogued SBOMs (store.CataloguedLiveSBOMs) below which a new
	// build is a full re-match instead of a diff: re-matching a few images costs less than the diff.
	// 0 always diffs.
	DiffMinImages int
}

// Feed is the Grype DB feed. It implements feeds.Feed.
type Feed struct {
	o    Options
	root string
}

// New returns the Grype DB feed.
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
	if o.Diff == nil {
		o.Diff = Diff
	}
	return &Feed{o: o, root: filepath.Join(o.DataDir, "grypedb")}
}

// Name implements feeds.Feed.
func (f *Feed) Name() string { return feeds.NameGrypeDB }

// Interval implements feeds.Feed.
func (f *Feed) Interval() time.Duration { return f.o.Config.Interval }

// StaleAfter implements feeds.Feed.
func (f *Feed) StaleAfter() time.Duration { return f.o.Config.StaleAfter }

// Current returns the installed build, if any.
func (f *Feed) Current(ctx context.Context) (path string, built time.Time, ok bool, err error) {
	st, err := f.o.Store.FeedState(ctx, feeds.NameGrypeDB)
	if err != nil {
		return "", time.Time{}, false, err
	}
	name := st.Meta[metaCurrent]
	if name == "" {
		return "", time.Time{}, false, nil
	}
	path = filepath.Join(f.root, name)
	if _, err := os.Stat(filepath.Join(path, v6.VulnerabilityDBFileName)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", time.Time{}, false, nil
		}
		return "", time.Time{}, false, err
	}
	built, err = time.Parse(time.RFC3339, st.Watermark)
	if err != nil {
		return "", time.Time{}, false, fmt.Errorf("grypedb: watermark %q: %w", st.Watermark, err)
	}
	return path, built, true, nil
}

// listing is the subset of latest.json that ffs reads.
type listing struct {
	Status        string    `json:"status"`
	SchemaVersion string    `json:"schemaVersion"`
	Built         time.Time `json:"built"`
	Path          string    `json:"path"`
	Checksum      string    `json:"checksum"`
}

func (l listing) validate() error {
	switch {
	case !strings.HasPrefix(l.SchemaVersion, "v6."):
		return fmt.Errorf("grypedb: latest.json schemaVersion %q is not v6", l.SchemaVersion)
	case !checksumRE.MatchString(l.Checksum):
		return fmt.Errorf("grypedb: latest.json checksum %q is not sha256:<64 hex>", l.Checksum)
	case l.Path == "" || l.Path == "." || strings.ContainsAny(l.Path, `/\`) || strings.Contains(l.Path, ".."):
		return fmt.Errorf("grypedb: latest.json path %q is not a plain file name", l.Path)
	case l.Built.IsZero():
		return errors.New("grypedb: latest.json has no built time")
	}
	return nil
}

// Sync installs the build named by latest.json when it is newer than the current one.
func (f *Feed) Sync(ctx context.Context) error {
	l, err := f.fetchListing(ctx)
	if err != nil {
		return err
	}
	st, err := f.o.Store.FeedState(ctx, feeds.NameGrypeDB)
	if err != nil {
		return err
	}
	if wm, _ := time.Parse(time.RFC3339, st.Watermark); !l.Built.After(wm) && len(feeds.Pending(st)) == 0 {
		return nil
	}

	current := st.Meta[metaCurrent]
	if current != "" && !hasDB(filepath.Join(f.root, current)) {
		current = "" // recorded but gone from disk: install as if first
	}
	name := l.Built.Format(dirLayout)
	newDir := filepath.Join(f.root, name)
	if err := f.prune(current, name); err != nil {
		return err
	}
	// newDir only ever appears by renaming a fully extracted and hydrated staging directory, so an
	// existing one is a complete build whose handler failed: offer it again without downloading.
	if !hasDB(newDir) {
		if err := f.install(ctx, l, newDir); err != nil {
			return err
		}
	}

	lastFull, _ := time.Parse(time.RFC3339, st.Meta[metaLastFull])
	u := Update{Path: newDir, Built: l.Built, Full: current == "" || f.o.Now().Sub(lastFull) > fullInterval}
	// A full re-match ignores Changed, and the diff of two production builds takes minutes and
	// gigabytes of SQLite temp space: run it only when its result is used, and not when re-matching
	// every SBOM costs less.
	if !u.Full && current != name {
		if u.Full, err = f.fewSBOMs(ctx); err != nil {
			return err
		}
	}
	if !u.Full && current != name {
		if u.Changed, err = f.changedPackages(ctx, filepath.Join(f.root, current), newDir); err != nil {
			return err
		}
	}

	feeds.SetPending(&st, []string{l.Built.Format(time.RFC3339)})
	if err := f.o.Store.PutFeedState(ctx, st); err != nil {
		return err
	}
	if err := f.o.Handler(ctx, u); err != nil {
		return fmt.Errorf("grypedb: handler for build %s: %w", l.Built.Format(time.RFC3339), err)
	}

	st.Watermark = l.Built.Format(time.RFC3339)
	if st.Meta == nil {
		st.Meta = map[string]string{}
	}
	st.Meta[metaCurrent] = name
	if u.Full {
		st.Meta[metaLastFull] = f.o.Now().UTC().Format(time.RFC3339)
	}
	feeds.SetPending(&st, nil)
	if err := f.o.Store.PutFeedState(ctx, st); err != nil {
		return err
	}
	return f.prune(name, current)
}

func (f *Feed) fetchListing(ctx context.Context) (listing, error) {
	resp, err := feeds.Fetch(ctx, f.o.HTTP, feeds.Request{URL: f.o.Config.URL, MaxBytes: maxListingBytes})
	if err != nil {
		return listing{}, err
	}
	var l listing
	if err := json.Unmarshal(resp.Body, &l); err != nil {
		return listing{}, fmt.Errorf("grypedb: parse latest.json: %w", err)
	}
	if err := l.validate(); err != nil {
		return listing{}, err
	}
	// second resolution, like the RFC 3339 watermark and the directory name, so a fractional built
	// time can never compare newer than its own watermark
	l.Built = l.Built.UTC().Truncate(time.Second)
	if l.Status != "active" {
		logr.FromContextOrDiscard(ctx).Info("Grype DB listing status is not active; installing it anyway",
			"status", l.Status, "built", l.Built)
	}
	return l, nil
}

// install downloads, verifies, extracts and hydrates the listed archive into dir.
func (f *Feed) install(ctx context.Context, l listing, dir string) error {
	archiveURL, err := siblingURL(f.o.Config.URL, l.Path)
	if err != nil {
		return err
	}
	dl := filepath.Join(f.root, downloadDir)
	defer func() { _ = os.RemoveAll(dl) }()
	if err := os.MkdirAll(dl, 0o750); err != nil {
		return err
	}
	archive := filepath.Join(dl, l.Path)
	h := sha256.New()
	if _, err := feeds.Download(ctx, f.o.HTTP, archiveURL, archive, maxArchiveBytes, h); err != nil {
		return err
	}
	want := strings.ToLower(strings.TrimPrefix(l.Checksum, "sha256:"))
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("%w: %s has sha256 %s, latest.json says %s", ErrChecksum, l.Path, got, want)
	}

	staging := filepath.Join(f.root, stagingDir)
	defer func() { _ = os.RemoveAll(staging) }()
	if err := os.RemoveAll(staging); err != nil {
		return err
	}
	if err := os.Mkdir(staging, 0o750); err != nil {
		return err
	}
	err = extract(archive, staging)
	_ = os.Remove(archive)
	if err != nil {
		return err
	}
	if err := v6.Hydrater()(staging); err != nil {
		return fmt.Errorf("grypedb: hydrate: %w", err)
	}
	return os.Rename(staging, dir)
}

// hasDB reports whether dir holds a vulnerability.db.
func hasDB(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, v6.VulnerabilityDBFileName))
	return err == nil
}

// siblingURL replaces the last path element of base with name.
func siblingURL(base, name string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("grypedb: listing URL: %w", err)
	}
	return u.ResolveReference(&url.URL{Path: name}).String(), nil
}

// prune removes every entry under the root except the named directories ("" names nothing).
func (f *Feed) prune(keep ...string) error {
	if err := os.MkdirAll(f.root, 0o750); err != nil {
		return err
	}
	entries, err := os.ReadDir(f.root)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if slices.Contains(keep, e.Name()) {
			continue
		}
		if err := os.RemoveAll(filepath.Join(f.root, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

// minDiffTimeout is the least time a diff gets, as the least the feed runner gives a Sync: a diff of
// two production builds takes tens of minutes (37 at 1.3 cores in issue #7), so twice a short
// interval would cut it off at every update.
const minDiffTimeout = 30 * time.Minute

// diffTimeout is how long a diff of builds polled every iv may take: max(2×iv, 30m), the budget the
// feed runner gives the whole Sync. Under the runner the Sync's own deadline, which started earlier,
// ends first; the diff's binds when Sync is called on its own.
func diffTimeout(iv time.Duration) time.Duration {
	return max(2*iv, minDiffTimeout)
}

// fewSBOMs reports whether fewer SBOMs are catalogued than Options.DiffMinImages, so a new build
// is cheaper to re-match in full than to diff.
func (f *Feed) fewSBOMs(ctx context.Context) (bool, error) {
	if f.o.DiffMinImages <= 0 {
		return false, nil
	}
	n, err := f.o.Store.CataloguedLiveSBOMs(ctx)
	if err != nil {
		return false, fmt.Errorf("grypedb: count the catalogued SBOMs: %w", err)
	}
	if n < f.o.DiffMinImages {
		logr.FromContextOrDiscard(ctx).V(1).Info("re-matching every SBOM with the new Grype DB instead of diffing the builds",
			"sboms", n, "diffMinImages", f.o.DiffMinImages)
		return true, nil
	}
	return false, nil
}

// changedPackages diffs two DB directories with Options.Diff, under diffTimeout, and returns the
// deduplicated, lowercased packages whose vulnerability records were added, removed or modified.
//
// The differ opens both databases for writing first (it hydrates them: migrations and ANALYZE). The
// Grype matcher holds oldDir's database open read-only, and Grype opens every database with SQLite's
// shared cache, which is one cache per file per process: a writable connection to that file in this
// process joins a read-only cache and fails ("attempt to write a readonly database"), and one in
// another process would change the file under the matcher. The diff therefore reads a copy of
// oldDir, on the same volume, removed when it ends (and by prune after a crash). newDir is not open
// in this process until the handler takes the update.
func (f *Feed) changedPackages(ctx context.Context, oldDir, newDir string) ([]PackageKey, error) {
	oldCopy := filepath.Join(f.root, diffOldDir)
	if err := os.RemoveAll(oldCopy); err != nil {
		return nil, fmt.Errorf("grypedb: diff: %w", err)
	}
	defer func() { _ = os.RemoveAll(oldCopy) }()
	if err := os.CopyFS(oldCopy, os.DirFS(oldDir)); err != nil {
		return nil, fmt.Errorf("grypedb: diff: copy the current database: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, diffTimeout(f.o.Config.Interval))
	defer cancel()
	keys, err := f.o.Diff(ctx, oldCopy, newDir)
	if err != nil {
		return nil, fmt.Errorf("grypedb: diff: %w", err)
	}
	return keys, nil
}
