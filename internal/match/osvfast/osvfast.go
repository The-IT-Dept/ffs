// Package osvfast is the OSV fast path (spec §6.5). Changed OSV records reach the stored packages
// through the inverted package index and are evaluated with osv-scalibr's semantic versions, so a
// new or changed advisory produces matches within minutes instead of waiting for the next Grype DB.
// Debian, Ubuntu, Alpine, Wolfi and Chainguard records name source packages and are joined through
// the stored source name. Go vulndb is the authority for the Go standard library. Ecosystems that
// semantic does not compare the way grype does (Linux, Android, Azure Linux, GIT) are skipped, as
// are rpm entries whose epochs disagree with the installed version's and kernel-header packages.
package osvfast

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/osv-scalibr/semantic"
	"github.com/ossf/osv-schema/bindings/go/osvschema"

	"github.com/the-it-dept/ffs/internal/feeds/osv"
	"github.com/the-it-dept/ffs/internal/match"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

const (
	bucketDebian = "Debian"
	bucketPyPI   = "PyPI"
	bucketMaven  = "Maven"
	goModule     = "go-module"
	goStdlib     = "stdlib"
)

// skippedBuckets are the ecosystems the fast path leaves to other matchers: semantic does not
// compare them the way grype does, or (GIT) they are the upstream and Kubernetes matchers' records.
var skippedBuckets = map[string]bool{osv.BucketGIT: true, "Linux": true, "Android": true, "Azure Linux": true}

// recordChunk is how many cached records MatchImage reads at a time: as many as recordChunkBytes holds
// of the largest record the OSV feed caches (maxCachedRecordBytes), so one read holds at most
// recordChunkBytes of records whatever their sizes. A host's Ubuntu linux source package alone indexes
// thousands of kernel records averaging over 400 KB, so reading a bucket's records at once can take
// gigabytes. A var so tests can lower it.
var recordChunk = recordChunkBytes / maxCachedRecordBytes

const (
	// recordChunkBytes bounds the uncompressed records of one read.
	recordChunkBytes = 64 << 20
	// maxCachedRecordBytes is the largest record the OSV feed caches: it skips larger ones
	// (internal/feeds/osv maxRecordBytes).
	maxCachedRecordBytes = 4 << 20
)

// loadRecords reads cached records by id: (*store.Store).OSVRecordsByID, a var so tests can watch
// the batches.
var loadRecords = (*store.Store).OSVRecordsByID

// Matcher is the OSV fast-path matcher. It is safe for concurrent use.
type Matcher struct{ st *store.Store }

var (
	_ match.Matcher       = (*Matcher)(nil)
	_ match.RecordMatcher = (*Matcher)(nil)
)

// New returns a matcher over the OSV records cached in st.
func New(st *store.Store) *Matcher { return &Matcher{st: st} }

// Source implements match.Matcher.
func (m *Matcher) Source() model.MatchSource { return model.SourceOSV }

// MatchImage implements match.Matcher. It looks up the cached records indexed under the image's
// packages, bucket by bucket, and evaluates them against those packages in id order, reading
// recordChunk records at a time and parsing and evaluating them one by one (see eachRecord).
// Synthetic digests get no matches. Each match is observed when ffs first saw the record behind it
// (see evalRecord).
func (m *Matcher) MatchImage(ctx context.Context, in match.ImageInput) ([]model.Match, error) {
	if match.IsSynthetic(in.Digest) {
		return nil, nil
	}
	byBucket := map[string][]model.Package{}
	for _, p := range in.Packages {
		if eco, ok := osv.PackageEcosystem(p); ok {
			b := osv.BucketOf(eco)
			byBucket[b] = append(byBucket[b], p)
		}
	}
	var ms matchSet
	canon := map[string]string{}
	for _, b := range slices.Sorted(maps.Keys(byBucket)) {
		pkgs := byBucket[b]
		var names []string
		for _, p := range pkgs {
			names = append(names, osv.PackageIndexNames(p)...)
		}
		slices.Sort(names)
		ids, err := m.st.OSVRecordIDsByName(ctx, b, slices.Compact(names))
		if err != nil {
			return nil, err
		}
		idx := indexPackages(pkgs)
		err = m.eachRecord(ctx, ids, func(v *osvschema.Vulnerability, observed time.Time) error {
			adv, ok := canon[v.GetId()]
			if !ok {
				var err error
				if adv, err = m.st.Canonical(ctx, v.GetId()); err != nil {
					return err
				}
				canon[v.GetId()] = adv
			}
			evalRecord(ctx, v, adv, observed, idx, &ms)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return ms.list, nil
}

// eachRecord calls fn with each cached record of ids that parses, and when ffs observed it, in the
// order of the ids (sorted) they are cached under; a record id is passed once. It reads recordChunk
// records at a time, and parses each record only once fn is done with the one before, dropping the
// raw copy as it goes: a parsed record takes several times its raw size, and parsing a read's 256
// records together held most of a gigabyte for a host's kernel records.
func (m *Matcher) eachRecord(ctx context.Context, ids []string, fn func(*osvschema.Vulnerability, time.Time) error) error {
	seen := make(map[string]bool, len(ids))
	for chunk := range slices.Chunk(ids, recordChunk) {
		raws, err := loadRecords(m.st, ctx, chunk)
		if err != nil {
			return err
		}
		observed, err := m.st.OSVRecordsObserved(ctx, chunk)
		if err != nil {
			return err
		}
		for i, raw := range raws {
			raws[i] = nil
			v, err := match.ParseOSV(raw)
			if err != nil {
				logr.FromContextOrDiscard(ctx).V(1).Info("skipping an unreadable cached OSV record", "error", err.Error())
				continue
			}
			id := v.GetId()
			if seen[id] {
				continue
			}
			seen[id] = true
			at, ok := observed[id]
			if _, asked := slices.BinarySearch(chunk, id); !ok && !asked {
				// A record whose id is not the one it is cached under: look its observation up by its id,
				// as records does.
				o, err := m.st.OSVRecordsObserved(ctx, []string{id})
				if err != nil {
					return err
				}
				at = o[id]
			}
			if err := fn(v, at); err != nil {
				return err
			}
		}
	}
	return nil
}

// ApplyOSV implements match.RecordMatcher. It stores the advisory of every changed record except
// GIT ones (the upstream and Kubernetes matchers' records), so the ids and aliases of records the
// fast path does not evaluate (Linux, Android, Azure Linux, notices) are stored and searchable too.
// It then re-evaluates each advisory touched from all of its cached records, the changed ones taking
// the place of their cached copies, against the packages they name; records the fast path skips
// match nothing. Each advisory gets one Delta scoped to the osv source and that advisory, so a
// withdrawn or narrowed record drops the matches it no longer supports. An unreadable record is
// skipped; only store failures are errors.
func (m *Matcher) ApplyOSV(ctx context.Context, recs []osv.Changed) ([]match.Delta, error) {
	log := logr.FromContextOrDiscard(ctx)
	changed := map[string]*osvschema.Vulnerability{}
	for _, r := range recs {
		if r.Ecosystem == osv.BucketGIT {
			continue
		}
		v, err := match.ParseOSV(r.Raw)
		if err != nil || v.GetId() == "" {
			log.V(1).Info("skipping an unreadable OSV record", "bucket", r.Ecosystem, "id", r.ID, "error", err)
			continue
		}
		if _, err := match.UpsertOSVAdvisory(ctx, m.st, v); err != nil {
			return nil, err
		}
		changed[v.GetId()] = v
	}
	// Resolve canonicals once every record is stored: a later record can merge an earlier one's
	// advisory into another.
	byAdv := map[string]map[string]*osvschema.Vulnerability{}
	for id, v := range changed {
		adv, err := m.st.Canonical(ctx, id)
		if err != nil {
			return nil, err
		}
		if byAdv[adv] == nil {
			byAdv[adv] = map[string]*osvschema.Vulnerability{}
		}
		byAdv[adv][id] = v
	}

	deltas := make([]match.Delta, 0, len(byAdv))
	for _, adv := range slices.Sorted(maps.Keys(byAdv)) {
		ms, err := m.evalAdvisory(ctx, adv, byAdv[adv])
		if err != nil {
			return nil, err
		}
		deltas = append(deltas, match.Delta{
			Scope:   store.MatchScope{Source: model.SourceOSV, AdvisoryIDs: []string{adv}},
			Matches: ms,
		})
	}
	return deltas, nil
}

// evalAdvisory evaluates every cached record of adv, with the changed records overriding their
// cached copies, against the stored packages the records name.
func (m *Matcher) evalAdvisory(ctx context.Context, adv string, changed map[string]*osvschema.Vulnerability) ([]model.Match, error) {
	ids, err := match.AdvisoryRecordIDs(ctx, m.st, adv)
	if err != nil {
		return nil, err
	}
	recs, observed, err := m.records(ctx, ids, changed)
	if err != nil {
		return nil, err
	}
	pkgs, err := m.candidates(ctx, recs)
	if err != nil {
		return nil, err
	}
	idx := indexPackages(pkgs)
	var ms matchSet
	for _, v := range recs {
		evalRecord(ctx, v, adv, observed[v.GetId()], idx, &ms)
	}
	return ms.list, nil
}

// records returns the cached records with ids, with override replacing (or adding) records by id,
// sorted by id, and when ffs observed each cached one (store.OSVRecordsObserved). Cached records
// that do not parse are skipped. The feed caches a changed record before handing it off, so an
// override has its observation time too.
func (m *Matcher) records(ctx context.Context, ids []string, override map[string]*osvschema.Vulnerability) ([]*osvschema.Vulnerability, map[string]time.Time, error) {
	recs, err := m.parsed(ctx, ids, override)
	if err != nil {
		return nil, nil, err
	}
	recIDs := make([]string, len(recs))
	for i, v := range recs {
		recIDs[i] = v.GetId()
	}
	observed, err := m.st.OSVRecordsObserved(ctx, recIDs)
	if err != nil {
		return nil, nil, err
	}
	return recs, observed, nil
}

// parsed returns the cached records with ids, with override replacing (or adding) records by id,
// sorted by id. Cached records that do not parse are skipped; those override replaces are not read.
func (m *Matcher) parsed(ctx context.Context, ids []string, override map[string]*osvschema.Vulnerability) ([]*osvschema.Vulnerability, error) {
	if len(override) > 0 {
		ids = slices.DeleteFunc(slices.Clone(ids), func(id string) bool { _, ok := override[id]; return ok })
	}
	raws, err := loadRecords(m.st, ctx, ids)
	if err != nil {
		return nil, err
	}
	byID := maps.Clone(override)
	if byID == nil {
		byID = map[string]*osvschema.Vulnerability{}
	}
	for _, raw := range raws {
		v, err := match.ParseOSV(raw)
		if err != nil {
			logr.FromContextOrDiscard(ctx).V(1).Info("skipping an unreadable cached OSV record", "error", err.Error())
			continue
		}
		if _, ok := byID[v.GetId()]; !ok {
			byID[v.GetId()] = v
		}
	}
	out := make([]*osvschema.Vulnerability, 0, len(byID))
	for _, id := range slices.Sorted(maps.Keys(byID)) {
		out = append(out, byID[id])
	}
	return out, nil
}

// lookup is how candidates finds stored packages by name.
type lookup uint8

const (
	byName       lookup = iota // the package name
	bySource                   // the source package name, or the name when the source is empty
	byFoldedName               // the PEP 503-folded package name
)

// candidates returns the stored packages the affected entries of recs can name: by source and by
// binary name in source-join buckets, by folded name for PyPI (Syft keeps the metadata's "Jinja2"
// or "typing_extensions" while records say "jinja2" or "typing-extensions"), by folded artifact ID
// for Maven (the group is checked against the PURL later) and by name elsewhere. That is a superset
// of the packages MatchImage would match against recs (for Maven, because Syft's PURL artifact is
// the package name), so the two paths agree once indexPackages and evalRecord apply the exact index
// names. Withdrawn records and skipped ecosystems name none. The names are looked up together, one
// query per package type and lookup: an Ubuntu kernel record alone names over a hundred packages.
func (m *Matcher) candidates(ctx context.Context, recs []*osvschema.Vulnerability) ([]model.Package, error) {
	type query struct {
		typ, name string
		by        lookup
	}
	type group struct {
		typ string
		by  lookup
	}
	seen := map[query]bool{}
	names := map[group][]string{}
	for _, v := range recs {
		if v.GetWithdrawn() != nil {
			continue
		}
		for _, a := range v.GetAffected() {
			b := osv.BucketOf(osv.NormalizeRecordEcosystem(a.GetPackage().GetEcosystem()))
			typ, name := osv.SyftType(b), a.GetPackage().GetName()
			if skippedBuckets[b] || osv.SkipID(b, v.GetId()) || typ == "" || name == "" {
				continue
			}
			var qs []query
			switch {
			case osv.SourceJoin(b):
				qs = []query{{typ, name, bySource}, {typ, name, byName}}
			case b == bucketPyPI:
				qs = []query{{typ, name, byFoldedName}}
			case b == bucketMaven:
				_, artifact, _ := strings.Cut(name, ":")
				qs = []query{{typ, artifact, byFoldedName}}
			default:
				qs = []query{{typ, name, byName}}
			}
			for _, q := range qs {
				if seen[q] || q.name == "" {
					continue
				}
				seen[q] = true
				g := group{q.typ, q.by}
				names[g] = append(names[g], q.name)
			}
		}
	}
	groups := slices.SortedFunc(maps.Keys(names), func(a, b group) int {
		return cmp.Or(strings.Compare(a.typ, b.typ), cmp.Compare(a.by, b.by))
	})
	var out []model.Package
	for _, g := range groups {
		var pkgs []model.Package
		var err error
		if g.by == byFoldedName {
			pkgs, err = m.st.PackagesByFoldedNames(ctx, g.typ, names[g])
		} else {
			pkgs, err = m.st.PackagesByNames(ctx, g.typ, names[g], g.by == bySource)
		}
		if err != nil {
			return nil, err
		}
		out = append(out, pkgs...)
	}
	return out, nil
}

// pkgKey is what an affected entry names: a normalised record ecosystem and an index name.
type pkgKey struct{ eco, name string }

// indexPackages indexes the packages the fast path may match by their ecosystem and index names,
// once each, leaving out synthetic subjects, kernel-header packages and packages outside the OSV
// ecosystems.
func indexPackages(pkgs []model.Package) map[pkgKey][]model.Package {
	idx := map[pkgKey][]model.Package{}
	seen := map[string]bool{}
	for _, p := range pkgs {
		if p.ID != "" && seen[p.ID] || match.IsSynthetic(p.ImageDigest) || match.IsKernelHeader(p) {
			continue
		}
		eco, ok := osv.PackageEcosystem(p)
		if !ok {
			continue
		}
		seen[p.ID] = true
		for _, n := range osv.PackageIndexNames(p) {
			k := pkgKey{eco, n}
			idx[k] = append(idx[k], p)
		}
	}
	return idx
}

// evalRecord adds to ms the matches of record v, whose canonical advisory is adv, against the
// indexed packages. Withdrawn records, skipped ecosystems and notice records match nothing. Each
// match is observed at observed, when ffs first saw the record's current content (zero when
// unknown): grype has an opinion on it only through a DB built after that (spec §6.5), however
// recently the image itself was catalogued.
func evalRecord(ctx context.Context, v *osvschema.Vulnerability, adv string, observed time.Time, idx map[pkgKey][]model.Package, ms *matchSet) {
	if v.GetWithdrawn() != nil {
		return
	}
	log := logr.FromContextOrDiscard(ctx)
	for _, a := range v.GetAffected() {
		eco := osv.NormalizeRecordEcosystem(a.GetPackage().GetEcosystem())
		b := osv.BucketOf(eco)
		if skippedBuckets[b] || osv.SkipID(b, v.GetId()) {
			continue
		}
		pkgs := idx[pkgKey{eco, osv.IndexName(b, a.GetPackage().GetName())}]
		if len(pkgs) == 0 {
			continue
		}
		sev, sevSource := vendorSeverity(v, a, b)
		for _, p := range pkgs {
			version, ok := InstalledVersion(p)
			if !ok || osv.SyftType(b) == "rpm" && epochMismatch(a, version) {
				continue
			}
			affected, fs, fixed, err := Evaluate(a, version)
			if errors.Is(err, semantic.ErrUnsupportedEcosystem) {
				break
			}
			if err != nil {
				log.V(1).Info("skipping an OSV entry that does not evaluate", "id", v.GetId(), "ecosystem", eco,
					"package", p.Name, "version", version, "error", err.Error())
				continue
			}
			if !affected {
				continue
			}
			ms.add(model.Match{
				ImageDigest:          p.ImageDigest,
				PackageID:            p.ID,
				AdvisoryID:           adv,
				Source:               model.SourceOSV,
				FixState:             fs,
				FixedVersions:        fixed,
				VendorSeverity:       sev,
				VendorSeveritySource: sevSource,
				Namespace:            eco,
				ObservedAt:           observed,
			})
		}
	}
}

// matchSet collects matches, merging those for the same package and advisory: several records
// (PYSEC and GHSA, say) or affected entries can name one package. Fixed versions are unioned, the
// first vendor severity found is kept and the earliest observation wins.
type matchSet struct {
	list []model.Match
	at   map[[3]string]int
}

func (s *matchSet) add(m model.Match) {
	k := [3]string{m.ImageDigest, m.PackageID, m.AdvisoryID}
	i, ok := s.at[k]
	if !ok {
		if s.at == nil {
			s.at = map[[3]string]int{}
		}
		s.at[k] = len(s.list)
		s.list = append(s.list, m)
		return
	}
	cur := &s.list[i]
	for _, f := range m.FixedVersions {
		if !slices.Contains(cur.FixedVersions, f) {
			cur.FixedVersions = append(cur.FixedVersions, f)
		}
	}
	if len(cur.FixedVersions) > 0 {
		cur.FixState = model.FixFixed
	}
	if cur.VendorSeverity == model.SeverityUnknown {
		cur.VendorSeverity, cur.VendorSeveritySource = m.VendorSeverity, m.VendorSeveritySource
	}
	if !m.ObservedAt.IsZero() && (cur.ObservedAt.IsZero() || m.ObservedAt.Before(cur.ObservedAt)) {
		cur.ObservedAt = m.ObservedAt
	}
}
