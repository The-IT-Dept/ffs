package upstream

import (
	"context"
	"encoding/json"
	"maps"
	"slices"
	"strings"

	"github.com/go-logr/logr"
	"github.com/ossf/osv-schema/bindings/go/osvschema"

	"github.com/the-it-dept/ffs/internal/feeds/osv"
	"github.com/the-it-dept/ffs/internal/match"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

// recordChunk is how many cached GIT records MatchImage reads, parses and evaluates at a time: a
// repository's records grow with the feed and can list thousands of tags each. A var so tests can
// lower it.
var recordChunk = 256

// loadRecords reads cached records by id: (*store.Store).OSVRecordsByID, a var so tests can watch
// the batches.
var loadRecords = (*store.Store).OSVRecordsByID

// Matcher is the upstream-runtime matcher. It matches the packages Lookup maps against the OSV GIT
// records cached for the entry's repository and the CNA ranges stored for its product. It is safe
// for concurrent use.
type Matcher struct{ st *store.Store }

var (
	_ match.Matcher       = (*Matcher)(nil)
	_ match.RecordMatcher = (*Matcher)(nil)
)

// New returns a matcher over the GIT records and CNA ranges in st.
func New(st *store.Store) *Matcher { return &Matcher{st: st} }

// Source implements match.Matcher.
func (m *Matcher) Source() model.MatchSource { return model.SourceUpstream }

// MatchImage implements match.Matcher. The GIT records of each repository are read recordChunk at a
// time, in id order. Synthetic digests get no matches.
func (m *Matcher) MatchImage(ctx context.Context, in match.ImageInput) ([]model.Match, error) {
	if match.IsSynthetic(in.Digest) {
		return nil, nil
	}
	byKey := map[string][]model.Package{}
	entries := map[string]Entry{}
	for _, p := range in.Packages {
		if e, ok := Lookup(p); ok {
			byKey[e.Key] = append(byKey[e.Key], p)
			entries[e.Key] = e
		}
	}
	c := newLookups(m.st)
	var ms matchSet
	for _, key := range slices.Sorted(maps.Keys(byKey)) {
		e := entries[key]
		ranges, err := c.ranges(ctx, e.Key)
		if err != nil {
			return nil, err
		}
		ids, err := m.st.OSVRecordIDsByName(ctx, osv.BucketGIT, []string{e.Repo})
		if err != nil {
			return nil, err
		}
		for _, id := range slices.Sorted(maps.Keys(ranges)) {
			if err := c.addCNA(ctx, &ms, e, id, ranges[id], byKey[key]); err != nil {
				return nil, err
			}
		}
		// ids are sorted, so consecutive chunks visit the records in the same order as reading them
		// all at once, and ms merges across chunks as before.
		for chunk := range slices.Chunk(ids, recordChunk) {
			recs, err := m.records(ctx, chunk, nil)
			if err != nil {
				return nil, err
			}
			for _, v := range recs {
				if err := c.addGit(ctx, &ms, e, v, byKey[key]); err != nil {
					return nil, err
				}
			}
		}
	}
	return ms.list, nil
}

// ApplyOSV implements match.RecordMatcher over the GIT records handed off by the OSV feed. Records
// with a range in one of Repos() have their advisory stored. Every GIT record is re-evaluated, so
// one that stopped referencing a mapped repository (the feed hands such a record off once before
// dropping it) clears the matches it supported. Each advisory touched gets one Delta, scoped to the
// upstream source and that advisory, combining its CNA and GIT matches. Unreadable records are
// skipped; only store failures are errors.
func (m *Matcher) ApplyOSV(ctx context.Context, recs []osv.Changed) ([]match.Delta, error) {
	log := logr.FromContextOrDiscard(ctx)
	repos := Repos()
	changed := map[string]*osvschema.Vulnerability{}
	for _, r := range recs {
		if r.Ecosystem != osv.BucketGIT {
			continue
		}
		v, err := match.ParseOSV(r.Raw)
		if err != nil || v.GetId() == "" {
			log.V(1).Info("skipping an unreadable OSV record", "bucket", r.Ecosystem, "id", r.ID, "error", err)
			continue
		}
		if referencesAny(v, repos) {
			if _, err := match.UpsertOSVAdvisory(ctx, m.st, v); err != nil {
				return nil, err
			}
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
	c := newLookups(m.st)
	deltas := make([]match.Delta, 0, len(byAdv))
	for _, adv := range slices.Sorted(maps.Keys(byAdv)) {
		d, err := m.evalAdvisory(ctx, c, adv, byAdv[adv])
		if err != nil {
			return nil, err
		}
		deltas = append(deltas, d)
	}
	return deltas, nil
}

// ApplyCNA re-evaluates the advisories of CVE records the cvelist feed stored, after resolving each
// id to its canonical advisory. Each advisory gets one Delta, scoped to the upstream source and that
// advisory, combining its CNA and GIT matches.
func (m *Matcher) ApplyCNA(ctx context.Context, advisoryIDs []string) ([]match.Delta, error) {
	advs := make([]string, 0, len(advisoryIDs))
	for _, id := range advisoryIDs {
		adv, err := m.st.Canonical(ctx, id)
		if err != nil {
			return nil, err
		}
		advs = append(advs, adv)
	}
	slices.Sort(advs)
	c := newLookups(m.st)
	deltas := make([]match.Delta, 0, len(advs))
	for _, adv := range slices.Compact(advs) {
		d, err := m.evalAdvisory(ctx, c, adv, nil)
		if err != nil {
			return nil, err
		}
		deltas = append(deltas, d)
	}
	return deltas, nil
}

// evalAdvisory evaluates every record id of adv, its cached GIT records (changed ones taking the
// place of their cached copies) and its stored CNA ranges, against the stored packages of each
// mapped product.
func (m *Matcher) evalAdvisory(ctx context.Context, c *lookups, adv string, changed map[string]*osvschema.Vulnerability) (match.Delta, error) {
	d := match.Delta{Scope: store.MatchScope{Source: model.SourceUpstream, AdvisoryIDs: []string{adv}}}
	ids, err := match.AdvisoryRecordIDs(ctx, m.st, adv)
	if err != nil {
		return d, err
	}
	recs, err := m.records(ctx, ids, changed)
	if err != nil {
		return d, err
	}
	var ms matchSet
	for _, e := range Map {
		ranges, err := c.ranges(ctx, e.Key)
		if err != nil {
			return d, err
		}
		var cna []string
		for _, id := range ids {
			if _, ok := ranges[id]; ok {
				cna = append(cna, id)
			}
		}
		git := slices.DeleteFunc(slices.Clone(recs), func(v *osvschema.Vulnerability) bool { return !referencesAny(v, []string{e.Repo}) })
		if len(cna) == 0 && len(git) == 0 {
			continue
		}
		pkgs, err := c.packages(ctx, e)
		if err != nil {
			return d, err
		}
		for _, id := range cna {
			if err := c.addCNA(ctx, &ms, e, id, ranges[id], pkgs); err != nil {
				return d, err
			}
		}
		for _, v := range git {
			if err := c.addGit(ctx, &ms, e, v, pkgs); err != nil {
				return d, err
			}
		}
	}
	d.Matches = ms.list
	return d, nil
}

// records returns the cached records with ids, with override replacing (or adding) records by id,
// sorted by id. Cached records that do not parse are skipped.
func (m *Matcher) records(ctx context.Context, ids []string, override map[string]*osvschema.Vulnerability) ([]*osvschema.Vulnerability, error) {
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

// referencesAny reports whether v has a GIT range whose repository is one of repos.
func referencesAny(v *osvschema.Vulnerability, repos []string) bool {
	for _, a := range v.GetAffected() {
		for _, r := range a.GetRanges() {
			if r.GetType() == osvschema.Range_GIT && slices.Contains(repos, osv.NormalizeRepo(r.GetRepo())) {
				return true
			}
		}
	}
	return false
}

// lookups caches, for one matcher call, the stored CNA ranges and packages of each product and the
// canonical id of each record id.
type lookups struct {
	st     *store.Store
	cna    map[string]map[string]CNARanges // product key → advisory id → ranges
	pkgs   map[string][]model.Package      // product key → mapped packages
	canons map[string]string
}

func newLookups(st *store.Store) *lookups {
	return &lookups{st: st, cna: map[string]map[string]CNARanges{}, pkgs: map[string][]model.Package{}, canons: map[string]string{}}
}

// ranges returns the decoded CNA ranges stored for the product key. Ranges that do not decode are
// skipped.
func (c *lookups) ranges(ctx context.Context, key string) (map[string]CNARanges, error) {
	if r, ok := c.cna[key]; ok {
		return r, nil
	}
	raw, err := c.st.UpstreamRanges(ctx, key)
	if err != nil {
		return nil, err
	}
	out := make(map[string]CNARanges, len(raw))
	for id, b := range raw {
		var r CNARanges
		if err := json.Unmarshal(b, &r); err != nil {
			logr.FromContextOrDiscard(ctx).V(1).Info("skipping unreadable CNA ranges", "id", id, "product", key, "error", err.Error())
			continue
		}
		out[id] = r
	}
	c.cna[key] = out
	return out, nil
}

// packages returns the stored packages of every image that Lookup maps to e.
func (c *lookups) packages(ctx context.Context, e Entry) ([]model.Package, error) {
	if p, ok := c.pkgs[e.Key]; ok {
		return p, nil
	}
	var out []model.Package
	for _, name := range e.Names {
		pkgs, err := c.st.PackagesByName(ctx, binaryEcosystem, nil, name, false)
		if err != nil {
			return nil, err
		}
		for _, p := range pkgs {
			if got, ok := Lookup(p); ok && got.Key == e.Key && !match.IsSynthetic(p.ImageDigest) {
				out = append(out, p)
			}
		}
	}
	c.pkgs[e.Key] = out
	return out, nil
}

func (c *lookups) canonical(ctx context.Context, id string) (string, error) {
	if adv, ok := c.canons[id]; ok {
		return adv, nil
	}
	adv, err := c.st.Canonical(ctx, id)
	if err != nil {
		return "", err
	}
	c.canons[id] = adv
	return adv, nil
}

// addCNA adds the matches of the CNA ranges stored for advisory id and product e.
func (c *lookups) addCNA(ctx context.Context, ms *matchSet, e Entry, id string, r CNARanges, pkgs []model.Package) error {
	for _, p := range pkgs {
		affected, fs, fixed := r.Affects(p.Version)
		if !affected {
			continue
		}
		adv, err := c.canonical(ctx, id)
		if err != nil {
			return err
		}
		ms.add(newMatch(p, adv, "cna:"+e.Key, fs, fixed))
	}
	return nil
}

// addGit adds the matches of GIT record v for product e.
func (c *lookups) addGit(ctx context.Context, ms *matchSet, e Entry, v *osvschema.Vulnerability, pkgs []model.Package) error {
	for _, p := range pkgs {
		ok, fs, fixed := MatchGitRecord(v, e.Repo, e.Tags(p.Version), p.Version)
		if !ok {
			continue
		}
		adv, err := c.canonical(ctx, v.GetId())
		if err != nil {
			return err
		}
		ms.add(newMatch(p, adv, "git:"+e.Repo, fs, fixed))
	}
	return nil
}

func newMatch(p model.Package, adv, namespace string, fs model.FixState, fixed []string) model.Match {
	return model.Match{
		ImageDigest:   p.ImageDigest,
		PackageID:     p.ID,
		AdvisoryID:    adv,
		Source:        model.SourceUpstream,
		FixState:      fs,
		FixedVersions: fixed,
		Namespace:     namespace,
	}
}

// matchSet collects matches, one per package and advisory. A CNA match replaces a GIT one for the
// same package and advisory; matches from the same kind of source are merged, keeping the smallest
// fixed version and FixFixed when either has it.
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
	curCNA, newCNA := isCNA(cur.Namespace), isCNA(m.Namespace)
	switch {
	case newCNA && !curCNA:
		*cur = m
		return
	case curCNA && !newCNA:
		return
	}
	if m.FixState == model.FixFixed {
		cur.FixState = model.FixFixed
	}
	if fixed := slices.Concat(cur.FixedVersions, m.FixedVersions); len(fixed) > 0 {
		cur.FixedVersions = []string{slices.MinFunc(fixed, CompareVersions)}
	}
}

func isCNA(namespace string) bool { return strings.HasPrefix(namespace, "cna:") }
