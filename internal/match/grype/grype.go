// Package grype is the matcher of record (spec §6.5). It drives grype's VulnerabilityMatcher with
// the grype CLI's defaults over stored syft SBOMs, records grype's own suppressions as not affected,
// emits not-affected "opinion" matches for OSV hints its DB has a record for, and keeps the names it
// searched so a DB diff re-matches only the affected digests.
package grype

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/name"
	"github.com/anchore/grype/grype/distro"
	grypematch "github.com/anchore/grype/grype/match"
	grypepkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
	syftpkg "github.com/anchore/syft/syft/pkg"

	"github.com/the-it-dept/ffs/internal/match"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

// Matcher is the grype matcher. It is safe for concurrent use.
type Matcher struct {
	st           *store.Store
	searchesCPEs func(syftpkg.Type) bool

	mu    sync.RWMutex
	vp    vulnerability.Provider // nil until Load
	built time.Time
}

var _ match.Matcher = (*Matcher)(nil)

// New returns a matcher with no database loaded.
func New(st *store.Store) *Matcher {
	return &Matcher{st: st, searchesCPEs: cpeSearchTypes()}
}

// Load opens the database in path (a directory holding vulnerability.db) and makes it current,
// closing the previous one. built is the database's build time, stamped on every match.
func (m *Matcher) Load(path string, built time.Time) error {
	rdr, err := v6.NewReader(v6.Config{DBDirPath: path})
	if err != nil {
		return fmt.Errorf("grype: open database %s: %w", path, err)
	}
	vp := v6.NewVulnerabilityProvider(rdr)
	m.mu.Lock()
	old := m.vp
	m.vp, m.built = vp, built
	m.mu.Unlock()
	// every reader of old held the read lock, so none is left once the write lock was taken
	if old != nil {
		if err := old.Close(); err != nil {
			return fmt.Errorf("grype: close previous database: %w", err)
		}
	}
	return nil
}

// Built returns the build time of the loaded database, zero before Load.
func (m *Matcher) Built() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.built
}

// Source implements match.Matcher.
func (m *Matcher) Source() model.MatchSource { return model.SourceGrype }

// MatchImage implements match.Matcher. A synthetic digest (no SBOM) gets no matches, and before
// Load it returns match.ErrNotReady. It stores the advisories it matched and the image's grype
// search keys.
func (m *Matcher) MatchImage(ctx context.Context, in match.ImageInput) ([]model.Match, error) {
	if in.SyftJSON == nil {
		return nil, nil
	}
	r, keys, err := m.matchImage(ctx, in)
	if err != nil {
		return nil, err
	}
	for _, a := range r.advisoryList() {
		if err := m.st.UpsertAdvisory(ctx, a); err != nil {
			return nil, fmt.Errorf("grype: store advisory %s: %w", a.ID, err)
		}
	}
	if err := m.st.PutGrypeKeys(ctx, in.Digest, keys.pkgNames, keys.cpeProducts); err != nil {
		return nil, fmt.Errorf("grype: store search keys of %s: %w", in.Digest, err)
	}
	return r.list(), nil
}

// matchImage runs grype over the image and adds the opinions, under the read lock.
func (m *Matcher) matchImage(ctx context.Context, in match.ImageInput) (*results, searchKeys, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.vp == nil {
		return nil, searchKeys{}, match.ErrNotReady
	}
	pkgs, pkgCtx, _, err := grypepkg.ProvideFromReader(bytes.NewReader(in.SyftJSON), providerConfig())
	if err != nil {
		return nil, searchKeys{}, fmt.Errorf("grype: read SBOM of %s: %w", in.Digest, err)
	}
	remaining, ignored, err := newVulnerabilityMatcher(m.vp).FindMatchesContext(ctx, pkgs, pkgCtx)
	if err != nil {
		return nil, searchKeys{}, fmt.Errorf("grype: match %s: %w", in.Digest, err)
	}
	r := toModel(in.Digest, in.Packages, m.built, remaining.Sorted(), ignored)
	if err := m.addOpinions(ctx, r, in); err != nil {
		return nil, searchKeys{}, err
	}
	return r, m.searchKeysOf(pkgs), nil
}

// addOpinions adds a not-affected match for each OSV hint that grype did not match but whose
// advisory, or an alias of it, has a record for the package in grype's DB: grype has an opinion,
// and it is "not affected" at this version (spec §6.5).
func (m *Matcher) addOpinions(ctx context.Context, r *results, in match.ImageInput) error {
	pkgs := make(map[string]model.Package, len(in.Packages))
	for _, p := range in.Packages {
		pkgs[p.ID] = p
	}
	for _, h := range in.Hints {
		p, ok := pkgs[h.PackageID]
		// Go vulndb, not grype, is the authority for the Go standard library (spec §6.5)
		if h.Source != model.SourceOSV || !ok || isGoStdlib(grypePackage(p)) {
			continue
		}
		ids := []string{h.AdvisoryID}
		a, ok, err := m.st.GetAdvisory(ctx, h.AdvisoryID)
		if err != nil {
			return fmt.Errorf("grype: advisory %s: %w", h.AdvisoryID, err)
		}
		if ok {
			ids = append(ids, a.ID)
			ids = append(ids, a.Aliases...)
		}
		slices.Sort(ids)
		ids = slices.Compact(ids)
		if r.matched(p.ID, ids) {
			continue
		}
		v, ok, err := findRecord(ctx, m.vp, p, ids)
		if err != nil {
			return err
		}
		if ok {
			r.add(p, v, model.FixNotAffected, nil)
		}
	}
	return nil
}

// HasRecord reports whether the loaded DB holds a record, affected or unaffected, for p under any of
// advisoryIDs, at any version. Before Load it returns match.ErrNotReady.
func (m *Matcher) HasRecord(ctx context.Context, p model.Package, advisoryIDs []string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.vp == nil {
		return false, match.ErrNotReady
	}
	_, ok, err := findRecord(ctx, m.vp, p, advisoryIDs)
	return ok, err
}

// findRecord returns the first record vp holds for p under one of ids: searched by p's grype search
// names and its source package name, in p's distro, or in p's package ecosystem when it has none.
func findRecord(ctx context.Context, vp vulnerability.Provider, p model.Package, ids []string) (vulnerability.Vulnerability, bool, error) {
	gp := grypePackage(p)
	names := name.PackageNames(gp)
	if p.SourceName != "" && !slices.Contains(names, p.SourceName) {
		names = append(names, p.SourceName)
	}
	var scope vulnerability.Criteria
	if p.Distro != nil {
		scope = search.ByDistro(*distro.NewFromNameVersion(p.Distro.ID, p.Distro.VersionID))
	} else {
		scope = search.ByEcosystem("", gp.Type)
	}
	for _, id := range ids {
		for _, n := range names {
			for _, unaffected := range []bool{false, true} {
				if err := ctx.Err(); err != nil {
					return vulnerability.Vulnerability{}, false, err
				}
				criteria := []vulnerability.Criteria{search.ByID(id), search.ByPackageName(n), scope}
				if unaffected {
					criteria = append(criteria, search.ForUnaffected())
				}
				vs, err := vp.FindVulnerabilities(criteria...)
				if err != nil {
					return vulnerability.Vulnerability{}, false, fmt.Errorf("grype: search %s for %s: %w", id, n, err)
				}
				if len(vs) > 0 {
					return vs[0], true, nil
				}
			}
		}
	}
	return vulnerability.Vulnerability{}, false, nil
}

// grypePackage is the minimal grype package for p that grype's search-name rules need.
func grypePackage(p model.Package) grypepkg.Package {
	return grypepkg.Package{Name: p.Name, Version: p.Version, Type: syftpkg.Type(p.Ecosystem), PURL: p.PURL}
}

// searchKeys are the names grype searches an image's packages by, lowercased.
type searchKeys struct{ pkgNames, cpeProducts []string }

// searchKeysOf collects every name grype searches pkgs by: their DB search names and upstream names,
// and the CPE products of packages whose matcher searches CPEs.
func (m *Matcher) searchKeysOf(pkgs []grypepkg.Package) searchKeys {
	names, products := map[string]bool{}, map[string]bool{}
	addProducts := func(p grypepkg.Package) {
		for _, c := range p.CPEs {
			products[strings.ToLower(c.Attributes.Product)] = true
		}
	}
	for _, gp := range pkgs {
		for _, n := range name.PackageNames(gp) {
			names[strings.ToLower(n)] = true
		}
		for _, u := range gp.Upstreams {
			names[strings.ToLower(u.Name)] = true
		}
		if !m.searchesCPEs(gp.Type) {
			continue
		}
		addProducts(gp)
		if gp.Type == syftpkg.ApkPkg { // the apk matcher also searches its origin package's CPEs
			for _, up := range grypepkg.UpstreamPackages(gp) {
				addProducts(up)
			}
		}
	}
	return searchKeys{pkgNames: sortedKeys(names), cpeProducts: sortedKeys(products)}
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		if k != "" && k != "*" {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out
}

// VendorSource names the source of a grype namespace's severity rating: its first segment, with
// "github" (GitHub Security Advisories) as "ghsa". "debian:distro:debian:12" gives "debian".
func VendorSource(namespace string) string {
	vendor, _, _ := strings.Cut(namespace, ":")
	if vendor == "github" {
		return "ghsa"
	}
	return vendor
}

// toModel converts grype's remaining and ignored matches to ffs matches on pkgs. Matches on the Go
// standard library are dropped (Go vulndb is the authority, spec §6.5), and so are matches ignored
// by a kernel-header rule. Every other ignored match is one of grype's own suppressions (a distro
// fixed or NAK record, file ownership overlap, its false-positive list) and becomes not affected.
// Packages that do not join to pkgs are skipped.
func toModel(digest string, pkgs []model.Package, built time.Time, remaining []grypematch.Match, ignored []grypematch.IgnoredMatch) *results {
	r := newResults(digest, pkgs, built)
	for _, gm := range remaining {
		if isGoStdlib(gm.Package) {
			continue
		}
		if p, ok := r.join(gm.Package); ok {
			r.add(p, gm.Vulnerability, fixState(gm.Vulnerability.Fix.State), gm.Vulnerability.Fix.Versions)
		}
	}
	kernelHeaders := ignoreRules()
	for _, im := range ignored {
		if isGoStdlib(im.Package) || slices.ContainsFunc(im.AppliedIgnoreRules, func(rule grypematch.IgnoreRule) bool {
			return slices.Contains(kernelHeaders, rule)
		}) {
			continue
		}
		if p, ok := r.join(im.Package); ok {
			r.add(p, im.Vulnerability, model.FixNotAffected, nil)
		}
	}
	return r
}

func isGoStdlib(gp grypepkg.Package) bool {
	return gp.Type == syftpkg.GoModulePkg && gp.Name == "stdlib"
}

func fixState(s vulnerability.FixState) model.FixState {
	switch s {
	case vulnerability.FixStateFixed:
		return model.FixFixed
	case vulnerability.FixStateNotFixed:
		return model.FixNotFixed
	case vulnerability.FixStateWontFix:
		return model.FixWontFix
	}
	return model.FixUnknown
}

// results accumulates the ffs matches of one image, deduplicated on (package, advisory, namespace),
// and the advisories they reference.
type results struct {
	digest     string
	built      time.Time
	bySyftID   map[string]model.Package
	byCoords   map[coords]model.Package
	matches    []model.Match
	seen       map[[3]string]bool
	advisories map[string]*model.Advisory
	ids        map[string]map[string]bool // package id → matched advisory ids and their aliases
}

// coords identify a package when its syft id is unknown: type, name, version and first path.
type coords struct{ ecosystem, name, version, path string }

func newResults(digest string, pkgs []model.Package, built time.Time) *results {
	r := &results{
		digest:     digest,
		built:      built,
		bySyftID:   map[string]model.Package{},
		byCoords:   map[coords]model.Package{},
		seen:       map[[3]string]bool{},
		advisories: map[string]*model.Advisory{},
		ids:        map[string]map[string]bool{},
	}
	for _, p := range pkgs {
		if _, dup := r.bySyftID[p.SyftID]; p.SyftID != "" && !dup {
			r.bySyftID[p.SyftID] = p
		}
		if k := (coords{p.Ecosystem, p.Name, p.Version, p.Path}); !r.hasCoords(k) {
			r.byCoords[k] = p
		}
	}
	return r
}

func (r *results) hasCoords(k coords) bool {
	_, ok := r.byCoords[k]
	return ok
}

// join finds the ffs package for a grype package: by syft id, else by type, name, version and the
// first real path.
func (r *results) join(gp grypepkg.Package) (model.Package, bool) {
	if p, ok := r.bySyftID[string(gp.ID)]; ok {
		return p, true
	}
	var path string
	if locs := gp.Locations.ToSlice(); len(locs) > 0 {
		path = locs[0].RealPath
	}
	p, ok := r.byCoords[coords{string(gp.Type), gp.Name, gp.Version, path}]
	return p, ok
}

// add records a match of v on p. A later match with the same package, advisory and namespace as
// an earlier one is dropped, so a remaining match wins over a suppressed one.
func (r *results) add(p model.Package, v vulnerability.Vulnerability, fix model.FixState, fixed []string) {
	ns := v.Namespace
	var severity string
	if v.Metadata != nil {
		ns, severity = v.Metadata.Namespace, v.Metadata.Severity
	}
	key := [3]string{p.ID, v.ID, ns}
	if r.seen[key] {
		return
	}
	r.seen[key] = true
	r.matches = append(r.matches, model.Match{
		ImageDigest:          r.digest,
		PackageID:            p.ID,
		AdvisoryID:           v.ID,
		Source:               model.SourceGrype,
		FixState:             fix,
		FixedVersions:        slices.Clone(fixed),
		VendorSeverity:       model.ParseSeverity(severity),
		VendorSeveritySource: VendorSource(ns),
		Namespace:            ns,
		DBBuilt:              r.built,
	})

	a := r.advisories[v.ID]
	if a == nil {
		a = &model.Advisory{ID: v.ID}
		r.advisories[v.ID] = a
	}
	if r.ids[p.ID] == nil {
		r.ids[p.ID] = map[string]bool{}
	}
	r.ids[p.ID][v.ID] = true
	for _, rel := range v.RelatedVulnerabilities {
		if rel.ID != "" && rel.ID != v.ID {
			a.Aliases = append(a.Aliases, rel.ID)
			r.ids[p.ID][rel.ID] = true
		}
	}
	if v.Metadata != nil {
		for _, l := range append([]string{v.Metadata.DataSource}, v.Metadata.URLs...) {
			if l != "" {
				a.Links = append(a.Links, l)
			}
		}
	}
}

// matched reports whether p has a match on any of ids, directly or through an alias.
func (r *results) matched(packageID string, ids []string) bool {
	return slices.ContainsFunc(ids, func(id string) bool { return r.ids[packageID][id] })
}

// list returns the matches with the not-affected ones first. The store keeps the last of several
// matches it canonicalises to one key, so an affected match always wins over a suppression.
func (r *results) list() []model.Match {
	out := slices.Clone(r.matches)
	slices.SortStableFunc(out, func(a, b model.Match) int {
		return cmp.Compare(rank(a), rank(b))
	})
	return out
}

func rank(m model.Match) int {
	if m.FixState == model.FixNotAffected {
		return 0
	}
	return 1
}

// advisoryList returns one advisory per matched advisory id, its aliases and links deduplicated.
func (r *results) advisoryList() []model.Advisory {
	out := make([]model.Advisory, 0, len(r.advisories))
	for _, a := range r.advisories {
		c := *a
		slices.Sort(c.Aliases)
		c.Aliases = slices.Compact(c.Aliases)
		slices.Sort(c.Links)
		c.Links = slices.Compact(c.Links)
		out = append(out, c)
	}
	slices.SortFunc(out, func(a, b model.Advisory) int { return strings.Compare(a.ID, b.ID) })
	return out
}
