// Package findings turns an owner's matches into findings and diffs them against the stored ones.
// It is pure: the caller supplies every input, including the time.
package findings

import (
	"cmp"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/priority"
)

const (
	cnaSource      = "cna"
	nvdSource      = "nvd"
	vexNotAffected = "not_affected"
	runsAsRoot     = "runs as root"
)

// grypeCovered holds the syft package types grype v0.122.1 has matchers for. An OSV verdict on any
// other type has no grype opinion to wait for, so it is never provisional (spec §6.5).
var grypeCovered = map[string]bool{
	"deb": true, "rpm": true, "apk": true, "alpm": true, "portage": true, "npm": true, "python": true,
	"go-module": true, "java-archive": true, "jenkins-plugin": true, "gem": true, "rust-crate": true,
	"dotnet": true, "php-composer": true, "hex": true, "bitnami": true,
}

// fixRank orders fix states when non-grype matches on one package merge. Anything else ranks 0.
var fixRank = map[model.FixState]int{model.FixFixed: 3, model.FixNotFixed: 2, model.FixWontFix: 1}

// BuildInput is everything Build needs for one owner.
type BuildInput struct {
	Cluster        string
	Owner          model.Owner
	Matches        []model.Match             // every source, for the owner's digests
	Packages       map[string]model.Package  // by Package.ID
	Advisories     map[string]model.Advisory // by canonical ID
	Exceptions     []ExceptionRule
	GrypeDBBuilds  []time.Time       // build times of every Grype DB ffs has applied
	ImageUsers     map[string]string // digest → Image.ConfigUser, catalogued images only (absent = unknown)
	Now            time.Time
	PriorityConfig config.PriorityConfig
}

// triple is the unit precedence between matchers is decided on.
type triple struct{ digest, pkgID, advisoryID string }

// verdict is what stands for one triple once precedence is applied.
type verdict struct {
	pkg         model.Package
	match       model.Match // the grype match, or the non-grype matches merged
	provisional bool
}

// Build returns the owner's findings, one per (image repository, canonical advisory), sorted by
// fingerprint. Matches on rejected CVEs (Advisory.Withdrawn), unknown packages and digests the owner
// does not run are ignored. All findings are open or excepted; Diff decides what resolved.
func Build(in BuildInput) []model.Finding {
	repos := digestRepos(in.Owner.Containers)
	byTriple := map[triple][]model.Match{}
	for _, m := range in.Matches {
		if in.Advisories[m.AdvisoryID].Withdrawn || len(repos[m.ImageDigest]) == 0 {
			continue
		}
		if _, ok := in.Packages[m.PackageID]; !ok {
			continue
		}
		t := triple{m.ImageDigest, m.PackageID, m.AdvisoryID}
		byTriple[t] = append(byTriple[t], m)
	}

	type groupKey struct{ repo, advisoryID string }
	groups := map[groupKey][]verdict{}
	// Sorted, so ties between equal vendor ratings resolve the same way every time.
	keys := slices.SortedFunc(maps.Keys(byTriple), func(a, b triple) int {
		return cmp.Or(strings.Compare(a.digest, b.digest), strings.Compare(a.pkgID, b.pkgID),
			strings.Compare(a.advisoryID, b.advisoryID))
	})
	for _, t := range keys {
		m, ok := precedence(byTriple[t])
		if !ok {
			continue
		}
		p := in.Packages[t.pkgID]
		v := verdict{pkg: p, match: m, provisional: provisional(m, p, in.GrypeDBBuilds)}
		for _, repo := range repos[t.digest] {
			k := groupKey{repo, t.advisoryID}
			groups[k] = append(groups[k], v)
		}
	}

	b := builder{in: in, ctx: ownerContext(in.Owner, in.ImageUsers), rules: sortRules(in.Exceptions)}
	out := make([]model.Finding, 0, len(groups))
	for k, vs := range groups {
		out = append(out, b.finding(k.repo, k.advisoryID, vs))
	}
	slices.SortFunc(out, func(a, b model.Finding) int { return strings.Compare(a.Fingerprint, b.Fingerprint) })
	return out
}

// digestRepos maps each non-empty container digest to the sorted repositories it runs as.
func digestRepos(cs []model.ContainerUse) map[string][]string {
	out := map[string][]string{}
	for _, c := range cs {
		if c.Digest != "" && !slices.Contains(out[c.Digest], c.Repo) {
			out[c.Digest] = append(out[c.Digest], c.Repo)
		}
	}
	for _, rs := range out {
		slices.Sort(rs)
	}
	return out
}

// precedence decides what stands for one triple (spec §6.5, §13.3). Grype has an opinion only
// through a DB built after ffs observed the other matches on the triple; then its match wins, and
// its not-affected verdict removes the triple. Otherwise the non-grype matches stand, merged.
func precedence(ms []model.Match) (model.Match, bool) {
	var grype *model.Match
	var others []model.Match
	for i, m := range ms {
		switch {
		case m.Source != model.SourceGrype:
			others = append(others, m)
		case grype == nil || m.DBBuilt.After(grype.DBBuilt):
			grype = &ms[i]
		}
	}
	if grype != nil && (len(others) == 0 || grype.DBBuilt.After(earliestObserved(others))) {
		return *grype, grype.FixState != model.FixNotAffected
	}
	return merge(others), true
}

func earliestObserved(ms []model.Match) time.Time {
	t := ms[0].ObservedAt
	for _, m := range ms[1:] {
		if m.ObservedAt.Before(t) {
			t = m.ObservedAt
		}
	}
	return t
}

// merge combines the non-grype matches on one triple: the union of fixed versions, the best fix
// state, the earliest observation and the highest vendor rating from OSV (upstream and Kubernetes
// matches use the CNA rating only, so their vendor ratings are dropped). Source stays OSV only when
// every match is OSV, since only an OSV verdict can be provisional.
func merge(ms []model.Match) model.Match {
	out := ms[0]
	out.FixState, out.FixedVersions = model.FixUnknown, nil
	out.VendorSeverity, out.VendorSeveritySource = model.SeverityUnknown, ""
	for _, m := range ms {
		if m.Source != model.SourceOSV {
			out.Source = m.Source
		} else if m.VendorSeverity > out.VendorSeverity {
			out.VendorSeverity, out.VendorSeveritySource = m.VendorSeverity, m.VendorSeveritySource
		}
		out.FixedVersions = append(out.FixedVersions, m.FixedVersions...)
		if fixRank[m.FixState] > fixRank[out.FixState] {
			out.FixState = m.FixState
		}
		if m.ObservedAt.Before(out.ObservedAt) {
			out.ObservedAt = m.ObservedAt
		}
	}
	out.FixedVersions = sortedSet(out.FixedVersions)
	return out
}

// provisional reports whether a standing match still waits on grype (spec §6.5): an OSV verdict on
// a package type grype covers, other than the Go standard library (Go vulndb is its authority),
// until two grype DBs built after the observation have been applied.
func provisional(m model.Match, p model.Package, builds []time.Time) bool {
	if m.Source != model.SourceOSV || !grypeCovered[p.Ecosystem] || p.GoStdlib {
		return false
	}
	after := 0
	for _, b := range builds {
		if b.After(m.ObservedAt) {
			after++
		}
	}
	return after < 2
}

// ownerContext returns the owner's workload context, privileged with the reason "runs as root"
// when a container runs as its image's user and that catalogued image sets none or root (spec §6.6).
func ownerContext(o model.Owner, imageUsers map[string]string) model.WorkloadContext {
	c := o.Context
	if slices.ContainsFunc(o.Containers, func(u model.ContainerUse) bool {
		return u.RootUnlessImageUser && rootUser(imageUsers, u.Digest)
	}) {
		c.Privileged = true
		c.PrivilegeReasons = sortedSet(append(slices.Clone(c.PrivilegeReasons), runsAsRoot))
	}
	return c
}

// rootUser reports whether the image config user of digest is known and is root.
func rootUser(imageUsers map[string]string, digest string) bool {
	u, ok := imageUsers[digest]
	if !ok {
		return false
	}
	name, _, _ := strings.Cut(u, ":")
	return name == "" || name == "0" || name == "root"
}

// sortRules orders exception rules cluster-wide first, then by key, so the first match is stable.
func sortRules(rules []ExceptionRule) []ExceptionRule {
	out := slices.Clone(rules)
	slices.SortFunc(out, func(a, b ExceptionRule) int {
		if a.ClusterWide != b.ClusterWide {
			if a.ClusterWide {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Key(), b.Key())
	})
	return out
}

// builder turns the verdicts of one (repo, advisory) group into a finding.
type builder struct {
	in    BuildInput
	ctx   model.WorkloadContext
	rules []ExceptionRule
}

func (b builder) finding(repo, advisoryID string, vs []verdict) model.Finding {
	adv := b.in.Advisories[advisoryID]
	f := model.Finding{
		Fingerprint: model.FindingFingerprint(b.in.Cluster, b.in.Owner.Ref, repo, advisoryID),
		Owner:       b.in.Owner.Ref,
		ImageRepo:   repo,
		AdvisoryID:  advisoryID,
		Packages:    packages(vs),
		FixState:    fixState(vs),
		State:       model.StateOpen,
		Published:   adv.Published,
		Observed:    adv.Observed,
		Matched:     b.in.Now,
		LastSeen:    b.in.Now,
		Provisional: true,
		GoStdlib:    true,
	}
	var digests, fixed []string
	for _, v := range vs {
		digests = append(digests, v.match.ImageDigest)
		fixed = append(fixed, v.match.FixedVersions...)
		f.Provisional = f.Provisional && v.provisional
		f.GoStdlib = f.GoStdlib && v.pkg.GoStdlib
	}
	f.Digests, fixed = sortedSet(digests), sortedSet(fixed)
	f.FixAvailable = len(fixed) > 0 || f.FixState == model.FixFixed
	f.Severity, f.SeveritySource = severity(vs, adv)

	pin := priority.Input{
		Severity:         f.Severity,
		SeverityPending:  f.Severity == model.SeverityUnknown,
		FixAvailable:     f.FixAvailable,
		FixState:         f.FixState,
		FixedVersions:    fixed,
		KEVAdded:         adv.KEVAdded,
		Malicious:        adv.Malicious,
		EPSS:             adv.EPSS,
		Exposed:          b.ctx.Exposed,
		ExposurePaths:    b.ctx.ExposurePaths,
		Privileged:       b.ctx.Privileged,
		PrivilegeReasons: b.ctx.PrivilegeReasons,
		PowerfulSA:       b.ctx.PowerfulSA,
		SAReasons:        b.ctx.SAReasons,
		NotRunning:       b.in.Owner.NotRunning,
		GoStdlib:         f.GoStdlib,
	}
	f.Priority, f.Reasons = priority.Evaluate(pin, b.in.PriorityConfig)
	b.except(&f, adv.Aliases, pin)
	return f
}

// except applies the first matching exception rule. A tenant rule cannot except an urgent finding:
// the finding stays open and says why (spec §6.8). Only the tenant check uses the priority computed
// without VEX; a not_affected rule then re-ranks the excepted finding.
func (b builder) except(f *model.Finding, aliases []string, pin priority.Input) {
	i := slices.IndexFunc(b.rules, func(r ExceptionRule) bool { return r.Matches(*f, aliases, b.in.Now) })
	if i < 0 {
		return
	}
	r := b.rules[i]
	if !r.ClusterWide && f.Priority == model.PriorityUrgent {
		f.Reasons = append(f.Reasons,
			"exception "+r.Key()+" not applied: urgent findings can only be excepted from the ffs namespace")
		return
	}
	f.State, f.ExceptedBy = model.StateExcepted, r.Key()
	if r.VEXStatus == vexNotAffected {
		pin.VEXNotAffected = true
		f.Priority, f.Reasons = priority.Evaluate(pin, b.in.PriorityConfig)
	}
}

// packages lists the affected packages, one entry per (name, ecosystem, installed, path) with the
// union of their fixed versions, so the same package on several platforms is listed once.
func packages(vs []verdict) []model.FindingPackage {
	type key struct{ name, ecosystem, installed, path string }
	index := map[key]int{}
	var out []model.FindingPackage
	for _, v := range vs {
		k := key{v.pkg.Name, v.pkg.Ecosystem, installed(v.pkg), v.pkg.Path}
		i, ok := index[k]
		if !ok {
			i = len(out)
			index[k] = i
			out = append(out, model.FindingPackage{Name: k.name, Ecosystem: k.ecosystem, Installed: k.installed, Path: k.path})
		}
		out[i].Fixed = append(out[i].Fixed, v.match.FixedVersions...)
	}
	for i := range out {
		out[i].Fixed = sortedSet(out[i].Fixed)
	}
	slices.SortFunc(out, func(a, b model.FindingPackage) int {
		return cmp.Or(strings.Compare(a.Name, b.Name), strings.Compare(a.Ecosystem, b.Ecosystem),
			strings.Compare(a.Installed, b.Installed), strings.Compare(a.Path, b.Path))
	})
	return out
}

// installed is the package version with its epoch, unless the version already carries it (dpkg's does).
func installed(p model.Package) string {
	if p.Epoch == "" || strings.HasPrefix(p.Version, p.Epoch+":") {
		return p.Version
	}
	return p.Epoch + ":" + p.Version
}

// fixState is fixed when any standing match is, wont-fix when all are, else not-fixed when any is.
func fixState(vs []verdict) model.FixState {
	n := map[model.FixState]int{}
	for _, v := range vs {
		n[v.match.FixState]++
	}
	switch {
	case n[model.FixFixed] > 0:
		return model.FixFixed
	case n[model.FixWontFix] == len(vs):
		return model.FixWontFix
	case n[model.FixNotFixed] > 0:
		return model.FixNotFixed
	}
	return model.FixUnknown
}

// severity picks the rating priority uses and its source (spec §6.5, §13.1). A standing match's
// vendor rating is the distro's for OS packages and GHSA's or the ecosystem's for language packages;
// upstream and Kubernetes matches carry none (see merge), so they fall to the CNA rating. The highest
// vendor rating wins, then the CNA rating, then a rating grype took from NVD, which comes last for
// every kind of package.
func severity(vs []verdict, adv model.Advisory) (model.Severity, string) {
	vendor, vendorSource, nvd := model.SeverityUnknown, "", model.SeverityUnknown
	for _, v := range vs {
		s, src := v.match.VendorSeverity, v.match.VendorSeveritySource
		switch {
		case src == nvdSource:
			nvd = max(nvd, s)
		case s > vendor:
			vendor, vendorSource = s, src
		}
	}
	switch {
	case vendor != model.SeverityUnknown:
		return vendor, vendorSource
	case adv.CNASeverity != model.SeverityUnknown:
		return adv.CNASeverity, cnaSource
	case nvd != model.SeverityUnknown:
		return nvd, nvdSource
	}
	return model.SeverityUnknown, ""
}

// sortedSet returns the sorted, de-duplicated strings, or nil when there are none.
func sortedSet(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	s = slices.Clone(s)
	slices.Sort(s)
	return slices.Compact(s)
}
