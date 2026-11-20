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
	"github.com/the-it-dept/ffs/internal/nodegroup"
	"github.com/the-it-dept/ffs/internal/priority"
)

const (
	cnaSource      = "cna"
	nvdSource      = "nvd"
	osvSource      = "osv"
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
	Cluster       string
	Owner         model.Owner
	Matches       []model.Match             // every source, for the owner's digests
	Packages      map[string]model.Package  // by Package.ID
	Advisories    map[string]model.Advisory // by canonical ID
	Exceptions    []ExceptionRule
	GrypeDBBuilds []time.Time       // build times of every Grype DB ffs has applied
	ImageUsers    map[string]string // digest → Image.ConfigUser, catalogued images only (absent = unknown)
	// Carry holds the owner's stored open or excepted findings on image repositories that run a
	// digest not yet catalogued (pending, unresolvable or catalogFailed), or catalogued but not yet
	// matched (store.UnmatchedDigests): what that digest holds is unknown, so a finding the matches
	// do not build stands instead of resolving (spec §6.2: never clean when not catalogued). Its
	// advisory must be in Advisories.
	Carry []model.Finding
	// Previous holds the priority of each of the owner's stored findings that is not resolved, by
	// fingerprint: it decides which EPSS edges rank the finding (priority.Thresholds). A finding
	// absent from it, new or reopening, enters at the configured edges.
	Previous       map[string]model.Priority
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

// Result is what BuildResult returns.
type Result struct {
	Findings []model.Finding
	// NotAffected holds the fingerprints of the (repository, advisory) groups that grype's
	// not-affected verdicts removed entirely: no finding was built for them.
	NotAffected map[string]bool
}

// Build returns the owner's findings, one per (image repository, canonical advisory), sorted by
// fingerprint. Matches on rejected CVEs (Advisory.Withdrawn), unknown packages, digests the owner
// does not run and Go modules in Owner.SuppressModules are ignored. All findings are open or
// excepted; Diff decides what resolved.
//
// A Nodes owner's findings are ranked with a context of their own (nodesContext): exposed through
// the node groups whose digests they affect, never privileged and with no service account.
func Build(in BuildInput) []model.Finding { return BuildResult(in).Findings }

// BuildResult is Build, also reporting which findings grype's not-affected verdict removed.
func BuildResult(in BuildInput) Result {
	repos := digestRepos(in.Owner.Containers)
	byTriple := map[triple][]model.Match{}
	for _, m := range in.Matches {
		if in.Advisories[m.AdvisoryID].Withdrawn || len(repos[m.ImageDigest]) == 0 {
			continue
		}
		p, ok := in.Packages[m.PackageID]
		if !ok || suppressed(in.Owner, p) {
			continue
		}
		t := triple{m.ImageDigest, m.PackageID, m.AdvisoryID}
		byTriple[t] = append(byTriple[t], m)
	}

	type groupKey struct{ repo, advisoryID string }
	groups := map[groupKey][]verdict{}
	notAffected := map[groupKey]bool{}
	// Sorted, so ties between equal vendor ratings resolve the same way every time.
	keys := slices.SortedFunc(maps.Keys(byTriple), func(a, b triple) int {
		return cmp.Or(strings.Compare(a.digest, b.digest), strings.Compare(a.pkgID, b.pkgID),
			strings.Compare(a.advisoryID, b.advisoryID))
	})
	for _, t := range keys {
		m, ok := precedence(byTriple[t])
		if !ok {
			for _, repo := range repos[t.digest] {
				notAffected[groupKey{repo, t.advisoryID}] = true
			}
			continue
		}
		p := in.Packages[t.pkgID]
		v := verdict{pkg: p, match: m, provisional: provisional(m, p, in.GrypeDBBuilds)}
		for _, repo := range repos[t.digest] {
			k := groupKey{repo, t.advisoryID}
			groups[k] = append(groups[k], v)
		}
	}

	b := builder{in: in, rules: sortRules(in.Exceptions)}
	if !isNodesOwner(in.Owner.Ref) {
		b.ctx = ownerContext(in.Owner, in.ImageUsers)
	}
	out := make([]model.Finding, 0, len(groups)+len(in.Carry))
	built := make(map[string]bool, len(groups))
	for k, vs := range groups {
		f := b.finding(k.repo, k.advisoryID, vs)
		built[f.Fingerprint] = true
		out = append(out, f)
	}
	for _, c := range in.Carry {
		if built[c.Fingerprint] || c.State == model.StateResolved || in.Advisories[c.AdvisoryID].Withdrawn {
			continue
		}
		built[c.Fingerprint] = true
		out = append(out, b.carried(c))
	}
	slices.SortFunc(out, func(a, b model.Finding) int { return strings.Compare(a.Fingerprint, b.Fingerprint) })
	gone := map[string]bool{}
	for k := range notAffected {
		if fp := model.FindingFingerprint(in.Cluster, in.Owner.Ref, k.repo, k.advisoryID); !built[fp] {
			gone[fp] = true
		}
	}
	return Result{Findings: out, NotAffected: gone}
}

// suppressed reports whether p is a Go module whose matches the owner ignores (Owner.SuppressModules):
// on the Nodes owner, modules that the Cluster or ContainerRuntime owner already reports.
func suppressed(o model.Owner, p model.Package) bool {
	return p.Ecosystem == "go-module" && slices.Contains(o.SuppressModules, p.Name)
}

// isNodesOwner reports whether r is the cluster-level Nodes owner, whose findings each take the
// context of the node groups they affect.
func isNodesOwner(r model.OwnerRef) bool { return r.ClusterLevel() && r.Kind == model.OwnerKindNodes }

// nodesContext is the context of a Nodes finding on digests: exposed when any container (node
// group) running one of them has exposure paths, with their sorted union. Node findings are never
// privileged and have no service account.
func nodesContext(cs []model.ContainerUse, digests []string) model.WorkloadContext {
	var c model.WorkloadContext
	for _, u := range cs {
		if len(u.ExposurePaths) > 0 && slices.Contains(digests, u.Digest) {
			c.ExposurePaths = append(c.ExposurePaths, u.ExposurePaths...)
		}
	}
	c.ExposurePaths = sortedSet(c.ExposurePaths)
	c.Exposed = len(c.ExposurePaths) > 0
	return c
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

// precedence decides what stands for one triple (spec §6.5, §13.3). Grype takes precedence only
// over OSV matches: the upstream-runtime map (CNA ranges and OSV GIT records) and Kubernetes matches
// are the authority on what they match, so a grype match beside one of them, such as an NVD CPE
// match on a binary built from source, never replaces their verdict or fix versions. Over OSV
// matches grype has an opinion only through a DB built after ffs observed them; then its match wins,
// and its not-affected verdict removes the triple. Otherwise the non-grype matches stand, merged.
func precedence(ms []model.Match) (model.Match, bool) {
	var grype *model.Match
	var others []model.Match
	osvOnly := true
	for i, m := range ms {
		switch {
		case m.Source != model.SourceGrype:
			others = append(others, m)
			osvOnly = osvOnly && m.Source == model.SourceOSV
		case grype == nil || m.DBBuilt.After(grype.DBBuilt):
			grype = &ms[i]
		}
	}
	if grype != nil && (len(others) == 0 || (osvOnly && grype.DBBuilt.After(earliestObserved(others)))) {
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
	f.Fix = fixAction(vs, fixed, b.in.Owner.Ref.Kind == model.OwnerKindNodes)
	f.Severity, f.SeveritySource = severity(vs, adv)
	b.rank(&f, adv, fixed, b.contextOf(f.Digests))
	return f
}

// carried returns the stored finding c, which the matches did not build because its repository
// runs a digest not yet catalogued or not yet matched, as it stands now: its packages, digests,
// fix state and fix action are kept, and its priority, signals and exception are re-evaluated with
// the current advisory and owner context, so a KEV listing or an expired exception still applies to
// it. A finding stored before Build set fix actions gets one from what it stored.
func (b builder) carried(c model.Finding) model.Finding {
	adv := b.in.Advisories[c.AdvisoryID]
	f := c
	f.State, f.ExceptedBy, f.ResolvedAt, f.LastSeen = model.StateOpen, "", nil, b.in.Now
	if f.Fix == nil {
		f.Fix = carriedFix(c)
	}
	if !adv.Published.IsZero() {
		f.Published = adv.Published
	}
	switch {
	case f.Severity != model.SeverityUnknown && f.SeveritySource != osvSource:
	case adv.CNASeverity != model.SeverityUnknown:
		f.Severity, f.SeveritySource = adv.CNASeverity, cnaSource
	default:
		f.Severity, f.SeveritySource = advisorySeverity(adv)
	}
	var fixed []string
	for _, p := range f.Packages {
		fixed = append(fixed, p.Fixed...)
	}
	b.rank(&f, adv, sortedSet(fixed), b.contextOf(f.Digests))
	return f
}

// contextOf is the context a finding on digests is ranked with: the owner's, or for a Nodes owner
// that of the node groups running those digests.
func (b builder) contextOf(digests []string) model.WorkloadContext {
	if isNodesOwner(b.in.Owner.Ref) {
		return nodesContext(b.in.Owner.Containers, digests)
	}
	return b.ctx
}

// rank sets f's priority, reasons and signals from its severity, fix and ctx, then applies the
// first matching exception.
func (b builder) rank(f *model.Finding, adv model.Advisory, fixed []string, ctx model.WorkloadContext) {
	pin := priority.Input{
		Severity:         f.Severity,
		SeverityPending:  f.Severity == model.SeverityUnknown,
		FixAvailable:     f.FixAvailable,
		FixState:         f.FixState,
		FixedVersions:    fixed,
		KEVAdded:         adv.KEVAdded,
		Malicious:        adv.Malicious,
		EPSS:             adv.EPSS,
		Exposed:          ctx.Exposed,
		ExposurePaths:    ctx.ExposurePaths,
		Privileged:       ctx.Privileged,
		PrivilegeReasons: ctx.PrivilegeReasons,
		PowerfulSA:       ctx.PowerfulSA,
		SAReasons:        ctx.SAReasons,
		NotRunning:       b.in.Owner.NotRunning,
		GoStdlib:         f.GoStdlib,
		Previous:         b.in.Previous[f.Fingerprint],
	}
	f.Signals = model.FindingSignals{
		Exposed: pin.Exposed, Privileged: pin.Privileged, PowerfulSA: pin.PowerfulSA, NotRunning: pin.NotRunning,
		KEV: pin.KEVAdded != nil, Malicious: pin.Malicious,
		EPSSElevated: pin.EPSS >= priority.Thresholds(pin, b.in.PriorityConfig).EPSSBump, EPSS: pin.EPSS,
	}
	f.Priority, f.Reasons = priority.Evaluate(pin, b.in.PriorityConfig)
	b.except(f, adv.Aliases, pin)
}

// except applies the first matching exception rule. A tenant rule cannot except an urgent finding:
// the finding stays open and says why (spec §6.8). Only the tenant check uses the priority computed
// without VEX; a not_affected rule then re-ranks the excepted finding.
//
// Exceptions follow the runtime cutover in both directions: a rule matches a finding when it
// matches the finding itself or its cutoverAlias, so re-homing never opens an excepted finding. The
// alias is a cluster-level owner, so only a rule's Kind/Name owner entries can match it (ownerMatches).
func (b builder) except(f *model.Finding, aliases []string, pin priority.Input) {
	alias, hasAlias := b.cutoverAlias(*f)
	i := slices.IndexFunc(b.rules, func(r ExceptionRule) bool {
		return r.Matches(*f, aliases, b.in.Now) || (hasAlias && r.Matches(alias, aliases, b.in.Now))
	})
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

// cutoverAlias returns f as it reads on the other side of the runtime cutover. A Nodes finding on a
// container runtime's module (nodegroup.RuntimeOwnerName) reads as a finding of that
// ContainerRuntime owner on the runtime's repository; a ContainerRuntime finding reads as a Nodes
// finding on the host repository. Other findings have no alias.
func (b builder) cutoverAlias(f model.Finding) (model.Finding, bool) {
	switch {
	case isNodesOwner(f.Owner):
		name, ok := nodegroup.RuntimeOwnerName(f.Packages)
		if !ok {
			return model.Finding{}, false
		}
		f.Owner, f.ImageRepo = model.OwnerRef{Kind: model.OwnerKindContainerRuntime, Name: name}, name
		return f, true
	case f.Owner.ClusterLevel() && f.Owner.Kind == model.OwnerKindContainerRuntime:
		f.Owner, f.ImageRepo = model.NodesOwner(b.in.Cluster), model.HostRepo
		return f, true
	}
	return model.Finding{}, false
}

// packages lists the affected packages, one entry per (name, ecosystem, installed, path) with the
// union of their fixed versions, so the same package on several platforms is listed once.
func packages(vs []verdict) []model.FindingPackage {
	type key struct{ name, ecosystem, installed, path string }
	index := map[key]int{}
	var out []model.FindingPackage
	for _, v := range vs {
		k := key{v.pkg.Name, v.pkg.Ecosystem, v.pkg.Installed(), v.pkg.Path}
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
// every kind of package. With none of those the CVSS vectors of the advisory's OSV records rate it,
// as source "osv": cvelistV5 backfills only 30 days, so an older CVE matched on the fast path, by
// the upstream-runtime map or on Kubernetes would otherwise stay "severity pending" for good.
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
	return advisorySeverity(adv)
}

// advisorySeverity is the advisory's own rating when no match carries one: its OSV records' CVSS.
func advisorySeverity(adv model.Advisory) (model.Severity, string) {
	if adv.OSVSeverity != model.SeverityUnknown {
		return adv.OSVSeverity, osvSource
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
