package upgrade

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/semantic"

	"github.com/the-it-dept/ffs/internal/eol"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

const (
	k8sRepo     = "kubernetes"
	k8sPrefix   = "k8s:"
	runtimePref = "runtime:"
)

// resolveClusterLevel advises a Cluster or ContainerRuntime owner that has an open finding at or
// above medium, and withdraws its suggestions otherwise. A Nodes owner gets no advice: host
// packages are upgraded on the nodes, so its suggestions are always withdrawn.
func (r *Resolver) resolveClusterLevel(ctx context.Context, o model.Owner, fs []model.Finding) error {
	qualifies := o.Ref.Kind != model.OwnerKindNodes && slices.ContainsFunc(fs, func(f model.Finding) bool {
		return f.State == model.StateOpen && f.Priority >= model.PriorityMedium
	})
	if !qualifies {
		if err := r.o.Store.DeleteSuggestions(ctx, o.Ref.Key(), nil); err != nil {
			return fmt.Errorf("upgrade: delete suggestions of %s: %w", o.Ref.Key(), err)
		}
		return nil
	}
	if o.Ref.Kind == model.OwnerKindCluster {
		return r.AdviseCluster(ctx, o)
	}
	return r.AdviseRuntime(ctx, o)
}

// openOn returns the owner's open findings on repo.
func (r *Resolver) openOn(ctx context.Context, o model.Owner, repo string) ([]model.Finding, error) {
	fs, err := r.o.Store.FindingsForOwner(ctx, o.Ref.Key())
	if err != nil {
		return nil, fmt.Errorf("upgrade: findings of %s: %w", o.Ref.Key(), err)
	}
	return slices.DeleteFunc(fs, func(f model.Finding) bool { return f.ImageRepo != repo || f.State != model.StateOpen }), nil
}

// cloneSynthetic stores toDigest as a copy of the synthetic image fromDigest with every package
// version fromVer replaced by toVer, so the candidate can be matched. An existing toDigest is kept.
func (r *Resolver) cloneSynthetic(ctx context.Context, repo, fromDigest, toDigest, fromVer, toVer string) error {
	if _, ok, err := r.o.Store.GetImage(ctx, toDigest); err != nil {
		return fmt.Errorf("upgrade: image %s: %w", toDigest, err)
	} else if ok {
		return nil
	}
	pkgs, err := r.o.Store.PackagesForImage(ctx, fromDigest)
	if err != nil {
		return fmt.Errorf("upgrade: packages of %s: %w", fromDigest, err)
	}
	for i := range pkgs {
		pkgs[i].Version = strings.Replace(pkgs[i].Version, fromVer, toVer, 1)
		pkgs[i].ImageDigest = toDigest
		pkgs[i].ID = model.PackageID(toDigest, pkgs[i])
	}
	if err := r.o.Store.PutSBOM(ctx, toDigest, nil, pkgs); err != nil {
		return fmt.Errorf("upgrade: sbom of %s: %w", toDigest, err)
	}
	img := model.Image{Digest: toDigest, Repo: repo, Status: model.ImageCatalogued, Source: "inventory", CataloguedAt: r.now()}
	if err := r.o.Store.UpsertImage(ctx, img); err != nil {
		return fmt.Errorf("upgrade: image %s: %w", toDigest, err)
	}
	return nil
}

// scoreTargets matches every target digest and scores the matches together against before.
func (r *Resolver) scoreTargets(ctx context.Context, o model.Owner, repo string, before []model.Finding, digests []string) (Scored, error) {
	var ms []model.Match
	for _, d := range digests {
		got, err := r.o.Scorer.MatchCandidate(ctx, d)
		if err != nil {
			return Scored{}, fmt.Errorf("matching %s: %w", d, err)
		}
		ms = append(ms, got...)
	}
	after, err := r.o.Scorer.ScoreMatches(ctx, o, repo, ms)
	if err != nil {
		return Scored{}, fmt.Errorf("scoring: %w", err)
	}
	fixes, remaining, introduces, fixedIDs, clears := Score(before, after)
	return Scored{Fixes: fixes, Remaining: remaining, Introduces: introduces, FixedIDs: fixedIDs, ClearsUrgentHigh: clears}, nil
}

// storeAdvice records the recommendation of scored (none when nothing helps) with its candidate rows.
func (r *Resolver) storeAdvice(ctx context.Context, key, repo, fromTag string, scored []Scored, rows []store.CandidateDigest, notes []string, eolText string) error {
	sg := model.Suggestion{Repo: repo, FromTag: fromTag, Tier: model.TierNone, ComputedAt: r.now()}
	rec, alts := Recommend(scored)
	if rec != nil {
		sg = suggestionOf(repo, fromTag, *rec, sg.ComputedAt)
	}
	for _, a := range alts {
		sg.Alternatives = append(sg.Alternatives, suggestionOf(repo, fromTag, a, sg.ComputedAt))
	}
	sg.Notes, sg.EOL = notes, eolText
	if err := r.o.Store.PutSuggestion(ctx, key, sg, rows); err != nil {
		return fmt.Errorf("upgrade: store suggestion of %s on %s: %w", key, repo, err)
	}
	return nil
}

// distributionNote is the advice for k3s and rke2 clusters, whose Kubernetes and runtime ship
// together; nil for any other distribution.
func distributionNote(ci model.ClusterInfo) []string {
	if ci.Distribution == "k3s" || ci.Distribution == "rke2" {
		return []string{"upgrade to the matching " + ci.Distribution + " release"}
	}
	return nil
}

func (r *Resolver) clusterInfo(ctx context.Context) (model.ClusterInfo, error) {
	ci, _, err := r.o.Store.GetClusterInfo(ctx)
	if err != nil {
		return model.ClusterInfo{}, fmt.Errorf("upgrade: cluster info: %w", err)
	}
	return ci, nil
}

// eolOf is the end-of-life text of pv, empty when unknown or without an evaluator.
func (r *Resolver) eolOf(pv eol.ProductVersion) string {
	if r.o.EOL == nil {
		return ""
	}
	s, ok := r.o.EOL.Evaluate(pv.Product, pv.Version)
	if !ok {
		return ""
	}
	return eol.Text(s, r.now())
}

// k8sMinor is the Kubernetes versions an owner runs in one minor line, and the patch to move to.
type k8sMinor struct {
	key       string   // "1.35"
	current   []string // versions run, highest first
	target    string   // "1.35.10"
	major, mn int
}

// AdviseCluster stores the patch-release advice for a Cluster owner: per Kubernetes minor it runs,
// the newest stable patch (the release server, else the end-of-life data), scored by cloning the
// current synthetic image onto the target version and matching it. The suggestion moves the highest
// version that is behind; other minors are named in its notes.
func (r *Resolver) AdviseCluster(ctx context.Context, o model.Owner) error {
	key := o.Ref.Key()
	before, err := r.openOn(ctx, o, k8sRepo)
	if err != nil {
		return err
	}
	ci, err := r.clusterInfo(ctx)
	if err != nil {
		return err
	}

	minors := map[string]*k8sMinor{}
	var highest string
	for _, c := range o.Containers {
		v, ok := strings.CutPrefix(c.Digest, k8sPrefix)
		tv, parsed := ParseTag(v)
		if !ok || !parsed || len(tv.Release) != 3 {
			continue
		}
		mk := fmt.Sprintf("%d.%d", tv.Release[0], tv.Release[1])
		m := minors[mk]
		if m == nil {
			m = &k8sMinor{key: mk, major: tv.Release[0], mn: tv.Release[1]}
			minors[mk] = m
		}
		if !slices.Contains(m.current, v) {
			m.current = append(m.current, v)
		}
		if highest == "" || versionLess(highest, v) {
			highest = v
		}
	}
	if highest == "" {
		return nil
	}
	for _, m := range minors {
		slices.SortFunc(m.current, func(a, b string) int { return compareVersions(b, a) })
		m.target = r.patchTarget(ctx, m)
	}

	// the highest version that is behind its minor's target is the one the suggestion moves
	var moving []*k8sMinor
	for _, m := range minors {
		if m.target != "" && m.current[0] != m.target {
			moving = append(moving, m)
		}
	}
	slices.SortFunc(moving, func(a, b *k8sMinor) int { return compareVersions(b.current[0], a.current[0]) })

	eolText := r.eolOf(eol.ClusterProduct(ci.Distribution, highest))
	var notes []string
	var scored []Scored
	var rows []store.CandidateDigest
	fromTag := "v" + highest
	if len(moving) > 0 {
		primary := moving[0]
		fromTag = "v" + primary.current[0]
		var digests []string
		for _, m := range minors {
			if m.target == "" {
				continue
			}
			td := k8sPrefix + m.target
			if m.current[0] != m.target {
				if err := r.cloneSynthetic(ctx, k8sRepo, k8sPrefix+m.current[0], td, m.current[0], m.target); err != nil {
					return err
				}
			}
			digests = append(digests, td)
		}
		slices.Sort(digests)
		s, err := r.scoreTargets(ctx, o, k8sRepo, before, digests)
		if err != nil {
			return err
		}
		cur, _ := ParseTag(primary.current[0])
		tgt, _ := ParseTag(primary.target)
		s.Tag, s.IndexDigest, s.Tier = "v"+primary.target, k8sPrefix+primary.target, TierBetween(cur, tgt)
		scored = []Scored{s}
		for _, m := range moving {
			mc, _ := ParseTag(m.current[0])
			mt, _ := ParseTag(m.target)
			rows = append(rows, store.CandidateDigest{Tag: "v" + m.target, Tier: TierBetween(mc, mt), Digest: k8sPrefix + m.target})
			if m != primary && m.key != primary.key {
				notes = append(notes, fmt.Sprintf("kubelets on %s: v%s", m.key, m.target))
			}
		}
		slices.Sort(notes)
	}
	notes = append(notes, distributionNote(ci)...)
	return r.storeAdvice(ctx, key, k8sRepo, fromTag, scored, rows, notes, eolText)
}

// patchTarget returns the patch to move m's versions to: the newest stable release of the minor,
// else the end-of-life data's latest for it, else "". It is never below the versions run.
func (r *Resolver) patchTarget(ctx context.Context, m *k8sMinor) string {
	target, err := LatestPatch(ctx, r.o.HTTP, r.o.Config.Upgrades.KubernetesReleaseURL, m.major, m.mn)
	if err != nil {
		target = ""
		if r.o.EOL != nil {
			if s, ok := r.o.EOL.Evaluate(k8sRepo, m.key); ok {
				target = strings.TrimPrefix(s.Latest, "v")
			}
		}
		if tv, ok := ParseTag(target); !ok || len(tv.Release) != 3 || fmt.Sprintf("%d.%d", tv.Release[0], tv.Release[1]) != m.key {
			r.o.Log.Info("no Kubernetes patch release known for the minor", "minor", m.key, "error", err.Error())
			return ""
		}
	}
	if versionLess(target, m.current[0]) {
		return m.current[0]
	}
	return target
}

// compareVersions orders dotted release versions.
func compareVersions(a, b string) int {
	ta, _ := ParseTag(a)
	tb, _ := ParseTag(b)
	return Compare(ta, tb)
}

func versionLess(a, b string) bool { return compareVersions(a, b) < 0 }

// goCompare compares two versions with Go module semantics; ok is false when either does not parse.
func goCompare(a, b string) (int, bool) {
	va, err := semantic.Parse(a, "Go")
	if err != nil {
		return 0, false
	}
	c, err := va.CompareStr(b)
	if err != nil {
		return 0, false
	}
	return c, true
}

// AdviseRuntime stores the advice for a ContainerRuntime owner (containerd or CRI-O): the lowest
// release that fixes each open finding, preferring one in the running minor, and the highest of
// those as the target. The target is scored on a synthetic copy of the running runtime.
func (r *Resolver) AdviseRuntime(ctx context.Context, o model.Owner) error {
	key, name := o.Ref.Key(), o.Ref.Name
	before, err := r.openOn(ctx, o, name)
	if err != nil {
		return err
	}
	ci, err := r.clusterInfo(ctx)
	if err != nil {
		return err
	}

	var cur, curDigest string
	for _, c := range o.Containers {
		if _, v, ok := strings.Cut(strings.TrimPrefix(c.Digest, runtimePref), "@"); ok && strings.HasPrefix(c.Digest, runtimePref) {
			if cur == "" || versionLess(cur, v) {
				cur, curDigest = v, c.Digest
			}
		}
	}
	if cur == "" {
		return nil
	}

	var notes []string
	var scored []Scored
	var rows []store.CandidateDigest
	target, err := r.runtimeTarget(ctx, before, curDigest, cur)
	if err != nil {
		return err
	}
	if target != "" {
		td := runtimePref + name + "@" + target
		if err := r.cloneSynthetic(ctx, name, curDigest, td, cur, target); err != nil {
			return err
		}
		s, err := r.scoreTargets(ctx, o, name, before, []string{td})
		if err != nil {
			return err
		}
		tc, _ := ParseTag(cur)
		tt, _ := ParseTag(target)
		s.Tag, s.IndexDigest, s.Tier = target, td, TierBetween(tc, tt)
		scored = []Scored{s}
		rows = []store.CandidateDigest{{Tag: target, Tier: s.Tier, Digest: td}}
		notes = append(notes, name+" >= "+target)
	}
	notes = append(notes, distributionNote(ci)...)
	var eolText string
	if pv, ok := eol.ContainerRuntimeProduct(name, cur); ok {
		eolText = r.eolOf(pv)
	}
	return r.storeAdvice(ctx, key, name, cur, scored, rows, notes, eolText)
}

// runtimeTarget returns the release to move the runtime at cur to, or "" when no open finding on it
// names a later fixed version. Per finding it is the lowest fixed version above cur in cur's
// major.minor, else the lowest above cur anywhere; the target is the highest of those.
func (r *Resolver) runtimeTarget(ctx context.Context, before []model.Finding, digest, cur string) (string, error) {
	open := map[string]bool{}
	for _, f := range before {
		open[f.AdvisoryID] = true
	}
	ms, err := r.o.Store.MatchesForDigests(ctx, []string{digest})
	if err != nil {
		return "", fmt.Errorf("upgrade: matches of %s: %w", digest, err)
	}
	fixed := map[string][]string{} // advisory → fixed versions
	for _, m := range ms {
		if open[m.AdvisoryID] {
			for _, v := range m.FixedVersions {
				fixed[m.AdvisoryID] = append(fixed[m.AdvisoryID], strings.TrimPrefix(v, "v"))
			}
		}
	}
	curTag, _ := ParseTag(cur)
	var target string
	for _, id := range slices.Sorted(maps.Keys(fixed)) {
		var sameLine, anyLine string
		for _, v := range fixed[id] {
			if c, ok := goCompare(v, cur); !ok || c <= 0 {
				continue
			}
			if anyLine == "" || lessGo(v, anyLine) {
				anyLine = v
			}
			if tv, ok := ParseTag(v); ok && len(tv.Release) > 1 && len(curTag.Release) > 1 &&
				tv.Release[0] == curTag.Release[0] && tv.Release[1] == curTag.Release[1] && (sameLine == "" || lessGo(v, sameLine)) {
				sameLine = v
			}
		}
		pick := sameLine
		if pick == "" {
			pick = anyLine
		}
		if pick != "" && (target == "" || lessGo(target, pick)) {
			target = pick
		}
	}
	return target, nil
}

func lessGo(a, b string) bool {
	c, ok := goCompare(a, b)
	return ok && c < 0
}
