package upgrade

import (
	"fmt"
	"slices"
	"strings"

	"github.com/the-it-dept/ffs/internal/model"
)

// Scored is one upgrade candidate after scoring against the owner's current findings on a repo.
type Scored struct {
	Tag, IndexDigest string // the candidate tag and the digest it resolved to
	Tier             model.Tier
	Platforms        map[string]string // platform → manifest digest
	Fixes            map[model.Priority]int
	Remaining        map[model.Priority]int
	Introduces       map[model.Priority]int
	FixedIDs         []string // sorted
	ClearsUrgentHigh bool
}

// tierRank orders the tiers nearest first; anything else ranks last.
func tierRank(t model.Tier) int {
	switch t {
	case model.TierRefresh:
		return 0
	case model.TierPatch:
		return 1
	case model.TierMinor:
		return 2
	case model.TierMajor:
		return 3
	}
	return 4
}

// Score compares the open findings an owner has on a repo now (before) with the ones it would have
// on a candidate (after), by advisory. An advisory only in before is fixed, counted at its before
// priority; one in both remains, and one only in after is introduced, each counted at its after
// priority. Findings that are not open are ignored. clears reports whether every fixable urgent and
// high finding of before is fixed.
func Score(before, after []model.Finding) (fixes, remaining, introduces map[model.Priority]int, fixedIDs []string, clears bool) {
	fixes, remaining, introduces = map[model.Priority]int{}, map[model.Priority]int{}, map[model.Priority]int{}
	now, next := openByAdvisory(before), openByAdvisory(after)
	clears = true
	for id, f := range now {
		n, still := next[id]
		if still {
			remaining[n.Priority]++
			if f.FixAvailable && f.Priority >= model.PriorityHigh {
				clears = false
			}
			continue
		}
		fixes[f.Priority]++
		fixedIDs = append(fixedIDs, id)
	}
	for id, n := range next {
		if _, was := now[id]; !was {
			introduces[n.Priority]++
		}
	}
	slices.Sort(fixedIDs)
	return fixes, remaining, introduces, fixedIDs, clears
}

func openByAdvisory(fs []model.Finding) map[string]model.Finding {
	out := map[string]model.Finding{}
	for _, f := range fs {
		if f.State == model.StateOpen {
			out[f.AdvisoryID] = f
		}
	}
	return out
}

// Recommend picks the nearest candidate that helps (spec §6.7.3). Only refresh, patch and minor
// candidates that fix something are eligible; major is never recommended. The first eligible
// candidate, nearest tier first, that clears every fixable urgent and high finding, introduces no
// urgent or high one, and either fixes more findings at medium or above than it introduces or does
// not make medium and low worse (net medium and low change of zero or more) wins. Failing that, the
// eligible candidate with the best net change wins:
// urgent, then high, then medium and low together, net of what it introduces, with ties going to the
// nearer tier. A best net change of nothing leaves no recommendation. The alternatives are the
// candidates of further tiers (every candidate when there is no recommendation) that fix an advisory
// the recommendation does not, nearest tier first.
func Recommend(cands []Scored) (rec *Scored, alts []Scored) {
	ordered := slices.Clone(cands)
	slices.SortStableFunc(ordered, func(a, b Scored) int { return tierRank(a.Tier) - tierRank(b.Tier) })

	var eligible []Scored
	for _, c := range ordered {
		if tierRank(c.Tier) < tierRank(model.TierMajor) && total(c.Fixes) > 0 {
			eligible = append(eligible, c)
		}
	}
	for _, c := range eligible {
		if clearsWithoutHarm(c) {
			rec = &c
			break
		}
	}
	if rec == nil {
		var best *Scored
		for _, c := range eligible {
			if best == nil || compareNet(net(c), net(*best)) > 0 {
				best = &c
			}
		}
		if best != nil && compareNet(net(*best), [3]int{}) > 0 {
			rec = best
		}
	}

	for _, c := range ordered {
		if rec != nil && tierRank(c.Tier) <= tierRank(rec.Tier) {
			continue
		}
		var covered []string
		if rec != nil {
			covered = rec.FixedIDs
		}
		if slices.ContainsFunc(c.FixedIDs, func(id string) bool { return !slices.Contains(covered, id) }) {
			alts = append(alts, c)
		}
	}
	return rec, alts
}

// clearsWithoutHarm is the first rule: c clears every fixable urgent and high finding and introduces
// none, and makes a net improvement at medium or above (it fixes more urgent, high and medium
// findings than it introduces) or leaves the net medium and low change non-negative. Without urgent
// or high findings clearing is vacuous, so the second half keeps a candidate that fixes one low, or
// one medium, finding from winning while it introduces more mediums.
func clearsWithoutHarm(c Scored) bool {
	if !c.ClearsUrgentHigh || c.Introduces[model.PriorityUrgent]+c.Introduces[model.PriorityHigh] > 0 {
		return false
	}
	d := net(c)
	improves := d[0]+d[1]+c.Fixes[model.PriorityMedium]-c.Introduces[model.PriorityMedium] > 0
	return improves || d[2] >= 0
}

func total(m map[model.Priority]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

// net is (urgent, high, medium and low) fixed minus introduced.
func net(c Scored) [3]int {
	d := func(p model.Priority) int { return c.Fixes[p] - c.Introduces[p] }
	return [3]int{d(model.PriorityUrgent), d(model.PriorityHigh), d(model.PriorityMedium) + d(model.PriorityLow)}
}

func compareNet(a, b [3]int) int {
	for i := range a {
		if a[i] != b[i] {
			return a[i] - b[i]
		}
	}
	return 0
}

// NetChange describes a suggestion's effect: "fixes 1 urgent, 2 high; introduces none".
func NetChange(s model.Suggestion) string {
	return "fixes " + counts(s.Fixes) + "; introduces " + counts(s.Introduces)
}

// counts lists the non-zero counts urgent first, or "none".
func counts(m map[model.Priority]int) string {
	var parts []string
	for p := model.PriorityUrgent; p >= model.PriorityLow; p-- {
		if n := m[p]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, p))
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

// syntheticRepos are the cluster-level subjects, whose versions read "kubernetes v1.35.10".
var syntheticRepos = map[string]bool{"kubernetes": true, "containerd": true, "cri-o": true}

// Target is what a suggestion moves to, as a user would write it: "nginx:1.30.7",
// "ghcr.io/org/app:2.1.0 (new digest)" for a refresh, or "kubernetes v1.35.10". It is empty for a
// suggestion with tier none.
func Target(s model.Suggestion) string {
	if s.Tier == model.TierNone {
		return ""
	}
	if syntheticRepos[s.Repo] {
		return s.Repo + " " + s.ToTag
	}
	repo := strings.TrimPrefix(s.Repo, "docker.io/library/")
	repo = strings.TrimPrefix(repo, "docker.io/")
	t := repo + ":" + s.ToTag
	if s.Tier == model.TierRefresh {
		t += " (new digest)"
	}
	return t
}
