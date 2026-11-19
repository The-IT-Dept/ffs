package dashboard

import (
	"cmp"
	"slices"

	"github.com/the-it-dept/ffs/internal/findings"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/web/api"
)

const (
	goModuleEcosystem = "go-module"
	goStdlibName      = "stdlib"
)

// AttentionGroup is one owner's open findings at priority high or above, with the upgrade
// suggestions that apply to them.
type AttentionGroup struct {
	Owner       api.OwnerView
	Findings    []api.FindingView
	Stdlib      []findings.StdlibGroup
	Suggestions []api.SuggestionView
	Highest     model.Priority
}

// Attention groups fs by owner. Groups are ordered by highest priority, then urgent count, then
// owner key. A group's suggestions are those whose owner and repository match one of its findings.
func Attention(fs []api.FindingView, owners map[string]api.OwnerView, sgs []api.SuggestionView) []AttentionGroup {
	byOwner := map[string][]api.FindingView{}
	for _, f := range fs {
		byOwner[f.Owner] = append(byOwner[f.Owner], f)
	}
	out := make([]AttentionGroup, 0, len(byOwner))
	urgent := map[string]int{}
	for key, group := range byOwner {
		g := AttentionGroup{Owner: owners[key]}
		if g.Owner.ID == "" {
			g.Owner = api.OwnerView{ID: key}
		}
		repos := map[string]bool{}
		for _, f := range group {
			g.Highest = max(g.Highest, f.Priority)
			if f.Priority == model.PriorityUrgent {
				urgent[key]++
			}
			repos[f.Repo] = true
		}
		g.Stdlib, g.Findings = groupStdlib(group)
		for _, sg := range sgs {
			if sg.Owner == key && repos[sg.Repo] {
				g.Suggestions = append(g.Suggestions, sg)
			}
		}
		out = append(out, g)
	}
	slices.SortFunc(out, func(a, b AttentionGroup) int {
		return cmp.Or(cmp.Compare(b.Highest, a.Highest), cmp.Compare(urgent[b.Owner.ID], urgent[a.Owner.ID]),
			cmp.Compare(a.Owner.ID, b.Owner.ID))
	})
	return out
}

// groupStdlib splits views into Go standard library groups and the other findings.
func groupStdlib(views []api.FindingView) ([]findings.StdlibGroup, []api.FindingView) {
	in := make([]model.Finding, 0, len(views))
	byID := make(map[string]api.FindingView, len(views))
	for _, v := range views {
		byID[v.ID] = v
		f := model.Finding{Fingerprint: v.ID, AdvisoryID: v.Advisory, Priority: v.Priority}
		for _, p := range v.Packages {
			f.Packages = append(f.Packages, model.FindingPackage{Name: p.Name, Ecosystem: p.Ecosystem, Installed: p.Installed,
				Path: p.Path, Fixed: p.Fixed})
		}
		f.GoStdlib = len(v.Packages) > 0 && v.Packages[0].Ecosystem == goModuleEcosystem && v.Packages[0].Name == goStdlibName
		in = append(in, f)
	}
	groups, rest := findings.GroupStdlib(in)
	var out []api.FindingView
	for _, f := range rest {
		out = append(out, byID[f.Fingerprint])
	}
	return groups, out
}
