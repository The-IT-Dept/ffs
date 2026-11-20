package apiserver

import (
	"time"

	"github.com/the-it-dept/ffs/internal/eol"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
	"github.com/the-it-dept/ffs/internal/upgrade"
	"github.com/the-it-dept/ffs/internal/web/apigen"
)

const dateFmt = "2006-01-02"

// priorityOf names p in the API; PriorityNone, whose String is "", is "none".
func priorityOf(p model.Priority) apigen.Priority {
	if p == model.PriorityNone {
		return apigen.PriorityNone
	}
	return apigen.Priority(p.String())
}

// modelPriority is the inverse of priorityOf; anything unknown is PriorityNone.
func modelPriority(p apigen.Priority) model.Priority {
	if p == apigen.PriorityNone {
		return model.PriorityNone
	}
	mp, err := model.ParsePriority(string(p))
	if err != nil {
		return model.PriorityNone
	}
	return mp
}

func priorityCounts(c store.PriorityCounts) apigen.PriorityCounts {
	return apigen.PriorityCounts{Urgent: c.Urgent, High: c.High, Medium: c.Medium, Low: c.Low}
}

func countsOfMap(m map[model.Priority]int) apigen.PriorityCounts {
	return apigen.PriorityCounts{Urgent: m[model.PriorityUrgent], High: m[model.PriorityHigh], Medium: m[model.PriorityMedium],
		Low: m[model.PriorityLow]}
}

func coverageFigure(c store.CoverageFigure) apigen.CoverageFigure {
	return apigen.CoverageFigure{InUse: c.InUse, SeenInto: c.SeenInto, Full: c.Full}
}

// workloadRef names an owner; a cluster-level owner has an empty namespace.
func workloadRef(o model.OwnerRef) apigen.WorkloadRef {
	return apigen.WorkloadRef{Scope: model.Scope{Kind: model.ScopeWorkload, Value: o.Key()}.String(), Kind: o.Kind,
		Namespace: o.Namespace, Name: o.Name}
}

func scopeRef(sc model.Scope, label string) apigen.ScopeRef {
	return apigen.ScopeRef{Scope: sc.String(), Kind: apigen.ScopeKind(sc.Kind), Label: label}
}

func managedBy(m *model.ManagedBy) *apigen.ManagedBy {
	if m == nil {
		return nil
	}
	return &apigen.ManagedBy{Tool: m.Tool, Name: m.Name, Namespace: optString(m.Namespace)}
}

// suggestionOf shapes an upgrade suggestion, with its target and net change as the notifications
// word them.
func suggestionOf(sg model.Suggestion) apigen.Suggestion {
	out := apigen.Suggestion{
		Repo: sg.Repo, FromTag: sg.FromTag, ToTag: sg.ToTag, ToDigest: optString(sg.ToDigest), Tier: string(sg.Tier),
		Target: upgrade.Target(sg), NetChange: upgrade.NetChange(sg),
		Fixes: countsOfMap(sg.Fixes), Remaining: countsOfMap(sg.Remaining), Introduces: countsOfMap(sg.Introduces),
		FixedIds: nz(sg.FixedIDs), Eol: optString(sg.EOL), Notes: nz(sg.Notes), Alternatives: []apigen.Suggestion{},
		ComputedAt: optTime(sg.ComputedAt),
	}
	for _, alt := range sg.Alternatives {
		out.Alternatives = append(out.Alternatives, suggestionOf(alt))
	}
	return out
}

// fixActionOf shapes the action that clears f (Finding.EffectiveFix). Only an upgrade carries what
// it introduces.
func fixActionOf(f model.Finding) apigen.FixAction {
	fa := f.EffectiveFix()
	out := apigen.FixAction{Kind: apigen.FixKind(fa.Kind), Key: fa.Key, Label: fa.Label}
	switch fa.Kind {
	case model.FixKindRebuild:
		out.Title = optString(model.FixTitleRebuild)
	case model.FixKindPackage:
		out.Package, out.Ecosystem = optString(fa.Package), optString(fa.Ecosystem)
		out.From, out.To = optString(fa.From), optString(fa.To)
	case model.FixKindUpgrade:
		if sg := f.Suggestion; sg != nil {
			intro := countsOfMap(sg.Introduces)
			out.Repo, out.FromTag, out.ToTag = optString(sg.Repo), optString(sg.FromTag), optString(sg.ToTag)
			out.Tier, out.Introduces = optString(string(sg.Tier)), &intro
		}
	case model.FixKindNone, model.FixKindWontFix:
	}
	return out
}

// signalsOf lists the signals f carries, in the read model's order; empty, not nil, when none.
func signalsOf(f model.Finding) []apigen.Signal {
	out := []apigen.Signal{}
	for _, s := range model.SignalsOf(f.SignalBits()) {
		out = append(out, apigen.Signal(s))
	}
	return out
}

func findingPackages(ps []model.FindingPackage) []apigen.FindingPackage {
	out := make([]apigen.FindingPackage, 0, len(ps))
	for _, p := range ps {
		out = append(out, apigen.FindingPackage{Name: p.Name, Ecosystem: p.Ecosystem, Installed: p.Installed, Path: optString(p.Path),
			Fixed: nz(p.Fixed)})
	}
	return out
}

// eolOf shapes a lifecycle status. Its text is eol.Support, so a status with no end-of-life date
// still says something: "Debian 12 supported until 2028-06-30", "Alpine Linux: rolling release".
func eolOf(st eol.Status, now time.Time) apigen.EOL {
	out := apigen.EOL{Product: st.Product, Cycle: st.Cycle, IsEol: st.IsEOL, Latest: st.Latest, Note: st.Note, Text: eol.Support(st, now)}
	if st.EOLDate != nil {
		out.EolDate = st.EOLDate.UTC().Format(dateFmt)
	}
	return out
}

// nz returns s, or an empty slice for nil, so JSON lists are never null.
func nz[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// optString is s as an optional member: nil when empty.
func optString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// optTime is t in UTC as an optional member: nil when zero.
func optTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}
