package notify

import (
	"time"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

// classify names what a finding's latest transition means to a target, given what the target was
// last told about it (l, nil when never). "" means there is nothing to report (spec §6.10, never
// twice): only a first sighting, an escalation above what was sent, a reopening, a resolution of
// something sent, or a fix appearing (digest only) count.
func classify(t model.Transition, l *store.LedgerEntry) Event {
	if t.Trigger == model.TriggerUpgradeAvailable {
		return "" // never an alert of its own: the digest lists it (see digest)
	}
	switch t.ToState {
	case model.StateOpen:
		switch {
		case l == nil:
			return EventDetected
		case l.LastState == model.StateResolved || l.LastState == model.StateExcepted:
			return EventReopened
		case t.ToPriority > l.MaxPriority:
			return EventEscalated
		case t.Trigger == model.TriggerFixAvailable:
			return EventFixAvailable
		}
	case model.StateResolved:
		if l != nil && l.LastState == model.StateOpen {
			return EventResolved
		}
	}
	return ""
}

// immediateEligible reports whether ev goes to the target now rather than waiting for its digest.
// Provisional findings alert immediately only when urgent (spec §6.5); a resolution is sent
// immediately when what was sent before was itself at the immediate threshold.
func immediateEligible(c TargetConfig, ev Event, t model.Transition, l *store.LedgerEntry) bool {
	if !c.allows(t.Owner.Namespace) {
		return false
	}
	switch ev {
	case EventDetected, EventEscalated, EventReopened:
		return t.ToPriority >= c.ImmediateMin && (!t.Provisional || t.ToPriority == model.PriorityUrgent)
	case EventResolved:
		return l != nil && l.MaxPriority >= c.ImmediateMin
	}
	return false
}

// ledgerAfter is the target's ledger entry once ev has been reported. A fix appearing leaves the
// entry as it was.
func ledgerAfter(uid string, ev Event, t model.Transition, l *store.LedgerEntry, now time.Time) (store.LedgerEntry, bool) {
	e := store.LedgerEntry{Target: uid, Fingerprint: t.Fingerprint, LastState: model.StateOpen, UpdatedAt: now}
	switch ev {
	case EventDetected, EventEscalated:
		e.MaxPriority = t.ToPriority
		if l != nil {
			e.MaxPriority = max(l.MaxPriority, t.ToPriority)
		}
	case EventReopened:
		e.MaxPriority = t.ToPriority
	case EventResolved:
		e.MaxPriority, e.LastState = l.MaxPriority, model.StateResolved
	default:
		return store.LedgerEntry{}, false
	}
	return e, true
}

// excepted is the ledger entry when a finding the target was told about becomes excepted: the
// next reopening (an expired exception) is then reported as such.
func excepted(uid string, t model.Transition, l *store.LedgerEntry, now time.Time) (store.LedgerEntry, bool) {
	if t.ToState != model.StateExcepted || l == nil || l.LastState == model.StateExcepted {
		return store.LedgerEntry{}, false
	}
	return store.LedgerEntry{Target: uid, Fingerprint: t.Fingerprint, MaxPriority: l.MaxPriority,
		LastState: model.StateExcepted, UpdatedAt: now}, true
}

// latest is a run of transitions reduced per fingerprint: the last transition of each, in
// first-seen order, and whether any was a fix appearing. UpgradeAvailable transitions are kept
// apart, the last per fingerprint in first-seen order, and never become a final transition.
type latest struct {
	order        []string
	final        map[string]model.Transition
	fixSeen      map[string]bool
	upgradeOrder []string
	upgrades     map[string]model.Transition
}

func reduce(ts []model.Transition) latest {
	r := latest{final: map[string]model.Transition{}, fixSeen: map[string]bool{}, upgrades: map[string]model.Transition{}}
	for _, t := range ts {
		if t.Trigger == model.TriggerUpgradeAvailable {
			if _, ok := r.upgrades[t.Fingerprint]; !ok {
				r.upgradeOrder = append(r.upgradeOrder, t.Fingerprint)
			}
			r.upgrades[t.Fingerprint] = t
			continue
		}
		if _, ok := r.final[t.Fingerprint]; !ok {
			r.order = append(r.order, t.Fingerprint)
		}
		r.final[t.Fingerprint] = t
		if t.Trigger == model.TriggerFixAvailable {
			r.fixSeen[t.Fingerprint] = true
		}
	}
	return r
}

// entry returns a pointer to the ledger entry of fp, nil when there is none.
func entry(m map[string]store.LedgerEntry, fp string) *store.LedgerEntry {
	if e, ok := m[fp]; ok {
		return &e
	}
	return nil
}
