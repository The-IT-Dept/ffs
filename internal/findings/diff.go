package findings

import (
	"maps"
	"slices"
	"time"

	"github.com/the-it-dept/ffs/internal/model"
)

// Causes is the set of reasons an owner was queued for the recompute Diff labels. An owner queued
// more than once before its recompute keeps every reason, so each transition takes the trigger of
// the reason that explains it, not one trigger for the whole recompute.
type Causes uint8

const (
	// CauseNewAdvisory: a feed changed the owner's matches (NewAdvisory).
	CauseNewAdvisory Causes = 1 << iota
	// CauseInventory: the owner's containers, context or existence changed (InventoryChange).
	CauseInventory
	// CausePriority: enrichment changed an advisory's KEV, EPSS or CNA data (PriorityChange).
	CausePriority
	// CauseException: an exception rule changed or expired.
	CauseException
)

// CausesOf is the cause a single trigger stands for: ExceptionExpired for an exception change, and
// PriorityChange for any trigger that names no other cause.
func CausesOf(t model.Trigger) Causes {
	switch t {
	case model.TriggerNewAdvisory:
		return CauseNewAdvisory
	case model.TriggerInventoryChange:
		return CauseInventory
	case model.TriggerExceptionExpired:
		return CauseException
	}
	return CausePriority
}

func (c Causes) has(x Causes) bool { return c&x != 0 }

// Top is the trigger of the highest-ranked cause: NewAdvisory, then InventoryChange, then
// PriorityChange, which also stands for an exception change.
func (c Causes) Top() model.Trigger {
	switch {
	case c.has(CauseNewAdvisory):
		return model.TriggerNewAdvisory
	case c.has(CauseInventory):
		return model.TriggerInventoryChange
	}
	return model.TriggerPriorityChange
}

// appeared labels a finding n that is created or reopens from resolved: the cause that produced its
// match, a feed before an inventory change, or else the exception change that queued the owner (the
// exception trigger, ExceptionExpired, for an open finding) or the enrichment.
//
// A finding that appears already excepted in an exception change's recompute is PriorityChange,
// the label of an exception being applied (see excepted): the trigger enum's only exception value,
// ExceptionExpired, says an exception lapsed, which is the opposite of what happened. A dedicated
// value would be an additive enum and API change, which this release does not make.
func (c Causes) appeared(n model.Finding) model.Trigger {
	switch {
	case c.has(CauseNewAdvisory):
		return model.TriggerNewAdvisory
	case c.has(CauseInventory):
		return model.TriggerInventoryChange
	case c.has(CauseException) && n.State == model.StateOpen:
		return model.TriggerExceptionExpired
	}
	return model.TriggerPriorityChange
}

// excepted labels an open finding becoming excepted: the exception change or the priority change
// that let a rule apply, PriorityChange, when either queued the owner.
func (c Causes) excepted() model.Trigger {
	if c.has(CauseException | CausePriority) {
		return model.TriggerPriorityChange
	}
	return c.Top()
}

// confirmed labels a provisional finding's confirmation (see change). The trigger enum has no
// confirmation value; the closest is NewAdvisory, Grype's DB ruling on it, or InventoryChange when
// only a rollout, whose new digest grype matched, queued the owner.
func (c Causes) confirmed() model.Trigger {
	if c.has(CauseInventory) && !c.has(CauseNewAdvisory) {
		return model.TriggerInventoryChange
	}
	return model.TriggerNewAdvisory
}

// resolved labels a stored finding that was not built. A provisional one w says was withdrawn
// resolves as Withdrawn. One the owner no longer runs every digest of, after an inventory change,
// was fixed by the rollout (spec §6.7.5) or went with its owner: InventoryChange, even when a feed
// also queued the owner. Anything else takes the top cause.
func (c Causes) resolved(o model.Finding, w Withdrawals) model.Trigger {
	switch {
	case o.Provisional && w.withdrawn(o, c):
		return model.TriggerWithdrawn
	case c.has(CauseInventory) && !w.runsAll(o):
		return model.TriggerInventoryChange
	}
	return c.Top()
}

// Withdrawals tells Diff why stored findings that were not built disappeared.
type Withdrawals struct {
	// NotAffected holds the fingerprints grype's not-affected verdict removed (Result.NotAffected).
	NotAffected map[string]bool
	// Digests are the digests the owner runs now; nil when it is gone.
	Digests []string
}

// withdrawn reports whether the stored finding o, which was not built, was withdrawn rather than
// fixed or removed: grype says the package is not affected (spec §6.5), or something other than an
// inventory change (a feed) dropped it while the owner still runs every digest it was found in.
func (w Withdrawals) withdrawn(o model.Finding, c Causes) bool {
	if w.NotAffected[o.Fingerprint] {
		return true
	}
	return c&^CauseInventory != 0 && w.runsAll(o)
}

// runsAll reports whether the owner still runs every digest o was found in.
func (w Withdrawals) runsAll(o model.Finding) bool {
	if len(o.Digests) == 0 {
		return false
	}
	for _, d := range o.Digests {
		if !slices.Contains(w.Digests, d) {
			return false
		}
	}
	return true
}

// Diff compares an owner's stored findings with the ones Build just produced. It returns the
// findings to upsert, sorted by fingerprint, and at most one transition per fingerprint (spec §6.6).
//
// A built finding keeps Matched and Suggestion from its stored one, takes the earlier non-zero of
// its stored and built Observed (the built one is the advisory's, which a first build before the
// advisory was stored left zero, and an alias merge can move earlier), and is seen now. A stored
// finding that was not built resolves: it keeps everything else. A finding that was resolved and is
// still absent is left alone.
//
// c holds every reason the owner was queued for; each transition takes the trigger of the one that
// explains it: a creation or reopening the cause of its match, a resolution as resolved says, an
// excepted finding reopening ExceptionExpired, and an open finding staying open a fix appearing, a
// priority change or, at the same priority, its confirmation (see change).
func Diff(stored, built []model.Finding, w Withdrawals, now time.Time, c Causes) ([]model.Finding, []model.Transition) {
	olds, news := byFingerprint(stored), byFingerprint(built)
	fps := slices.Collect(maps.Keys(olds))
	for fp := range news {
		if _, ok := olds[fp]; !ok {
			fps = append(fps, fp)
		}
	}
	slices.Sort(fps)

	var ups []model.Finding
	var ts []model.Transition
	for _, fp := range fps {
		o, hasOld := olds[fp]
		n, hasNew := news[fp]
		switch {
		case hasNew:
			if hasOld {
				n.Matched, n.Suggestion = o.Matched, o.Suggestion
				n.Observed = earliest(o.Observed, n.Observed)
			}
			n.LastSeen, n.ResolvedAt = now, nil
			ups = append(ups, n)
			if t, ok := change(o, hasOld, n, c); ok {
				ts = append(ts, transition(o, n, t, now))
			}
		case o.State != model.StateResolved:
			at := now
			r := o
			r.State, r.ResolvedAt = model.StateResolved, &at
			ups = append(ups, r)
			ts = append(ts, transition(o, r, c.resolved(o, w), now))
		}
	}
	return ups, ts
}

// change returns the trigger of the transition from o (when hasOld) to n, a built finding (open or
// excepted), if there is one.
//
// An open provisional finding that stops being provisional at the same priority is confirmed: grype
// ruled on it, or two Grype DBs passed without a record. The confirmation is a transition of its
// own, so a finding held back from immediate alerts while provisional (spec §6.5) is alerted once
// confirmed if nothing was sent for it yet.
func change(o model.Finding, hasOld bool, n model.Finding, c Causes) (model.Trigger, bool) {
	switch {
	case !hasOld || o.State == model.StateResolved:
		return c.appeared(n), true
	case o.State == model.StateExcepted && n.State == model.StateOpen:
		return model.TriggerExceptionExpired, true
	case o.State != n.State:
		return c.excepted(), true
	case n.State != model.StateOpen:
		return "", false // an excepted finding stays quiet whatever its priority does
	case !o.FixAvailable && n.FixAvailable:
		return model.TriggerFixAvailable, true
	case o.Priority != n.Priority:
		return model.TriggerPriorityChange, true
	case o.Provisional && !n.Provisional:
		return c.confirmed(), true
	}
	return "", false
}

// earliest returns the earlier of a and b, ignoring a zero time.
func earliest(a, b time.Time) time.Time {
	if a.IsZero() || (!b.IsZero() && b.Before(a)) {
		return b
	}
	return a
}

// transition records from → to; from is the zero Finding for a creation.
func transition(from, to model.Finding, trig model.Trigger, at time.Time) model.Transition {
	return model.Transition{
		Fingerprint:  to.Fingerprint,
		Owner:        to.Owner,
		AdvisoryID:   to.AdvisoryID,
		FromState:    from.State,
		ToState:      to.State,
		FromPriority: from.Priority,
		ToPriority:   to.Priority,
		Trigger:      trig,
		Provisional:  to.Provisional,
		At:           at,
	}
}

func byFingerprint(fs []model.Finding) map[string]model.Finding {
	out := make(map[string]model.Finding, len(fs))
	for _, f := range fs {
		out[f.Fingerprint] = f
	}
	return out
}
