package findings

import (
	"maps"
	"slices"
	"time"

	"github.com/the-it-dept/ffs/internal/model"
)

// Withdrawals tells Diff why stored findings that were not built disappeared.
type Withdrawals struct {
	// NotAffected holds the fingerprints grype's not-affected verdict removed (Result.NotAffected).
	NotAffected map[string]bool
	// Digests are the digests the owner runs now; nil when it is gone.
	Digests []string
}

// withdrawn reports whether the stored finding o, which was not built, was withdrawn rather than
// fixed or removed: grype says the package is not affected (spec §6.5), or a feed change, not an
// inventory change, dropped it while the owner still runs every digest it was found in.
func (w Withdrawals) withdrawn(o model.Finding, trig model.Trigger) bool {
	if w.NotAffected[o.Fingerprint] {
		return true
	}
	if trig == model.TriggerInventoryChange || len(o.Digests) == 0 {
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
// finding that was not built resolves: it keeps everything else, and a provisional one that w says
// was withdrawn resolves as withdrawn; one the owner fixed by moving to another image, or that went
// with its owner, keeps trig. A finding that was resolved and is still absent is left alone. trig is
// the transition trigger, except that an excepted finding reopening is an expired exception, and an
// open finding staying open is a fix appearing, a priority change or, at the same priority, its
// confirmation (see change).
func Diff(stored, built []model.Finding, w Withdrawals, now time.Time, trig model.Trigger) ([]model.Finding, []model.Transition) {
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
			if t, ok := change(o, hasOld, n, trig); ok {
				ts = append(ts, transition(o, n, t, now))
			}
		case o.State != model.StateResolved:
			at := now
			r := o
			r.State, r.ResolvedAt = model.StateResolved, &at
			ups = append(ups, r)
			t := trig
			if o.Provisional && w.withdrawn(o, trig) {
				t = model.TriggerWithdrawn
			}
			ts = append(ts, transition(o, r, t, now))
		}
	}
	return ups, ts
}

// change returns the trigger of the transition from o (when hasOld) to n, if there is one.
//
// An open provisional finding that stops being provisional at the same priority is confirmed: grype
// ruled on it, or two Grype DBs passed without a record. The confirmation is a transition of its
// own, so a finding held back from immediate alerts while provisional (spec §6.5) is alerted once
// confirmed if nothing was sent for it yet. The trigger enum has no confirmation value; it carries
// trig, the closest: NewAdvisory when a Grype DB confirmed it, InventoryChange when a rollout's
// match did.
func change(o model.Finding, hasOld bool, n model.Finding, trig model.Trigger) (model.Trigger, bool) {
	switch {
	case !hasOld:
		return trig, true
	case o.State == model.StateExcepted && n.State == model.StateOpen:
		return model.TriggerExceptionExpired, true
	case o.State != n.State:
		return trig, true
	case n.State != model.StateOpen:
		return "", false // an excepted finding stays quiet whatever its priority does
	case !o.FixAvailable && n.FixAvailable:
		return model.TriggerFixAvailable, true
	case o.Priority != n.Priority:
		return model.TriggerPriorityChange, true
	case o.Provisional && !n.Provisional:
		return trig, true
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
