package findings

import (
	"maps"
	"slices"
	"time"

	"github.com/the-it-dept/ffs/internal/model"
)

// Diff compares an owner's stored findings with the ones Build just produced. It returns the
// findings to upsert, sorted by fingerprint, and at most one transition per fingerprint (spec §6.6).
//
// A built finding keeps Matched, Observed and Suggestion from its stored one and is seen now. A
// stored finding that was not built resolves: it keeps everything else, and a provisional one
// resolves as withdrawn. A finding that was resolved and is still absent is left alone. trig is
// the transition trigger, except that an excepted finding reopening is an expired exception, and
// an open finding staying open is a fix appearing or a priority change.
func Diff(stored, built []model.Finding, now time.Time, trig model.Trigger) ([]model.Finding, []model.Transition) {
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
				n.Matched, n.Observed, n.Suggestion = o.Matched, o.Observed, o.Suggestion
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
			if o.Provisional {
				t = model.TriggerWithdrawn
			}
			ts = append(ts, transition(o, r, t, now))
		}
	}
	return ups, ts
}

// change returns the trigger of the transition from o (when hasOld) to n, if there is one.
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
	}
	return "", false
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
