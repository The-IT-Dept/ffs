package findings

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

func TestDiff_Transitions(t *testing.T) {
	const (
		open     = model.StateOpen
		excepted = model.StateExcepted
		resolved = model.StateResolved
		urgent   = model.PriorityUrgent
		high     = model.PriorityHigh
		medium   = model.PriorityMedium
		newAdv   = model.TriggerNewAdvisory
		inv      = model.TriggerInventoryChange
		prioCh   = model.TriggerPriorityChange
		expired  = model.TriggerExceptionExpired
	)
	ref := api().Ref
	f := func(s model.FindingState, p model.Priority) *model.Finding {
		return &model.Finding{Fingerprint: "fp", Owner: ref, ImageRepo: phpRepo, AdvisoryID: "CVE-2026-0001", State: s, Priority: p,
			Digests: []string{amd}}
	}
	running := Withdrawals{Digests: []string{amd, arm}} // the owner still runs what the finding was found in
	movedOn := Withdrawals{Digests: []string{"sha256:new"}}
	notAffected := Withdrawals{NotAffected: map[string]bool{"fp": true}, Digests: []string{"sha256:new"}}
	prov := func(x *model.Finding) *model.Finding { x.Provisional = true; return x }
	fixed := func(x *model.Finding) *model.Finding { x.FixAvailable, x.FixState = true, model.FixFixed; return x }

	// feedAndRollout: a Grype DB update and an inventory change queued the owner before its recompute.
	feedAndRollout := CauseNewAdvisory | CauseInventory
	cases := []struct {
		name     string
		old, new *model.Finding
		trig     model.Trigger
		wantTo   model.FindingState
		wantTrig model.Trigger
		none     bool
		w        *Withdrawals // nil = running
		causes   Causes       // 0 = CausesOf(trig)
	}{
		{"create open", nil, f(open, high), newAdv, open, newAdv, false, nil, 0},
		{"create excepted", nil, f(excepted, high), inv, excepted, inv, false, nil, 0},
		{"create provisional", nil, prov(f(open, urgent)), newAdv, open, newAdv, false, nil, 0},
		{"gone", f(open, high), nil, inv, resolved, inv, false, nil, 0},
		{"gone provisional", prov(f(open, urgent)), nil, newAdv, resolved, model.TriggerWithdrawn, false, nil, 0},
		{"gone provisional after a rollout", prov(f(open, urgent)), nil, inv, resolved, inv, false, nil, 0},
		{"gone provisional, owner moved on", prov(f(open, urgent)), nil, newAdv, resolved, newAdv, false, &movedOn, 0},
		{"gone provisional with its owner", prov(f(open, urgent)), nil, newAdv, resolved, newAdv, false, &Withdrawals{}, 0},
		{"gone provisional, grype not affected", prov(f(open, urgent)), nil, inv, resolved, model.TriggerWithdrawn, false, &notAffected, 0},
		{"gone settled, grype not affected", f(open, urgent), nil, inv, resolved, inv, false, &notAffected, 0},
		{"excepted gone", f(excepted, high), nil, inv, resolved, inv, false, nil, 0},
		{"regression", f(resolved, high), f(open, high), inv, open, inv, false, nil, 0},
		{"regression excepted", f(resolved, high), f(excepted, high), inv, excepted, inv, false, nil, 0},
		{"exception expired", f(excepted, high), f(open, high), prioCh, open, model.TriggerExceptionExpired, false, nil, 0},
		{"excepted", f(open, high), f(excepted, high), prioCh, excepted, prioCh, false, nil, 0},
		{"escalation", f(open, high), f(open, urgent), newAdv, open, prioCh, false, nil, 0},
		{"de-escalation", f(open, urgent), f(open, medium), inv, open, prioCh, false, nil, 0},
		{"fix appeared", f(open, medium), fixed(f(open, high)), newAdv, open, model.TriggerFixAvailable, false, nil, 0},
		{"fix appeared, same priority", f(open, high), fixed(f(open, high)), newAdv, open, model.TriggerFixAvailable, false, nil, 0},
		{"confirmed", prov(f(open, high)), f(open, high), newAdv, open, newAdv, false, nil, 0},
		{"confirmed by a rollout's match", prov(f(open, high)), f(open, high), inv, open, inv, false, nil, 0},
		{"confirmed and escalated", prov(f(open, high)), f(open, urgent), newAdv, open, prioCh, false, nil, 0},
		{"still provisional", prov(f(open, high)), prov(f(open, high)), newAdv, "", "", true, nil, 0},
		{"confirmed while excepted", prov(f(excepted, high)), f(excepted, high), newAdv, "", "", true, nil, 0},
		{"unchanged", f(open, high), f(open, high), newAdv, "", "", true, nil, 0},
		{"rollout resolves it during a DB update", f(open, high), nil, "", resolved, inv, false, &movedOn, feedAndRollout},
		{"owner gone during a DB update", f(open, high), nil, "", resolved, inv, false, &Withdrawals{}, feedAndRollout},
		{"feed drops it while the owner still runs it", f(open, high), nil, "", resolved, newAdv, false, nil, feedAndRollout},
		{"provisional, rollout during a DB update", prov(f(open, urgent)), nil, "", resolved, inv, false, &movedOn, feedAndRollout},
		{"provisional, feed drops it during a rollout elsewhere", prov(f(open, urgent)), nil, "", resolved, model.TriggerWithdrawn,
			false, nil, feedAndRollout},
		{"created by an exception change", nil, f(open, high), "", open, expired, false, nil, CauseException},
		{"created excepted by an exception change", nil, f(excepted, high), "", excepted, prioCh, false, nil, CauseException},
		{"reopened by an exception change", f(resolved, high), f(open, high), "", open, expired, false, nil, CauseException},
		{"created during an exception change and a DB update", nil, f(open, high), "", open, newAdv, false, nil,
			CauseException | CauseNewAdvisory},
		{"created by enrichment", nil, f(open, high), prioCh, open, prioCh, false, nil, 0},
		{"excepted during a DB update", f(open, high), f(excepted, high), "", excepted, prioCh, false, nil,
			CauseException | CauseNewAdvisory},
		{"excepted by a feed alias", f(open, high), f(excepted, high), newAdv, excepted, newAdv, false, nil, 0},
		{"confirmed during a rollout and a DB update", prov(f(open, high)), f(open, high), "", open, newAdv, false, nil, feedAndRollout},
		{"resolved during an exception change", f(open, high), nil, "", resolved, prioCh, false, &movedOn, CauseException},
		{"fix still there", fixed(f(open, high)), fixed(f(open, high)), newAdv, "", "", true, nil, 0},
		{"excepted, priority moved", f(excepted, high), f(excepted, medium), prioCh, "", "", true, nil, 0},
		{"resolved stays gone", f(resolved, high), nil, inv, "", "", true, nil, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var old, built []model.Finding
			var from, to model.Finding
			if c.old != nil {
				old, from, to = []model.Finding{*c.old}, *c.old, *c.old // resolving keeps old's priority and provisional
			}
			if c.new != nil {
				built, to = []model.Finding{*c.new}, *c.new
			}
			w := running
			if c.w != nil {
				w = *c.w
			}
			causes := c.causes
			if causes == 0 {
				causes = CausesOf(c.trig)
			}
			_, ts := Diff(old, built, w, now, causes)
			if c.none {
				assert.Empty(t, ts)
				return
			}
			require.Len(t, ts, 1)
			assert.Equal(t, model.Transition{
				Fingerprint:  "fp",
				Owner:        ref,
				AdvisoryID:   "CVE-2026-0001",
				FromState:    from.State,
				ToState:      c.wantTo,
				FromPriority: from.Priority,
				ToPriority:   to.Priority,
				Trigger:      c.wantTrig,
				Provisional:  to.Provisional,
				At:           now,
			}, ts[0])
		})
	}
}

func TestDiff_Upserts(t *testing.T) {
	t0, t1 := now.Add(-48*time.Hour), now.Add(-time.Hour)
	ref := api().Ref
	sug := &model.Suggestion{Repo: phpRepo, FromTag: "8.3.14", ToTag: "8.3.15", Tier: model.TierPatch}
	stored := func(fp string, s model.FindingState) model.Finding {
		return model.Finding{Fingerprint: fp, Owner: ref, AdvisoryID: "CVE-" + fp, State: s, Priority: model.PriorityHigh,
			Matched: t0, Observed: t0, LastSeen: t1, Suggestion: sug}
	}
	fresh := func(fp string) model.Finding {
		return model.Finding{Fingerprint: fp, Owner: ref, AdvisoryID: "CVE-" + fp, State: model.StateOpen,
			Priority: model.PriorityHigh, Matched: now, Observed: t1, LastSeen: now}
	}
	resolvedAt := t1
	stillGone := stored("a-still-gone", model.StateResolved)
	stillGone.ResolvedAt = &resolvedAt
	regressed := stored("b-regression", model.StateResolved)
	regressed.ResolvedAt = &resolvedAt

	ups, _ := Diff(
		[]model.Finding{stored("d-unchanged", model.StateOpen), stored("c-gone", model.StateOpen), regressed, stillGone},
		[]model.Finding{fresh("e-new"), fresh("d-unchanged"), fresh("b-regression")},
		Withdrawals{}, now, CauseInventory)

	fps := make([]string, 0, len(ups))
	got := map[string]model.Finding{}
	for _, u := range ups {
		fps = append(fps, u.Fingerprint)
		got[u.Fingerprint] = u
	}
	assert.Equal(t, []string{"b-regression", "c-gone", "d-unchanged", "e-new"}, fps)

	unchanged := got["d-unchanged"]
	assert.Equal(t, now, unchanged.LastSeen)
	assert.Equal(t, t0, unchanged.Matched)
	assert.Equal(t, t0, unchanged.Observed)
	assert.Same(t, sug, unchanged.Suggestion)
	assert.Nil(t, unchanged.ResolvedAt)

	gone := got["c-gone"]
	assert.Equal(t, model.StateResolved, gone.State)
	require.NotNil(t, gone.ResolvedAt)
	assert.Equal(t, now, *gone.ResolvedAt)
	assert.Equal(t, t1, gone.LastSeen)
	assert.Equal(t, model.PriorityHigh, gone.Priority)
	assert.Same(t, sug, gone.Suggestion)

	regression := got["b-regression"]
	assert.Equal(t, model.StateOpen, regression.State)
	assert.Nil(t, regression.ResolvedAt)
	assert.Equal(t, t0, regression.Matched)
	assert.Equal(t, now, regression.LastSeen)

	created := got["e-new"]
	assert.Equal(t, now, created.Matched)
	assert.Nil(t, created.Suggestion)
}

func TestDiff_ObservedTakesTheEarliestNonZero(t *testing.T) {
	t0, t1 := now.Add(-48*time.Hour), now.Add(-time.Hour)
	ref := api().Ref
	fnd := func(fp string, observed time.Time) model.Finding {
		return model.Finding{Fingerprint: fp, Owner: ref, AdvisoryID: "CVE-" + fp, State: model.StateOpen,
			Priority: model.PriorityHigh, Observed: observed}
	}
	ups, _ := Diff(
		[]model.Finding{fnd("a-zero-stored", time.Time{}), fnd("b-later-stored", t1), fnd("c-earlier-stored", t0),
			fnd("d-zero-built", t0)},
		[]model.Finding{fnd("a-zero-stored", t1), fnd("b-later-stored", t0), fnd("c-earlier-stored", t1),
			fnd("d-zero-built", time.Time{})},
		Withdrawals{}, now, CauseNewAdvisory)
	got := map[string]time.Time{}
	for _, u := range ups {
		got[u.Fingerprint] = u.Observed
	}
	assert.Equal(t, map[string]time.Time{
		"a-zero-stored":    t1, // the advisory was not stored when the finding was first built
		"b-later-stored":   t0, // an alias merge moved the advisory's first sighting earlier
		"c-earlier-stored": t0,
		"d-zero-built":     t0,
	}, got)
}
