package notify

import (
	"context"
	"maps"
	"slices"
	"time"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

// digest sends the target's scheduled summary when it is due (spec §6.10): what changed between
// the digest cursor and the immediate cursor that was not already sent, in four sections (new,
// escalated, fixes now available, resolved) plus feed health, and the upgrades that became
// available for findings already reported (see upgradesToList). Every section keeps to the
// digest's minimum priority; a fix or resolution counts at the priority the target was told about.
// When nothing qualifies, nothing is sent; the cursor still moves and resolutions are still
// recorded in the ledger. Classifying against the ledger, which the immediate pass has already
// updated, keeps anything sent immediately out of the digest. With holdNodes the transitions of
// Nodes findings are passed over, as the immediate pass does. A resolution in a namespace that has
// been deleted is still in scope, so the ledger entry of a finding sent before closes.
func (e *Engine) digest(ctx context.Context, t *target, st store.NotifyTargetState, upTo int64, now time.Time, holdNodes bool) error {
	fire := t.digestFire(st)
	if !digestDue(fire, now) {
		return nil
	}
	uid := t.cfg.UID
	cursor, err := e.st.Cursor(ctx, digestCursor(uid))
	if err != nil {
		return err
	}
	var ts []model.Transition
	for cursor < upTo {
		page, err := e.st.TransitionsAfter(ctx, cursor, pageSize)
		if err != nil {
			return err
		}
		if len(page) == 0 {
			break
		}
		for _, tr := range page {
			if tr.ID <= upTo {
				ts = append(ts, tr)
			}
		}
		cursor = page[len(page)-1].ID
	}
	r := reduce(ts)
	ledger, err := e.st.Ledger(ctx, uid, append(slices.Clone(r.order), r.upgradeOrder...))
	if err != nil {
		return err
	}
	d := t.cfg.Digest
	var updates []store.LedgerEntry
	byEvent := map[Event][]string{}
	listedFP := map[string]bool{}
	for _, fp := range r.order {
		tr, l := r.final[fp], entry(ledger, fp)
		if holdNodes && isNodes(tr.Owner) {
			continue
		}
		ev := classify(tr, l)
		if !t.cfg.covers(ev, tr.Owner.Namespace) {
			continue
		}
		var listed bool
		switch ev {
		case EventDetected, EventReopened, EventEscalated:
			listed = tr.ToPriority >= d.MinPriority
		case EventResolved:
			// Only what the target was told at or above its digest threshold: the baseline
			// records every open finding, low ones included, and their resolution is no news.
			listed = d.IncludeResolved && l.MaxPriority >= d.MinPriority
		}
		if (ev == "" || ev == EventFixAvailable) && r.fixSeen[fp] && tr.ToState == model.StateOpen &&
			max(tr.ToPriority, told(l)) >= d.MinPriority {
			ev, listed = EventFixAvailable, true
		}
		if listed {
			byEvent[ev] = append(byEvent[ev], fp)
			listedFP[fp] = true
		}
		// A resolution is recorded even when the digest leaves resolved findings out.
		if listed || ev == EventResolved {
			if le, ok := ledgerAfter(uid, ev, tr, l, now); ok {
				updates = append(updates, le)
			}
		}
	}
	ups, err := e.upgradesToList(ctx, t, r, ledger, listedFP)
	if err != nil {
		return err
	}
	if len(ups) > 0 {
		byEvent[EventUpgradeAvailable] = ups
		for _, fp := range ups {
			if _, ok := r.final[fp]; !ok {
				r.final[fp] = r.upgrades[fp] // the finding's only transition in this digest
			}
		}
	}
	c := store.NotifyCommit{Target: uid, Cursors: map[string]int64{digestCursor(uid): upTo}, Ledger: updates, LastDigestAt: now}
	if len(byEvent) > 0 {
		m, err := e.digestMessage(ctx, t, r, byEvent, fire, now)
		if err != nil {
			return err
		}
		dl, err := delivery(m, now)
		if err != nil {
			return err
		}
		c.Deliveries = []store.Delivery{dl}
	}
	return e.st.CommitNotify(ctx, c)
}

// upgradesToList returns, in order, the findings whose suggested upgrade was announced in the
// digest's run of transitions and that the digest lists under upgradeAvailable: still open, not
// listed otherwise, already reported to the target at its digest or immediate threshold, and with
// a stored suggestion that fixes their advisory. An immediate alert goes out before the upgrade
// resolver has scored candidates, so this is where its suggested upgrade reaches the target (spec
// §6.10). It is never an alert of its own (never twice), and each announcement is listed once,
// since the digest cursor moves past it.
func (e *Engine) upgradesToList(ctx context.Context, t *target, r latest, ledger map[string]store.LedgerEntry,
	listed map[string]bool) ([]string, error) {
	var cand []string
	for _, fp := range r.upgradeOrder {
		tr, l := r.upgrades[fp], entry(ledger, fp)
		switch {
		case listed[fp], l == nil, l.LastState != model.StateOpen, !t.cfg.allows(tr.Owner.Namespace):
			continue
		case l.MaxPriority < t.cfg.Digest.MinPriority && l.MaxPriority < t.cfg.ImmediateMin:
			continue
		}
		if f, ok := r.final[fp]; ok && f.ToState != model.StateOpen {
			continue
		}
		cand = append(cand, fp)
	}
	if len(cand) == 0 {
		return nil, nil
	}
	stored, err := e.st.FindingsByFingerprint(ctx, cand)
	if err != nil {
		return nil, err
	}
	out := cand[:0]
	for _, fp := range cand {
		f, ok := stored[fp]
		if ok && f.State == model.StateOpen && f.Suggestion != nil && slices.Contains(f.Suggestion.FixedIDs, f.AdvisoryID) {
			out = append(out, fp)
		}
	}
	return out, nil
}

// told is the highest priority the target was told about a finding, PriorityNone when never.
func told(l *store.LedgerEntry) model.Priority {
	if l == nil {
		return model.PriorityNone
	}
	return l.MaxPriority
}

// digestFire is the target's next digest time: the first scheduled time after its last digest, or
// after its baseline when that is later. It is zero when the schedule never fires.
func (t *target) digestFire(st store.NotifyTargetState) time.Time {
	from := st.LastDigestAt
	if st.BaselineAt.After(from) {
		from = st.BaselineAt
	}
	return t.sched.Next(from.In(t.cfg.Digest.Location))
}

// digestDue reports whether a digest due at fire is due by now.
func digestDue(fire, now time.Time) bool { return !fire.IsZero() && !now.Before(fire) }

var digestEvents = []Event{EventDetected, EventReopened, EventEscalated, EventFixAvailable, EventResolved, EventUpgradeAvailable}

func (e *Engine) digestMessage(ctx context.Context, t *target, r latest, byEvent map[Event][]string, fire, now time.Time) (Message, error) {
	var fps []string
	for _, ev := range digestEvents {
		fps = append(fps, byEvent[ev]...)
	}
	views, b, err := e.views(ctx, fps, r)
	if err != nil {
		return Message{}, err
	}
	var items []Item
	listed := make([]model.Finding, 0, len(fps))
	for _, ev := range digestEvents {
		fs := make([]model.Finding, 0, len(byEvent[ev]))
		for _, fp := range byEvent[ev] {
			fs = append(fs, views[fp])
		}
		listed = append(listed, fs...)
		for _, part := range bySuggestion(ev, fs) {
			for _, g := range b.groups(ev, part) {
				items = append(items, g.item)
			}
		}
	}
	slices.SortStableFunc(items, compareItems)
	n := map[Event]int{}
	for _, it := range items {
		n[it.Event]++
	}
	m := e.message(t, KindDigest, fire.Format(time.RFC3339),
		digestTitle(e.o.Cluster, n[EventDetected]+n[EventReopened], n[EventEscalated], n[EventFixAvailable], n[EventResolved],
			n[EventUpgradeAvailable]), now)
	m.Items = items
	m.Summary = summarise(listed) // the findings listed, as the baseline counts its findings
	for _, name := range slices.Sorted(maps.Keys(e.o.FeedStaleAfter)) {
		fs, err := e.st.FeedState(ctx, name)
		if err != nil {
			return Message{}, err
		}
		m.Feeds = append(m.Feeds, e.feedStatus(fs, e.o.FeedStaleAfter[name], now))
	}
	return m, nil
}

// bySuggestion splits the findings of an upgradeAvailable section by their suggested upgrade, so
// that each item names the one upgrade that fixes every workload it lists. Other events are not
// split.
func bySuggestion(ev Event, fs []model.Finding) [][]model.Finding {
	if ev != EventUpgradeAvailable {
		return [][]model.Finding{fs}
	}
	idx := map[string]int{}
	var out [][]model.Finding
	for _, f := range fs {
		var k string
		if sg := f.Suggestion; sg != nil {
			k = sg.Repo + "|" + sg.FromTag + "|" + sg.ToTag + "|" + sg.ToDigest
		}
		i, ok := idx[k]
		if !ok {
			i = len(out)
			idx[k] = i
			out = append(out, nil)
		}
		out[i] = append(out[i], f)
	}
	return out
}
