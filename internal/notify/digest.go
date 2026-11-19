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
// escalated, fixes now available, resolved) plus feed health. When nothing qualifies, nothing is
// sent; the cursor still moves and resolutions are still recorded in the ledger. Classifying
// against the ledger, which the immediate pass has already updated, keeps anything sent
// immediately out of the digest.
func (e *Engine) digest(ctx context.Context, t *target, st store.NotifyTargetState, upTo int64, now time.Time) error {
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
	ledger, err := e.st.Ledger(ctx, uid, r.order)
	if err != nil {
		return err
	}
	d := t.cfg.Digest
	var updates []store.LedgerEntry
	byEvent := map[Event][]string{}
	for _, fp := range r.order {
		tr, l := r.final[fp], entry(ledger, fp)
		if !t.cfg.allows(tr.Owner.Namespace) {
			continue
		}
		ev := classify(tr, l)
		var listed bool
		switch ev {
		case EventDetected, EventReopened, EventEscalated:
			listed = tr.ToPriority >= d.MinPriority
		case EventResolved:
			listed = d.IncludeResolved
		}
		if (ev == "" || ev == EventFixAvailable) && r.fixSeen[fp] && tr.ToState == model.StateOpen &&
			(l != nil || tr.ToPriority >= d.MinPriority) {
			ev, listed = EventFixAvailable, true
		}
		if listed {
			byEvent[ev] = append(byEvent[ev], fp)
		}
		// A resolution is recorded even when the digest leaves resolved findings out.
		if listed || ev == EventResolved {
			if le, ok := ledgerAfter(uid, ev, tr, l, now); ok {
				updates = append(updates, le)
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

var digestEvents = []Event{EventDetected, EventReopened, EventEscalated, EventFixAvailable, EventResolved}

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
	for _, ev := range digestEvents {
		fs := make([]model.Finding, 0, len(byEvent[ev]))
		for _, fp := range byEvent[ev] {
			fs = append(fs, views[fp])
		}
		for _, g := range b.groups(ev, fs) {
			items = append(items, g.item)
		}
	}
	slices.SortStableFunc(items, compareItems)
	owners := map[string]bool{}
	counts := map[model.Priority]int{}
	n := map[Event]int{}
	for _, it := range items {
		for _, o := range it.Owners {
			owners[o.Key()] = true
		}
		counts[it.Priority]++
		n[it.Event]++
	}
	m := e.message(t, KindDigest, fire.Format(time.RFC3339),
		digestTitle(e.o.Cluster, n[EventDetected]+n[EventReopened], n[EventEscalated], n[EventFixAvailable], n[EventResolved]), now)
	m.Items = items
	m.Summary = &Summary{Workloads: len(owners), Counts: counts}
	for _, name := range slices.Sorted(maps.Keys(e.o.FeedStaleAfter)) {
		fs, err := e.st.FeedState(ctx, name)
		if err != nil {
			return Message{}, err
		}
		m.Feeds = append(m.Feeds, e.feedStatus(fs, e.o.FeedStaleAfter[name], now))
	}
	return m, nil
}
