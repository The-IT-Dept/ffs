// Package notify turns finding transitions into notifications (spec §6.10): one baseline summary
// when a target first sees the cluster, immediate alerts grouped by advisory, scheduled digests,
// and feed-stale alerts. A per-target ledger keeps every finding from being sent twice at the same
// level, and the deliveries outbox gives at-least-once delivery with stable message IDs.
package notify

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/robfig/cron/v3"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

const (
	pageSize        = 1000 // transitions read at a time
	maxPerPass      = 5000 // transitions one target handles per ProcessOnce
	baselineItems   = 10
	processInterval = 15 * time.Second
	drainInterval   = 2 * time.Second
	pruneInterval   = 24 * time.Hour
)

// Options configures an Engine.
type Options struct {
	Cluster, DashboardURL string
	// Ready reports that the initial inventory is catalogued and matched; nothing is processed
	// before, so the first baseline covers the whole cluster. Nil means always ready.
	Ready   func(ctx context.Context) bool
	Changed <-chan struct{}
	// FeedStaleAfter is the staleness threshold of each registered feed, keyed by feed name.
	FeedStaleAfter map[string]time.Duration
	// Retention is how long sent and failed deliveries, and ledger entries of resolved findings,
	// are kept.
	Retention time.Duration
	Now       func() time.Time // time.Now when nil
	Rand      func() float64   // backoff jitter in [0,1); math/rand when nil
}

// Engine runs notifications for every registered target. It is a leader-only manager.Runnable.
type Engine struct {
	st      *store.Store
	o       Options
	started time.Time

	mu      sync.Mutex
	targets map[string]*target   // by UID
	uids    map[string]string    // name → UID
	backoff map[string]time.Time // by UID: after a failed send, nothing more goes to the target before this

	// passMu serialises ProcessOnce with deleting a target's stored state, so a pass never
	// writes state back for a target removed under it.
	passMu   sync.Mutex
	feedSent map[string]bool // feed-stale delivery IDs already committed; guarded by passMu
}

// New returns an Engine over st.
func New(st *store.Store, o Options) *Engine {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Rand == nil {
		o.Rand = rand.Float64 //nolint:gosec // G404: backoff jitter, not security-sensitive
	}
	if o.Ready == nil {
		o.Ready = func(context.Context) bool { return true }
	}
	return &Engine{st: st, o: o, started: o.Now().UTC(), targets: map[string]*target{}, uids: map[string]string{},
		backoff: map[string]time.Time{}, feedSent: map[string]bool{}}
}

// now is the engine clock in UTC, the zone of every stored and sent time.
func (e *Engine) now() time.Time { return e.o.Now().UTC() }

func immediateCursor(uid string) string { return "notify:" + uid }
func digestCursor(uid string) string    { return "notify-digest:" + uid }

// Register adds or updates a target and its sink. The digest schedule and quiet hours must parse.
// Re-registering with the same ConfigHash keeps a disabled target disabled; a new one re-enables it.
func (e *Engine) Register(ctx context.Context, t TargetConfig, s Sink) error {
	if t.UID == "" || t.Name == "" {
		return errors.New("notify: a target needs a UID and a name")
	}
	if s == nil {
		return fmt.Errorf("notify: target %s has no sink", t.Name)
	}
	sched, err := cron.ParseStandard(t.Digest.Schedule)
	if err != nil {
		return fmt.Errorf("notify: target %s: digest schedule: %w", t.Name, err)
	}
	for i, iv := range t.QuietHours {
		if err := iv.Validate(); err != nil {
			return fmt.Errorf("notify: target %s: quiet hours interval %d: %w", t.Name, i+1, err)
		}
	}
	if t.Digest.Location == nil {
		t.Digest.Location = time.UTC
	}
	if t.ImmediateMin == model.PriorityNone {
		t.ImmediateMin = defaultImmediateMin
	}
	if t.Digest.MinPriority == model.PriorityNone {
		t.Digest.MinPriority = defaultDigestMin
	}
	e.mu.Lock()
	old, had := e.uids[t.Name]
	e.mu.Unlock()
	if had && old != t.UID {
		// The AlertTarget was deleted and created again under the same name.
		if err := e.forget(ctx, old); err != nil {
			return err
		}
	}
	if err := e.st.PutNotifyTarget(ctx, t.UID, t.Name, t.ConfigHash); err != nil {
		return fmt.Errorf("notify: target %s: %w", t.Name, err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if prev := e.targets[t.UID]; prev != nil && prev.cfg.Name != t.Name {
		delete(e.uids, prev.cfg.Name)
	}
	e.targets[t.UID] = &target{cfg: t, sink: s, sched: sched}
	e.uids[t.Name] = t.UID
	return nil
}

// Unregister forgets the target called name and deletes its stored state, including state left
// from before a restart.
func (e *Engine) Unregister(ctx context.Context, name string) error {
	e.passMu.Lock()
	defer e.passMu.Unlock()
	e.mu.Lock()
	uid, ok := e.uids[name]
	e.dropLocked(uid)
	e.mu.Unlock()
	rows, err := e.st.NotifyTargets(ctx)
	if err != nil {
		return fmt.Errorf("notify: unregister %s: %w", name, err)
	}
	var errs []error
	for _, r := range rows {
		if r.Name == name || (ok && r.Target == uid) {
			errs = append(errs, e.st.DeleteNotifyTarget(ctx, r.Target))
		}
	}
	return errors.Join(errs...)
}

// Retain deletes the stored state of every target whose UID is not in liveUIDs, such as an
// AlertTarget deleted while ffs was not running.
func (e *Engine) Retain(ctx context.Context, liveUIDs []string) error {
	e.passMu.Lock()
	defer e.passMu.Unlock()
	rows, err := e.st.NotifyTargets(ctx)
	if err != nil {
		return fmt.Errorf("notify: retain: %w", err)
	}
	var errs []error
	for _, r := range rows {
		if slices.Contains(liveUIDs, r.Target) {
			continue
		}
		e.mu.Lock()
		e.dropLocked(r.Target)
		e.mu.Unlock()
		errs = append(errs, e.st.DeleteNotifyTarget(ctx, r.Target))
	}
	return errors.Join(errs...)
}

// Status returns the stored delivery status of the target uid.
func (e *Engine) Status(ctx context.Context, uid string) (store.NotifyTargetState, bool, error) {
	return e.st.NotifyTarget(ctx, uid)
}

// forget drops uid from memory and deletes its stored state.
func (e *Engine) forget(ctx context.Context, uid string) error {
	e.passMu.Lock()
	defer e.passMu.Unlock()
	e.mu.Lock()
	e.dropLocked(uid)
	e.mu.Unlock()
	return e.st.DeleteNotifyTarget(ctx, uid)
}

// dropLocked removes uid from memory; e.mu must be held.
func (e *Engine) dropLocked(uid string) {
	delete(e.backoff, uid)
	if t := e.targets[uid]; t != nil {
		if e.uids[t.cfg.Name] == uid {
			delete(e.uids, t.cfg.Name)
		}
		delete(e.targets, uid)
	}
}

// snapshot returns the registered targets ordered by name.
func (e *Engine) snapshot() []*target {
	e.mu.Lock()
	defer e.mu.Unlock()
	ts := slices.Collect(maps.Values(e.targets))
	slices.SortFunc(ts, func(a, b *target) int { return strings.Compare(a.cfg.Name, b.cfg.Name) })
	return ts
}

// NeedLeaderElection makes the engine leader-only.
func (e *Engine) NeedLeaderElection() bool { return true }

// Start processes transitions on every Changed signal and every 15s, drains the outbox every 2s,
// and prunes old deliveries daily, until ctx is done. Errors are logged and the loops go on.
func (e *Engine) Start(ctx context.Context) error {
	log := logr.FromContextOrDiscard(ctx).WithName("notify")
	var wg sync.WaitGroup
	wg.Go(func() {
		tick := time.NewTicker(drainInterval)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
			if err := e.DrainOnce(ctx); err != nil && ctx.Err() == nil {
				log.Error(err, "delivering notifications failed")
			}
		}
	})
	defer wg.Wait()
	process := time.NewTicker(processInterval)
	defer process.Stop()
	prune := time.NewTicker(pruneInterval)
	defer prune.Stop()
	e.prune(ctx, log)
	for {
		if err := e.ProcessOnce(ctx); err != nil && ctx.Err() == nil {
			log.Error(err, "processing notifications failed")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-e.o.Changed:
		case <-process.C:
		case <-prune.C:
			e.prune(ctx, log)
		}
	}
}

func (e *Engine) prune(ctx context.Context, log logr.Logger) {
	if e.o.Retention <= 0 {
		return
	}
	if n, err := e.st.PruneNotify(ctx, e.now().Add(-e.o.Retention)); err != nil && ctx.Err() == nil {
		log.Error(err, "pruning the delivery log failed")
	} else if n > 0 {
		log.V(1).Info("pruned the delivery log", "rows", n)
	}
}

// ProcessOnce runs one pass for every registered target: the baseline for a new target, otherwise
// immediate alerts for the transitions since its cursor, then its digest when due and its
// feed-stale alerts. It does nothing until Ready. Deliveries are queued for DrainOnce.
func (e *Engine) ProcessOnce(ctx context.Context) error {
	if !e.o.Ready(ctx) {
		return nil
	}
	e.passMu.Lock()
	defer e.passMu.Unlock()
	var errs []error
	for _, t := range e.snapshot() {
		if err := e.processTarget(ctx, t); err != nil {
			errs = append(errs, fmt.Errorf("notify: target %s: %w", t.cfg.Name, err))
		}
		if ctx.Err() != nil {
			break
		}
	}
	return errors.Join(errs...)
}

func (e *Engine) processTarget(ctx context.Context, t *target) error {
	uid := t.cfg.UID
	st, ok, err := e.st.NotifyTarget(ctx, uid)
	if err != nil || !ok {
		return err
	}
	now := e.now()
	if st.BaselineAt.IsZero() {
		if t.cfg.Paused {
			return nil
		}
		return e.baseline(ctx, t, now)
	}
	cursor, err := e.st.Cursor(ctx, immediateCursor(uid))
	if err != nil {
		return err
	}
	ts, last, err := e.transitionsAfter(ctx, cursor, maxPerPass)
	if err != nil {
		return err
	}
	if t.cfg.Paused || st.Disabled {
		// Move past everything without sending, so nothing old arrives once it is resumed. A digest
		// fire time that passes meanwhile is spent too, so the first digest after resuming comes on
		// schedule rather than at once. A pass with neither writes nothing.
		if len(ts) == 0 && !digestDue(t.digestFire(st), now) {
			return nil
		}
		return e.st.CommitNotify(ctx, store.NotifyCommit{Target: uid,
			Cursors: map[string]int64{immediateCursor(uid): last, digestCursor(uid): last}, LastDigestAt: now})
	}
	if len(ts) > 0 {
		if err := e.immediate(ctx, t, ts, last, now); err != nil {
			return err
		}
	}
	if err := e.digest(ctx, t, st, last, now); err != nil {
		return err
	}
	return e.feedStale(ctx, t, now)
}

// transitionsAfter reads up to limit transitions after cursor, a page at a time, and returns them
// with the last ID read (cursor when there are none).
func (e *Engine) transitionsAfter(ctx context.Context, cursor int64, limit int) ([]model.Transition, int64, error) {
	var ts []model.Transition
	last := cursor
	for len(ts) < limit {
		page, err := e.st.TransitionsAfter(ctx, last, min(pageSize, limit-len(ts)))
		if err != nil {
			return nil, 0, err
		}
		if len(page) == 0 {
			break
		}
		ts = append(ts, page...)
		last = page[len(page)-1].ID
	}
	return ts, last, nil
}

// immediate queues one message per advisory and event for the transitions eligible to be sent now,
// and records them in the ledger, together with the cursor in one commit.
func (e *Engine) immediate(ctx context.Context, t *target, ts []model.Transition, last int64, now time.Time) error {
	uid := t.cfg.UID
	r := reduce(ts)
	ledger, err := e.st.Ledger(ctx, uid, r.order)
	if err != nil {
		return err
	}
	var updates []store.LedgerEntry
	byEvent := map[Event][]string{}
	for _, fp := range r.order {
		tr, l := r.final[fp], entry(ledger, fp)
		ev := classify(tr, l)
		if immediateEligible(t.cfg, ev, tr, l) {
			byEvent[ev] = append(byEvent[ev], fp)
			if le, ok := ledgerAfter(uid, ev, tr, l, now); ok {
				updates = append(updates, le)
			}
		} else if le, ok := excepted(uid, tr, l, now); ok {
			updates = append(updates, le)
		}
	}
	var deliveries []store.Delivery
	if len(byEvent) > 0 {
		if deliveries, err = e.immediateMessages(ctx, t, r, byEvent, now); err != nil {
			return err
		}
	}
	return e.st.CommitNotify(ctx, store.NotifyCommit{Target: uid, Cursors: map[string]int64{immediateCursor(uid): last},
		Ledger: updates, Deliveries: deliveries})
}

// immediateEvents are the events sent immediately, in the order their messages are queued.
var immediateEvents = []Event{EventDetected, EventEscalated, EventReopened, EventResolved}

func (e *Engine) immediateMessages(ctx context.Context, t *target, r latest, byEvent map[Event][]string, now time.Time) ([]store.Delivery, error) {
	var fps []string
	for _, ev := range immediateEvents {
		fps = append(fps, byEvent[ev]...)
	}
	views, b, err := e.views(ctx, fps, r)
	if err != nil {
		return nil, err
	}
	quietUntil, quiet := QuietUntil(t.cfg.QuietHours, now)
	var out []store.Delivery
	for _, ev := range immediateEvents {
		fs := make([]model.Finding, 0, len(byEvent[ev]))
		for _, fp := range byEvent[ev] {
			fs = append(fs, views[fp])
		}
		for _, g := range b.groups(ev, fs) {
			first, lastID := r.final[g.fps[0]].ID, r.final[g.fps[0]].ID
			for _, fp := range g.fps {
				first, lastID = min(first, r.final[fp].ID), max(lastID, r.final[fp].ID)
			}
			if ev == EventResolved && slices.ContainsFunc(g.fps, func(fp string) bool { return r.final[fp].Trigger == model.TriggerWithdrawn }) {
				g.item.Reasons = append([]string{"withdrawn"}, g.item.Reasons...)
			}
			key := fmt.Sprintf("%s|%s|%d|%d", g.key, ev, first, lastID)
			m := e.message(t, KindImmediate, key, immediateTitle(ev, g.subject, g.item), now)
			m.Items = []Item{g.item}
			notBefore := now
			if quiet && (!t.cfg.AllowUrgentInQuietHours || g.item.Priority != model.PriorityUrgent) {
				notBefore = quietUntil
			}
			d, err := delivery(m, notBefore)
			if err != nil {
				return nil, err
			}
			out = append(out, d)
		}
	}
	return out, nil
}

// views loads the findings of fps as of their final transitions in r, and an item builder over
// their advisories.
func (e *Engine) views(ctx context.Context, fps []string, r latest) (map[string]model.Finding, itemBuilder, error) {
	stored, err := e.st.FindingsByFingerprint(ctx, fps)
	if err != nil {
		return nil, itemBuilder{}, err
	}
	views := make(map[string]model.Finding, len(fps))
	ids := map[string]bool{}
	for _, fp := range fps {
		f, ok := stored[fp]
		views[fp] = view(f, ok, r.final[fp])
		ids[r.final[fp].AdvisoryID] = true
	}
	advs, err := e.st.Advisories(ctx, slices.Sorted(maps.Keys(ids)))
	if err != nil {
		return nil, itemBuilder{}, err
	}
	return views, itemBuilder{advisories: advs, dashboardURL: e.o.DashboardURL}, nil
}

// baseline sends a new target one summary of the open findings instead of an alert for each, and
// starts both of its cursors at the newest transition (spec §6.10). The newest ID is read before
// the findings, so a finding created in between is in the summary rather than lost.
func (e *Engine) baseline(ctx context.Context, t *target, now time.Time) error {
	uid := t.cfg.UID
	maxID, err := e.st.MaxTransitionID(ctx)
	if err != nil {
		return err
	}
	all, err := e.st.ListFindings(ctx, store.FindingFilter{States: []model.FindingState{model.StateOpen}})
	if err != nil {
		return err
	}
	owners, err := e.st.ListOwners(ctx)
	if err != nil {
		return err
	}
	n := 0
	for _, o := range owners {
		if o.Ref.Kind != "Cluster" && o.Ref.Kind != "ContainerRuntime" && t.cfg.allows(o.Ref.Namespace) {
			n++
		}
	}
	var open []model.Finding
	var ledger []store.LedgerEntry
	counts := map[model.Priority]int{}
	ids := map[string]bool{}
	for _, f := range all {
		if !t.cfg.allows(f.Owner.Namespace) {
			continue
		}
		open = append(open, f)
		counts[f.Priority]++
		ids[f.AdvisoryID] = true
		ledger = append(ledger, store.LedgerEntry{Target: uid, Fingerprint: f.Fingerprint, MaxPriority: f.Priority,
			LastState: model.StateOpen, UpdatedAt: now})
	}
	advs, err := e.st.Advisories(ctx, slices.Sorted(maps.Keys(ids)))
	if err != nil {
		return err
	}
	b := itemBuilder{advisories: advs, dashboardURL: e.o.DashboardURL}
	var items []Item
	for _, fs := range byAdvisory(open) {
		items = append(items, b.advisoryItem("", fs[0].AdvisoryID, fs))
	}
	slices.SortFunc(items, func(a, b Item) int {
		return cmp.Or(cmp.Compare(b.Priority, a.Priority), cmp.Compare(len(b.Owners), len(a.Owners)), strings.Compare(a.AdvisoryID, b.AdvisoryID))
	})
	m := e.message(t, KindBaseline, strconv.FormatInt(maxID, 10),
		baselineTitle(n, counts[model.PriorityUrgent], counts[model.PriorityHigh]), now)
	m.Items = items[:min(len(items), baselineItems)]
	m.Summary = &Summary{Workloads: n, Counts: counts}
	d, err := delivery(m, now)
	if err != nil {
		return err
	}
	return e.st.CommitNotify(ctx, store.NotifyCommit{Target: uid,
		Cursors: map[string]int64{immediateCursor(uid): maxID, digestCursor(uid): maxID},
		Ledger:  ledger, Deliveries: []store.Delivery{d}, BaselineAt: now, LastDigestAt: now})
}

// feedStale queues one alert per stale feed and episode for a target that opted in (spec §6.4).
// The episode is the feed's last success, so the alert's ID repeats until the feed recovers.
func (e *Engine) feedStale(ctx context.Context, t *target, now time.Time) error {
	if !t.cfg.NotifyOnFeedStale {
		return nil
	}
	for _, name := range slices.Sorted(maps.Keys(e.o.FeedStaleAfter)) {
		fs, err := e.st.FeedState(ctx, name)
		if err != nil {
			return err
		}
		status := e.feedStatus(fs, e.o.FeedStaleAfter[name], now)
		if !status.Stale {
			continue
		}
		m := e.message(t, KindFeedStale, fmt.Sprintf("%s@%d", name, fs.LastSuccess.Unix()), feedStaleTitle(name, fs.LastSuccess), now)
		if e.feedSent[m.ID] {
			continue
		}
		m.Feeds = []FeedStatus{status}
		d, err := delivery(m, now)
		if err != nil {
			return err
		}
		if err := e.st.CommitNotify(ctx, store.NotifyCommit{Target: t.cfg.UID, Deliveries: []store.Delivery{d}}); err != nil {
			return err
		}
		e.feedSent[m.ID] = true
	}
	return nil
}

// feedStatus reports a feed's freshness. A feed that never synced is measured from engine start.
func (e *Engine) feedStatus(fs store.FeedState, staleAfter time.Duration, now time.Time) FeedStatus {
	since := fs.LastSuccess
	if since.IsZero() {
		since = e.started
	}
	return FeedStatus{Name: fs.Name, LastSuccess: fs.LastSuccess, StaleAfter: staleAfter,
		Stale: staleAfter > 0 && now.Sub(since) > staleAfter, LastError: fs.LastError}
}

// message starts a message for t with its stable ID.
func (e *Engine) message(t *target, kind Kind, key, title string, now time.Time) Message {
	return Message{ID: messageID(t.cfg.UID, kind, key), Kind: kind, Cluster: e.o.Cluster, TargetName: t.cfg.Name,
		Title: title, DashboardURL: e.o.DashboardURL, At: now}
}

// delivery wraps m as a pending delivery to its target, not sent before notBefore.
func delivery(m Message, notBefore time.Time) (store.Delivery, error) {
	payload, err := json.Marshal(m)
	if err != nil {
		return store.Delivery{}, fmt.Errorf("encode message: %w", err)
	}
	return store.Delivery{ID: m.ID, Kind: string(m.Kind), Payload: payload, State: store.DeliveryPending,
		NotBefore: notBefore, CreatedAt: m.At}, nil
}
