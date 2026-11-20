// Package events turns finding transitions into aggregated Kubernetes Events.
package events

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	kevents "k8s.io/client-go/tools/events"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

const (
	// CursorName is the transition cursor this emitter consumes under.
	CursorName = "events"
	// BatchSize is the number of transitions read and aggregated at a time.
	BatchSize = 500
	// MaxNoteBytes caps an event note.
	MaxNoteBytes = 1024

	resyncInterval = 60 * time.Second
	// staleRepeat is how often FeedStale is emitted again while a feed stays stale: Kubernetes
	// expires Events after about an hour, so a feed that stays stale keeps a visible Event.
	staleRepeat = time.Hour
)

func typesUID(s string) types.UID { return types.UID(s) }

// Store is the persistence the emitter needs.
type Store interface {
	TransitionsAfter(ctx context.Context, afterID int64, limit int) ([]model.Transition, error)
	Cursor(ctx context.Context, consumer string) (int64, error)
	SetCursor(ctx context.Context, consumer string, id int64) error
	FindingsForOwner(ctx context.Context, key string) ([]model.Finding, error)
	FeedState(ctx context.Context, name string) (store.FeedState, error)
}

// Options configures an Emitter.
type Options struct {
	Store    Store
	Recorder kevents.EventRecorder
	Config   config.EventsConfig
	// Self is the ffs Deployment. When nil, cluster-level and health Events are skipped.
	Self    *corev1.ObjectReference
	Changed <-chan struct{}
	Log     logr.Logger
	Now     func() time.Time // nil = time.Now
}

// Emitter writes one Event per owner and reason for each batch of transitions. It is a
// leader-only Runnable.
type Emitter struct {
	o Options

	mu    sync.Mutex
	stale map[string]staleFeed // by feed name, while the feed stays stale
}

// staleFeed is a feed FeedStale reported and when its Event was last emitted.
type staleFeed struct {
	lastSuccess time.Time
	staleAfter  time.Duration
	emitted     time.Time
}

// New returns an Emitter.
func New(o Options) *Emitter {
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Emitter{o: o, stale: map[string]staleFeed{}}
}

// Start drains on every Changed signal and every 60s until ctx is done, and repeats the FeedStale
// Event of a feed that stays stale (RepeatStale).
func (e *Emitter) Start(ctx context.Context) error {
	tick := time.NewTicker(resyncInterval)
	defer tick.Stop()
	for {
		if err := e.Drain(ctx); err != nil && ctx.Err() == nil {
			e.o.Log.Error(err, "emitting events failed")
		}
		e.RepeatStale(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-e.o.Changed:
		case <-tick.C:
		}
	}
}

// Drain emits events for every transition after the cursor, then advances the cursor.
func (e *Emitter) Drain(ctx context.Context) error {
	min, err := model.ParsePriority(e.o.Config.MinPriority)
	if err != nil {
		return fmt.Errorf("events: events.minPriority: %w", err)
	}
	cursor, err := e.o.Store.Cursor(ctx, CursorName)
	if err != nil {
		return fmt.Errorf("events: read cursor: %w", err)
	}
	for {
		batch, err := e.o.Store.TransitionsAfter(ctx, cursor, BatchSize)
		if err != nil {
			return fmt.Errorf("events: read transitions: %w", err)
		}
		if len(batch) == 0 {
			return nil
		}
		if err := e.emitBatch(ctx, batch, min); err != nil {
			return err
		}
		cursor = batch[len(batch)-1].ID
		if err := e.o.Store.SetCursor(ctx, CursorName, cursor); err != nil {
			return fmt.Errorf("events: write cursor: %w", err)
		}
	}
}

type ownerBatch struct {
	owner    model.OwnerRef
	byReason map[string][]model.Transition
}

func (e *Emitter) emitBatch(ctx context.Context, batch []model.Transition, min model.Priority) error {
	owners := map[string]*ownerBatch{}
	for _, t := range batch {
		reason, p, ok := classify(t)
		if !ok || p < min {
			continue
		}
		key := t.Owner.Key()
		ob := owners[key]
		if ob == nil {
			ob = &ownerBatch{owner: t.Owner, byReason: map[string][]model.Transition{}}
			owners[key] = ob
		}
		ob.byReason[reason] = append(ob.byReason[reason], t)
	}
	keys := make([]string, 0, len(owners))
	for k := range owners {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		ob := owners[key]
		ref, prefix, ok := regarding(ob.owner, e.o.Self)
		if !ok {
			e.o.Log.V(1).Info("no event target for owner", "owner", key)
			continue
		}
		var findings map[string]*model.Finding
		for _, reason := range reasonOrder {
			ts := ob.byReason[reason]
			if len(ts) == 0 {
				continue
			}
			if reason == ReasonDetected || reason == ReasonUpgradeAvailable {
				if findings == nil {
					var err error
					if findings, err = e.findings(ctx, key); err != nil {
						return err
					}
				}
			}
			items := make([]item, 0, len(ts))
			for _, t := range ts {
				items = append(items, buildItem(reason, t, findings[t.Fingerprint]))
			}
			eventType, note := buildNote(reason, prefix, items)
			e.o.Recorder.Eventf(ref, nil, eventType, reason, "Evaluate", "%s", note)
		}
	}
	return nil
}

func (e *Emitter) findings(ctx context.Context, ownerKey string) (map[string]*model.Finding, error) {
	fs, err := e.o.Store.FindingsForOwner(ctx, ownerKey)
	if err != nil {
		return nil, fmt.Errorf("events: findings for %s: %w", ownerKey, err)
	}
	m := make(map[string]*model.Finding, len(fs))
	for i := range fs {
		m[fs[i].Fingerprint] = &fs[i]
	}
	return m, nil
}

// FeedStale emits a Warning on the ffs Deployment that a feed has not synced within staleAfter, and
// remembers the feed so RepeatStale emits it again while the feed stays stale.
func (e *Emitter) FeedStale(feed string, lastSuccess time.Time, staleAfter time.Duration) {
	if e.o.Self == nil {
		return
	}
	e.emitStale(feed, lastSuccess, staleAfter)
	e.mu.Lock()
	e.stale[feed] = staleFeed{lastSuccess: lastSuccess, staleAfter: staleAfter, emitted: e.o.Now()}
	e.mu.Unlock()
}

// RepeatStale emits FeedStale again for every remembered feed whose Event is an hour old, and
// forgets the feeds that synced since they were reported (the feed state's last success moved on).
func (e *Emitter) RepeatStale(ctx context.Context) {
	e.mu.Lock()
	feeds := make(map[string]staleFeed, len(e.stale))
	maps.Copy(feeds, e.stale)
	e.mu.Unlock()
	for _, name := range slices.Sorted(maps.Keys(feeds)) {
		sf := feeds[name]
		st, err := e.o.Store.FeedState(ctx, name)
		if err != nil {
			if ctx.Err() == nil {
				e.o.Log.Error(err, "reading a stale feed's state failed", "feed", name)
			}
			continue
		}
		now := e.o.Now()
		synced := st.LastSuccess.After(sf.lastSuccess)
		if !synced && now.Sub(sf.emitted) < staleRepeat {
			continue
		}
		if !synced {
			e.emitStale(name, sf.lastSuccess, sf.staleAfter)
		}
		e.mu.Lock()
		if e.stale[name] == sf { // a FeedStale meanwhile starts over
			if synced {
				delete(e.stale, name)
			} else {
				sf.emitted = now
				e.stale[name] = sf
			}
		}
		e.mu.Unlock()
	}
}

func (e *Emitter) emitStale(feed string, lastSuccess time.Time, staleAfter time.Duration) {
	var note string
	if lastSuccess.IsZero() {
		note = fmt.Sprintf("Feed %s has never synced (stale after %s). Findings may be out of date.", feed, staleAfter)
	} else {
		note = fmt.Sprintf("Feed %s has not synced since %s (stale after %s). Findings may be out of date.",
			feed, lastSuccess.UTC().Format(time.RFC3339), staleAfter)
	}
	e.o.Recorder.Eventf(e.o.Self, nil, "Warning", ReasonFeedStale, "Sync", "%s", note)
}
