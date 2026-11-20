// Package live is the change-event hub behind GET /api/v1/stream. It learns of changes from the
// engine (findings recomputed, matches replaced) and by polling the store's change marks, coalesces
// them over a short window, and sends each coalesced event to every open stream, keeping recent
// events so a reconnecting browser can replay what it missed.
package live

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/utils/clock"

	"github.com/the-it-dept/ffs/internal/store"
)

// Kind is what changed; the values of the API's ChangeKind schema.
type Kind string

// The change kinds. KindAll asks the browser to refresh everything.
const (
	KindFindings   Kind = "findings"
	KindInventory  Kind = "inventory"
	KindImages     Kind = "images"
	KindFeeds      Kind = "feeds"
	KindNodes      Kind = "nodes"
	KindExceptions Kind = "exceptions"
	KindAll        Kind = "all"
)

// Event is one coalesced change, as the stream sends it: Seq is "<epoch hex>-<seq>", Kinds and
// Scopes are sorted. A scope "*" means every scope, and "<kind>:*" every scope of that kind.
type Event struct {
	Seq    string   `json:"seq"`
	Kinds  []Kind   `json:"kinds"`
	Scopes []string `json:"scopes"`
}

// ID is the event's stream id, its Seq.
func (e Event) ID() string { return e.Seq }

// MarkSource reads the store's change marks; *store.Store implements it.
type MarkSource interface {
	ChangeMarks(ctx context.Context) (store.ChangeMarks, error)
}

// NodeMarks returns an opaque mark of the node grouping and node-agent state; equal marks mean no
// change.
type NodeMarks func(ctx context.Context) (string, error)

// Options configure a Hub. Zero durations and sizes take the defaults; a nil Now is time.Now, a nil
// Clock the real clock, a nil Marks or Nodes polls nothing of that kind, and a nil Store leaves
// owner digests unexpanded.
type Options struct {
	Store      *store.Store
	Marks      MarkSource
	Nodes      NodeMarks
	Coalesce   time.Duration // 2s: how long changes gather into one event
	Poll       time.Duration // 2s: how often the change marks are compared
	Heartbeat  time.Duration // 25s: how often an idle stream gets a comment
	Ring       int           // 256: how many events are kept for replay
	MaxStreams int           // 64: open streams at once
	Now        func() time.Time
	Log        logr.Logger
	// Clock drives the coalescer, the poller and the heartbeats. It needs AfterFunc as well as
	// NewTicker, so it is a WithTickerAndDelayedExecution (clock.RealClock and the fake clock
	// implement it).
	Clock clock.WithTickerAndDelayedExecution
	// Cluster is the cluster name the problem document of a refused stream carries.
	Cluster string
}

const (
	defaultCoalesce   = 2 * time.Second
	defaultPoll       = 2 * time.Second
	defaultHeartbeat  = 25 * time.Second
	defaultRing       = 256
	defaultMaxStreams = 64

	// subscriberBuffer is how many events a stream may fall behind before it is closed; its browser
	// reconnects and replays from the ring.
	subscriberBuffer = 16
	// maxScopes is how many scopes an event names before it says "*".
	maxScopes = 200
	// expandTimeout bounds the store read that turns owners into image scopes.
	expandTimeout = 5 * time.Second
)

// Hub coalesces changes into events and fans them out to the open streams. Its state is guarded by
// mu; flushes are serialised by flushMu, and neither lock is held while the clock is called.
type Hub struct {
	o     Options
	epoch string

	flushMu sync.Mutex

	mu      sync.Mutex
	kinds   map[Kind]bool   // pending
	scopes  map[string]bool // pending
	owners  map[string]bool // pending owner keys whose digests become image scopes
	armed   bool            // a flush is scheduled
	seq     uint64          // the latest event's sequence number
	ring    []Event         // the latest events, oldest first
	subs    map[*subscriber]struct{}
	closed  bool
	done    chan struct{}
	closeMu sync.Once
}

// subscriber is one open stream: its pending events, and gone, closed when the hub drops it.
type subscriber struct {
	ch   chan Event
	gone chan struct{}
}

// NewHub returns a hub with o's defaults filled in. Its epoch is the start time in Unix nanoseconds,
// in hex, so ids from an earlier process are never mistaken for this one's.
func NewHub(o Options) *Hub {
	if o.Coalesce <= 0 {
		o.Coalesce = defaultCoalesce
	}
	if o.Poll <= 0 {
		o.Poll = defaultPoll
	}
	if o.Heartbeat <= 0 {
		o.Heartbeat = defaultHeartbeat
	}
	if o.Ring <= 0 {
		o.Ring = defaultRing
	}
	if o.MaxStreams <= 0 {
		o.MaxStreams = defaultMaxStreams
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Clock == nil {
		o.Clock = clock.RealClock{}
	}
	if o.Log.GetSink() == nil {
		o.Log = logr.Discard()
	}
	return &Hub{
		o: o, epoch: fmt.Sprintf("%x", o.Now().UnixNano()),
		kinds: map[Kind]bool{}, scopes: map[string]bool{}, owners: map[string]bool{},
		subs: map[*subscriber]struct{}{}, done: make(chan struct{}),
	}
}

// Publish queues a change of kinds in scopes; it is sent with the next coalesced event.
func (h *Hub) Publish(kinds []Kind, scopes []string) { h.add(kinds, scopes, nil) }

// add merges a change into the pending event and schedules a flush when none is.
func (h *Hub) add(kinds []Kind, scopes, owners []string) {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	for _, k := range kinds {
		h.kinds[k] = true
	}
	for _, s := range scopes {
		h.scopes[s] = true
	}
	for _, o := range owners {
		h.owners[o] = true
	}
	arm := !h.armed
	h.armed = true
	h.mu.Unlock()
	if arm {
		h.o.Clock.AfterFunc(h.o.Coalesce, h.flush)
	}
}

// flush turns the pending change into an event: owners become the image scopes of their digests,
// the scopes are sorted (or "*" above maxScopes), and the event is numbered, kept in the ring and
// sent to every stream. A stream too far behind is dropped.
func (h *Hub) flush() {
	h.flushMu.Lock()
	defer h.flushMu.Unlock()
	h.mu.Lock()
	kinds, scopes, owners := h.kinds, h.scopes, h.owners
	h.kinds, h.scopes, h.owners, h.armed = map[Kind]bool{}, map[string]bool{}, map[string]bool{}, false
	h.mu.Unlock()
	if len(kinds) == 0 {
		return
	}
	if len(owners) > 0 && h.o.Store != nil {
		ctx, cancel := context.WithTimeout(context.Background(), expandTimeout)
		byOwner, err := h.o.Store.DigestsOfOwners(ctx, sortedKeys(owners))
		cancel()
		if err != nil {
			h.o.Log.Error(err, "cannot expand owners into image scopes")
		}
		for _, digests := range byOwner {
			for _, d := range digests {
				if containerDigest(d) {
					scopes["image:"+d] = true
				}
			}
		}
	}
	ev := Event{Kinds: sortedKeys(kinds), Scopes: sortedKeys(scopes)}
	if len(ev.Scopes) > maxScopes || scopes["*"] {
		ev.Scopes = []string{"*"}
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.seq++
	ev.Seq = h.seqID(h.seq)
	h.ring = append(h.ring, ev)
	if len(h.ring) > h.o.Ring {
		h.ring = slices.Clone(h.ring[len(h.ring)-h.o.Ring:])
	}
	for sub := range h.subs {
		select {
		case sub.ch <- ev:
		default:
			h.dropLocked(sub)
		}
	}
}

func (h *Hub) seqID(n uint64) string { return fmt.Sprintf("%s-%d", h.epoch, n) }

// dropLocked removes a stream; its handler sees gone and ends the response. mu must be held.
func (h *Hub) dropLocked(sub *subscriber) {
	if _, ok := h.subs[sub]; ok {
		delete(h.subs, sub)
		close(sub.gone)
	}
}

// Streams is how many streams are open.
func (h *Hub) Streams() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}

// Start polls the change marks until ctx ends, then closes the hub. The first poll of each source
// sets its baseline; a later difference publishes its kinds to every scope.
func (h *Hub) Start(ctx context.Context) error {
	defer h.Close()
	if h.o.Marks == nil && h.o.Nodes == nil {
		select {
		case <-ctx.Done():
		case <-h.done:
		}
		return nil
	}
	t := h.o.Clock.NewTicker(h.o.Poll)
	defer t.Stop()
	var p poller
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-h.done:
			return nil
		case <-t.C():
			h.poll(ctx, &p)
		}
	}
}

// NeedLeaderElection is false: every replica serves streams.
func (h *Hub) NeedLeaderElection() bool { return false }

// Close ends every open stream and stops the hub. It is safe to call more than once.
func (h *Hub) Close() {
	h.closeMu.Do(func() {
		h.mu.Lock()
		h.closed = true
		for sub := range h.subs {
			h.dropLocked(sub)
		}
		h.mu.Unlock()
		close(h.done)
	})
}

// poller holds the last good marks of each source.
type poller struct {
	marks *store.ChangeMarks
	nodes *string
}

// poll compares the marks with the last good ones and publishes what changed. A read error is
// logged and leaves the last good marks in place.
func (h *Hub) poll(ctx context.Context, p *poller) {
	var kinds []Kind
	if h.o.Marks != nil {
		m, err := h.o.Marks.ChangeMarks(ctx)
		switch {
		case err != nil:
			h.o.Log.Error(err, "cannot read change marks")
		case p.marks != nil:
			kinds = append(kinds, markKinds(*p.marks, m)...)
			p.marks = &m
		default:
			p.marks = &m
		}
	}
	if h.o.Nodes != nil {
		m, err := h.o.Nodes(ctx)
		switch {
		case err != nil:
			h.o.Log.Error(err, "cannot read node marks")
		case p.nodes != nil:
			if m != *p.nodes {
				kinds = append(kinds, KindNodes)
			}
			p.nodes = &m
		default:
			p.nodes = &m
		}
	}
	if len(kinds) > 0 {
		h.add(kinds, []string{"*"}, nil)
	}
}

// markKinds lists what changed between two sets of marks.
func markKinds(old, cur store.ChangeMarks) []Kind {
	var kinds []Kind
	if old.Images != cur.Images {
		kinds = append(kinds, KindImages)
	}
	if old.Feeds != cur.Feeds {
		kinds = append(kinds, KindFeeds)
	}
	if old.Exceptions != cur.Exceptions {
		kinds = append(kinds, KindExceptions, KindFindings)
	}
	if old.Suggestions != cur.Suggestions {
		kinds = append(kinds, KindFindings)
	}
	if old.Nodes != cur.Nodes {
		kinds = append(kinds, KindNodes)
	}
	return kinds
}

// containerDigest reports whether d is a container image digest: not a synthetic Kubernetes or
// runtime digest, nor a node group's host packages.
func containerDigest(d string) bool {
	return !strings.HasPrefix(d, "k8s:") && !strings.HasPrefix(d, "runtime:") && !strings.HasPrefix(d, "nodegroup:")
}

func sortedKeys[K ~string](m map[K]bool) []K {
	out := make([]K, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
