// Package engine orchestrates matching and findings. Inventory and feed hooks re-match images and
// apply match deltas, queue the owners whose matches or context changed, and recompute those owners'
// findings, writing state changes to the transitions outbox. Outputs never call the engine: they
// read the store, woken by Changed.
package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/feeds/grypedb"
	"github.com/the-it-dept/ffs/internal/feeds/osv"
	"github.com/the-it-dept/ffs/internal/findings"
	"github.com/the-it-dept/ffs/internal/match"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/output/metrics"
	"github.com/the-it-dept/ffs/internal/store"
)

// Store is the part of *store.Store the engine uses.
type Store interface {
	GetImage(ctx context.Context, digest string) (model.Image, bool, error)
	GetSBOM(ctx context.Context, digest string) ([]byte, bool, error)
	PackagesForImage(ctx context.Context, digest string) ([]model.Package, error)
	ReplaceMatches(ctx context.Context, scope store.MatchScope, ms []model.Match) ([]string, error)
	MatchesForDigests(ctx context.Context, digests []string) ([]model.Match, error)
	OwnersForDigests(ctx context.Context, digests []string) ([]string, error)
	OwnersWithAdvisories(ctx context.Context, ids []string) ([]string, error)
	GetOwner(ctx context.Context, key string) (model.Owner, bool, error)
	ListOwners(ctx context.Context) ([]model.Owner, error)
	FindingsForOwner(ctx context.Context, key string) ([]model.Finding, error) // all states, incl. resolved
	ApplyFindings(ctx context.Context, upserts []model.Finding, ts []model.Transition) error
	Advisories(ctx context.Context, ids []string) (map[string]model.Advisory, error)
	Canonical(ctx context.Context, id string) (string, error)
	RekeyFindings(ctx context.Context, rks []store.FindingRekey) error
	DigestsInUse(ctx context.Context) ([]string, error)
	PruneResolved(ctx context.Context, olderThan time.Time) (int, error)
	PruneImages(ctx context.Context, now time.Time, unusedFor time.Duration) (int, error)
	RecordGrypeDBBuild(ctx context.Context, built time.Time) error
	GrypeDBBuilds(ctx context.Context) ([]time.Time, error)
}

// ExceptionSource supplies the cached Exception rules (*store.Store, Task 22).
type ExceptionSource interface {
	ExceptionRules(ctx context.Context) ([]findings.ExceptionRule, error)
}

// CNAMatcher re-evaluates advisories whose cvelistV5 records changed (the upstream matcher).
type CNAMatcher interface {
	ApplyCNA(ctx context.Context, advisoryIDs []string) ([]match.Delta, error)
}

// GrypeMatcher is the matcher of record (*grype.Matcher).
type GrypeMatcher interface {
	match.Matcher
	Load(path string, built time.Time) error
	Rematch(ctx context.Context, changed []grypedb.PackageKey) (match.Delta, error)
	RematchAll(ctx context.Context) (match.Delta, error)
}

// Options configures an Engine.
type Options struct {
	Config     config.Config
	Store      Store
	Exceptions ExceptionSource       // nil = no exceptions
	Grype      GrypeMatcher          // always set; returns match.ErrNotReady until a DB is loaded
	Matchers   []match.Matcher       // non-grype image matchers, run in order: osvfast, upstream, k8s
	Records    []match.RecordMatcher // osvfast, upstream, k8s
	CNA        CNAMatcher            // upstream; nil = no CNA matching
	Now        func() time.Time      // nil = time.Now
	Log        logr.Logger
}

// Engine turns inventory and feed events into matches, findings and transitions. It is safe for
// concurrent use.
type Engine struct {
	o Options

	mu sync.Mutex // serialises Recompute

	qmu     sync.Mutex
	pending map[string]model.Trigger // owner key → trigger of its queued recompute
	running atomic.Int32             // Recompute calls in progress, or batches Drain has taken
	wake    chan struct{}

	subMu sync.Mutex
	subs  []chan struct{}

	expiryMu  sync.Mutex
	lastCheck time.Time // CheckExceptionExpiry has seen every expiry up to here

	obsMu     sync.Mutex
	observers []Observer
}

// New returns an engine with an empty queue.
func New(o Options) *Engine {
	if o.Now == nil {
		o.Now = time.Now
	}
	e := &Engine{o: o, pending: map[string]model.Trigger{}, wake: make(chan struct{}, 1)}
	e.lastCheck = e.now()
	return e
}

func (e *Engine) now() time.Time { return e.o.Now().UTC() }

// OnImageCatalogued re-matches a newly catalogued digest with every matcher and queues the owners
// running it. The owners are queued even when a matcher failed; the error is returned afterwards.
func (e *Engine) OnImageCatalogued(ctx context.Context, digest string) error {
	_, err := e.matchImage(ctx, digest, true)
	// The owners are looked up now: a synthetic digest can be catalogued before its owner is stored,
	// and the owner change then arrives through OnOwnersChanged.
	owners, oerr := e.o.Store.OwnersForDigests(ctx, []string{digest})
	if oerr != nil {
		return errors.Join(err, fmt.Errorf("engine: owners of %s: %w", digest, oerr))
	}
	e.enqueue(owners, model.TriggerInventoryChange)
	return err
}

// OnOwnersChanged queues owners whose containers, context or existence changed. Diff reports a
// change that only moves priority as a PriorityChange.
func (e *Engine) OnOwnersChanged(_ context.Context, keys []string) error {
	e.enqueue(keys, model.TriggerInventoryChange)
	return nil
}

// OnMatchDelta replaces the matches in d's scope and queues the owners of every digest whose
// matches changed, plus, for an advisory-scoped delta, the owners holding findings on those
// advisories (an alias merge can move matches between advisory keys without changing a digest's
// rows). A delta with an empty scope is a no-op.
func (e *Engine) OnMatchDelta(ctx context.Context, d match.Delta, trig model.Trigger) error {
	s := d.Scope
	if len(s.Digests) == 0 && len(s.PackageIDs) == 0 && len(s.AdvisoryIDs) == 0 {
		return nil
	}
	// A match without an observation time is observed now; ReplaceMatches keeps the earlier of a
	// surviving row's stored and incoming times, so nothing is re-read here.
	affected, err := e.o.Store.ReplaceMatches(ctx, s, stampObserved(d.Matches, nil, e.now()))
	if err != nil {
		return fmt.Errorf("engine: replace %s matches: %w", s.Source, err)
	}
	e.matchesReplaced(ctx, affected)
	if len(affected) > 0 {
		owners, err := e.o.Store.OwnersForDigests(ctx, affected)
		if err != nil {
			return fmt.Errorf("engine: owners of changed digests: %w", err)
		}
		e.enqueue(owners, trig)
	}
	if len(s.AdvisoryIDs) > 0 {
		owners, err := e.o.Store.OwnersWithAdvisories(ctx, s.AdvisoryIDs)
		if err != nil {
			return fmt.Errorf("engine: owners with changed advisories: %w", err)
		}
		e.enqueue(owners, trig)
	}
	return nil
}

// OnAdvisoriesEnriched queues the owners holding findings on ids, whose KEV, EPSS or CNA severity
// changed.
func (e *Engine) OnAdvisoriesEnriched(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	owners, err := e.o.Store.OwnersWithAdvisories(ctx, ids)
	if err != nil {
		return fmt.Errorf("engine: owners with enriched advisories: %w", err)
	}
	e.enqueue(owners, model.TriggerPriorityChange)
	return nil
}

// OnExceptionsChanged queues every owner, since any finding may gain or lose an exception.
func (e *Engine) OnExceptionsChanged(ctx context.Context) error {
	return e.enqueueAll(ctx, model.TriggerPriorityChange)
}

// observe records the time since start in h.
func observe(h prometheus.Observer, start time.Time) { h.Observe(time.Since(start).Seconds()) }

// OnOSVRecords hands changed OSV records to every record matcher and applies their deltas. A
// failing matcher does not stop the others; the errors are returned together.
func (e *Engine) OnOSVRecords(ctx context.Context, recs []osv.Changed) error {
	defer observe(metrics.RematchDuration.WithLabelValues("osv"), time.Now())
	var errs []error
	for _, m := range e.o.Records {
		ds, err := m.ApplyOSV(ctx, recs)
		if err != nil {
			errs = append(errs, fmt.Errorf("engine: apply OSV records: %w", err))
		}
		errs = append(errs, e.applyDeltas(ctx, ds, model.TriggerNewAdvisory))
	}
	return errors.Join(errs...)
}

// OnCNARecords re-matches advisories whose cvelistV5 records changed, then queues the owners
// holding them, since their CNA severity may have changed.
func (e *Engine) OnCNARecords(ctx context.Context, ids []string) error {
	defer observe(metrics.RematchDuration.WithLabelValues("cna"), time.Now())
	var errs []error
	if e.o.CNA != nil {
		ds, err := e.o.CNA.ApplyCNA(ctx, ids)
		if err != nil {
			errs = append(errs, fmt.Errorf("engine: apply CNA records: %w", err))
		}
		errs = append(errs, e.applyDeltas(ctx, ds, model.TriggerNewAdvisory))
	}
	errs = append(errs, e.OnAdvisoriesEnriched(ctx, ids))
	return errors.Join(errs...)
}

// OnGrypeDB loads a new Grype DB, records its build and re-matches the affected digests (every
// digest when u.Full). Every owner is then queued, because the new build counts towards settling
// provisional findings. A load failure is returned before the build is recorded, so the feed offers
// the build again.
func (e *Engine) OnGrypeDB(ctx context.Context, u grypedb.Update) error {
	defer observe(metrics.RematchDuration.WithLabelValues("grypedb"), time.Now())
	if err := e.o.Grype.Load(u.Path, u.Built); err != nil {
		return fmt.Errorf("engine: load grype database: %w", err)
	}
	if err := e.o.Store.RecordGrypeDBBuild(ctx, u.Built); err != nil {
		return fmt.Errorf("engine: record grype database build: %w", err)
	}
	var (
		d   match.Delta
		err error
	)
	if u.Full {
		d, err = e.o.Grype.RematchAll(ctx)
	} else {
		d, err = e.o.Grype.Rematch(ctx, u.Changed)
	}
	if err != nil {
		return fmt.Errorf("engine: grype re-match: %w", err)
	}
	if err := e.OnMatchDelta(ctx, d, model.TriggerNewAdvisory); err != nil {
		return err
	}
	return e.enqueueAll(ctx, model.TriggerNewAdvisory)
}

// MatchCandidate runs every matcher over a catalogued digest and returns the matches without
// storing them, with canonical advisory ids. A grype matcher with no DB loaded contributes no
// matches; any other matcher failure is an error. An uncatalogued digest has no matches.
func (e *Engine) MatchCandidate(ctx context.Context, digest string) ([]model.Match, error) {
	ms, err := e.matchImage(ctx, digest, false)
	if err != nil {
		return nil, err
	}
	return e.canonicalise(ctx, ms)
}

// Changed returns a new subscriber channel. It receives a value, coalesced, whenever a Recompute
// writes findings or transitions.
func (e *Engine) Changed() <-chan struct{} {
	ch := make(chan struct{}, 1)
	e.subMu.Lock()
	e.subs = append(e.subs, ch)
	e.subMu.Unlock()
	return ch
}

// signal notifies every Changed subscriber without blocking.
func (e *Engine) signal() {
	e.subMu.Lock()
	defer e.subMu.Unlock()
	for _, ch := range e.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// Idle reports whether no owner is queued and no Recompute is running.
func (e *Engine) Idle() bool {
	e.qmu.Lock()
	defer e.qmu.Unlock()
	return len(e.pending) == 0 && e.running.Load() == 0
}

// applyDeltas applies each delta, continuing past failures.
func (e *Engine) applyDeltas(ctx context.Context, ds []match.Delta, trig model.Trigger) error {
	var errs []error
	for _, d := range ds {
		errs = append(errs, e.OnMatchDelta(ctx, d, trig))
	}
	return errors.Join(errs...)
}

// enqueueAll queues every stored owner.
func (e *Engine) enqueueAll(ctx context.Context, trig model.Trigger) error {
	owners, err := e.o.Store.ListOwners(ctx)
	if err != nil {
		return fmt.Errorf("engine: list owners: %w", err)
	}
	keys := make([]string, len(owners))
	for i, o := range owners {
		keys[i] = o.Ref.Key()
	}
	e.enqueue(keys, trig)
	return nil
}

// canonicalise rewrites the advisory ids of ms to their canonicals and keeps the last match of each
// key, as ReplaceMatches does when it stores them.
func (e *Engine) canonicalise(ctx context.Context, ms []model.Match) ([]model.Match, error) {
	canon := map[string]string{}
	index := map[matchKey]int{}
	var out []model.Match
	for _, m := range ms {
		c, ok := canon[m.AdvisoryID]
		if !ok {
			var err error
			if c, err = e.o.Store.Canonical(ctx, m.AdvisoryID); err != nil {
				return nil, fmt.Errorf("engine: canonical id of %s: %w", m.AdvisoryID, err)
			}
			canon[m.AdvisoryID] = c
		}
		m.AdvisoryID = c
		k := keyOf(m)
		if i, dup := index[k]; dup {
			out[i] = m
			continue
		}
		index[k] = len(out)
		out = append(out, m)
	}
	return out, nil
}
