// Package engine orchestrates matching and findings. Inventory and feed hooks re-match images and
// apply match deltas, queue the owners whose matches or context changed, and recompute those owners'
// findings, writing state changes to the transitions outbox. Outputs never call the engine: they
// read the store, woken by Changed.
package engine

import (
	"context"
	"errors"
	"fmt"
	"slices"
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
	Rehome(ctx context.Context, upsert *model.Owner, moves []store.FindingMove, drop []string) error
	RehomeWithState(ctx context.Context, upsert *model.Owner, moves []store.FindingMove, drop []string, state store.NodesState) error
	FindingsByFingerprint(ctx context.Context, fps []string) (map[string]model.Finding, error)
	DigestsInUse(ctx context.Context) ([]string, error)
	LiveDigests(ctx context.Context) ([]string, error)
	DigestsAwaitingGrype(ctx context.Context, built time.Time) ([]string, error)
	UnmatchedDigests(ctx context.Context, digests []string) ([]string, error)
	MarkMatched(ctx context.Context, digest string) error
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
	// Affected returns the digests whose grype search keys include a changed package.
	Affected(ctx context.Context, changed []grypedb.PackageKey) ([]string, error)
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
	// matchMu serialises every match computation with the write of its result: matchImage, record
	// and CNA deltas, and each digest of a Grype DB re-match. A matcher reads the records, packages or
	// stored matches it computes from, then replaces a whole scope; without it a concurrent writer's
	// matches in that scope would be overwritten by a result computed before they existed.
	matchMu sync.Mutex

	qmu     sync.Mutex
	pending map[string]model.Trigger // owner key → trigger of its queued recompute
	running atomic.Int32             // Recompute calls in progress, or batches Drain has taken
	wake    chan struct{}
	// awaiting, under qmu, holds the To owners Rehome found absent, by owner key, with when it did:
	// their recompute is skipped for rehomeWait so the moved findings are not resolved before the
	// owner is stored.
	awaiting map[string]time.Time

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
	e := &Engine{o: o, pending: map[string]model.Trigger{}, awaiting: map[string]time.Time{}, wake: make(chan struct{}, 1)}
	e.lastCheck = e.now()
	return e
}

func (e *Engine) now() time.Time { return e.o.Now().UTC() }

// OnImageCatalogued re-matches a newly catalogued digest with every matcher and queues the owners
// running it. The owners are queued even when a matcher failed; the error is returned afterwards.
// Once every matcher succeeded the digest's mark as unmatched (store.MarkUnmatched) is cleared
// before its owners are queued, so their recompute resolves findings against its matches instead
// of carrying them.
func (e *Engine) OnImageCatalogued(ctx context.Context, digest string) error {
	_, err := e.matchImage(ctx, digest, matchPersist)
	if err == nil {
		if merr := e.o.Store.MarkMatched(ctx, digest); merr != nil {
			err = fmt.Errorf("engine: record %s matched: %w", digest, merr)
		}
	}
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
// change that only moves priority as a PriorityChange. An owner Rehome was awaiting is no longer
// awaited: its recompute proceeds whether or not it is stored.
func (e *Engine) OnOwnersChanged(_ context.Context, keys []string) error {
	e.qmu.Lock()
	for _, k := range keys {
		delete(e.awaiting, k)
	}
	e.qmu.Unlock()
	e.enqueue(keys, model.TriggerInventoryChange)
	return nil
}

// OnMatchDelta replaces the matches in d's scope and queues the owners of every digest whose
// matches changed, plus, for an advisory-scoped delta, the owners holding findings on those
// advisories (an alias merge can move matches between advisory keys without changing a digest's
// rows). A delta with an empty scope is a no-op.
func (e *Engine) OnMatchDelta(ctx context.Context, d match.Delta, trig model.Trigger) error {
	e.matchMu.Lock()
	defer e.matchMu.Unlock()
	return e.applyDelta(ctx, d, trig)
}

// applyDelta is OnMatchDelta; the caller holds matchMu.
func (e *Engine) applyDelta(ctx context.Context, d match.Delta, trig model.Trigger) error {
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
// failing matcher does not stop the others; the errors are returned together. Each matcher's
// evaluation and the write of its deltas hold matchMu, so an image catalogued meanwhile is matched
// after the deltas land, against the records they came from.
func (e *Engine) OnOSVRecords(ctx context.Context, recs []osv.Changed) error {
	defer observe(metrics.RematchDuration.WithLabelValues("osv"), time.Now())
	var errs []error
	for _, m := range e.o.Records {
		errs = append(errs, e.applyRecords(ctx, func() ([]match.Delta, error) { return m.ApplyOSV(ctx, recs) }, "OSV records"))
	}
	return errors.Join(errs...)
}

// applyRecords computes record deltas with apply and writes them, under matchMu.
func (e *Engine) applyRecords(ctx context.Context, apply func() ([]match.Delta, error), what string) error {
	e.matchMu.Lock()
	defer e.matchMu.Unlock()
	var errs []error
	ds, err := apply()
	if err != nil {
		errs = append(errs, fmt.Errorf("engine: apply %s: %w", what, err))
	}
	for _, d := range ds {
		errs = append(errs, e.applyDelta(ctx, d, model.TriggerNewAdvisory))
	}
	return errors.Join(errs...)
}

// OnCNARecords re-matches advisories whose cvelistV5 records changed, then queues the owners
// holding them, since their CNA severity may have changed.
func (e *Engine) OnCNARecords(ctx context.Context, ids []string) error {
	defer observe(metrics.RematchDuration.WithLabelValues("cna"), time.Now())
	var errs []error
	if e.o.CNA != nil {
		errs = append(errs, e.applyRecords(ctx, func() ([]match.Delta, error) { return e.o.CNA.ApplyCNA(ctx, ids) }, "CNA records"))
	}
	errs = append(errs, e.OnAdvisoriesEnriched(ctx, ids))
	return errors.Join(errs...)
}

// OnGrypeDB loads a new Grype DB and re-matches, one digest at a time, the live digests (those an
// owner runs or a suggestion holds) it can change:
//   - on a full update (the first DB, then weekly), every live digest with every matcher: the
//     safety net for anything an incremental path missed, OSV and upstream included;
//   - otherwise, with grype alone, the digests whose packages the diff changed plus those with OSV
//     matches grype has not ruled on yet (store.DigestsAwaitingGrype).
//
// A digest that fails is logged and left for the next DB; it never fails the update on its own. The
// update fails, before the build is recorded so the feed offers it again, only when it is cancelled
// or when grype failed on every digest that tests the DB: every live digest of a full update, and
// on an incremental one every digest the diff selected. Those have search keys, so grype read them
// before and their failing says the DB is at fault. A digest re-matched only because it awaits
// grype says nothing about the DB (grype may never have read its SBOM, and then it awaits grype at
// every update), so its failure is skipped. The build is recorded once the re-match is done, since
// it counts towards settling provisional findings, and every owner is then queued.
func (e *Engine) OnGrypeDB(ctx context.Context, u grypedb.Update) error {
	defer observe(metrics.RematchDuration.WithLabelValues("grypedb"), time.Now())
	if err := e.o.Grype.Load(u.Path, u.Built); err != nil {
		return fmt.Errorf("engine: load grype database: %w", err)
	}
	digests, tests, err := e.grypeTargets(ctx, u)
	if err != nil {
		return err
	}
	mode := matchGrype
	if u.Full {
		mode = matchPersist
	}
	var (
		failed, skipped, grypeFailed int
		lastErr                      error
	)
	for _, d := range digests {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("engine: grype re-match: %w", err)
		}
		r, err := e.matchImage(ctx, d, mode)
		if err != nil {
			failed++
			e.o.Log.Error(err, "re-matching an image with the new Grype DB failed; it waits for the next one", "digest", d)
		}
		switch {
		case !r.grypeFailed:
		case tests[d]:
			grypeFailed++
			lastErr = err
		default:
			skipped++
		}
	}
	if grypeFailed > 0 && grypeFailed == len(tests) {
		return fmt.Errorf("engine: grype re-match failed on all %d images: %w", grypeFailed, lastErr)
	}
	if failed > 0 {
		e.o.Log.Info("some images were not re-matched with the new Grype DB", "failed", failed,
			"awaitingGrypeSkipped", skipped, "images", len(digests))
	}
	if err := e.o.Store.RecordGrypeDBBuild(ctx, u.Built); err != nil {
		return fmt.Errorf("engine: record grype database build: %w", err)
	}
	return e.enqueueAll(ctx, model.TriggerNewAdvisory)
}

// grypeTargets returns the digests OnGrypeDB re-matches for u, and those of them that test the DB:
// all of them on a full update, and otherwise the live digests the diff selected (the others await
// grype: store.DigestsAwaitingGrype).
func (e *Engine) grypeTargets(ctx context.Context, u grypedb.Update) ([]string, map[string]bool, error) {
	live, err := e.o.Store.LiveDigests(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("engine: live digests: %w", err)
	}
	if u.Full {
		return live, setOf(live), nil
	}
	changed, err := e.o.Grype.Affected(ctx, u.Changed)
	if err != nil {
		return nil, nil, fmt.Errorf("engine: digests the grype database changed: %w", err)
	}
	waiting, err := e.o.Store.DigestsAwaitingGrype(ctx, u.Built)
	if err != nil {
		return nil, nil, fmt.Errorf("engine: digests awaiting grype: %w", err)
	}
	selected := slices.DeleteFunc(changed, func(d string) bool { _, ok := slices.BinarySearch(live, d); return !ok })
	tests := setOf(selected)
	out := append(slices.Clone(selected), waiting...)
	slices.Sort(out)
	return slices.Compact(out), tests, nil
}

func setOf(ss []string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

// MatchCandidate runs every matcher over a catalogued digest and returns the matches without
// storing them, with canonical advisory ids. An uncatalogued digest has no matches. While the
// grype feed is enabled but no DB is loaded it returns match.ErrNotReady: without grype's OS
// package matches every candidate would seem to fix everything the running image has. With the
// feed disabled grype contributes nothing, as for the running image. Any other matcher failure is
// an error.
func (e *Engine) MatchCandidate(ctx context.Context, digest string) ([]model.Match, error) {
	r, err := e.matchImage(ctx, digest, matchCandidate)
	if err != nil {
		return nil, err
	}
	if r.grypeNotReady && e.o.Config.Feeds.GrypeDB.Enabled {
		return nil, fmt.Errorf("engine: scoring %s: %w", digest, match.ErrNotReady)
	}
	return e.canonicalise(ctx, r.matches)
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
