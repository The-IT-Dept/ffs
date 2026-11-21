package feeds

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"sync"
	"time"

	"github.com/go-logr/logr"

	"github.com/the-it-dept/ffs/internal/store"
)

var (
	// ErrRunning means the feed is already syncing.
	ErrRunning = errors.New("feeds: sync already running")
	// ErrUnknownFeed means no registered feed has the given name.
	ErrUnknownFeed = errors.New("feeds: unknown feed")
)

const (
	staleCheckInterval = time.Minute
	minSyncTimeout     = 30 * time.Minute
	firstRetryDelay    = time.Minute
	maxBackoffShift    = 20 // caps 1m×2^n well below Duration overflow; Interval is the real ceiling
	jitterFraction     = 0.1
)

// RunnerOptions configures a Runner.
type RunnerOptions struct {
	OnStale func(ctx context.Context, feed string, lastSuccess time.Time) // once per entry into stale
	Now     func() time.Time                                              // nil = time.Now
	After   func(d time.Duration) <-chan time.Time                        // nil = time.After; tests inject a fake timer and drive time through Now and After
}

// Runner syncs each feed on its own schedule, never concurrently with itself, records the outcome
// in the feed's store.FeedState and reports feeds whose last success is older than StaleAfter. A
// feed that never succeeded is measured from its first attempt, which is stored, so restarts do not
// reset it. A sync cancelled by shutdown is not an attempt: nothing about it is recorded.
type Runner struct {
	st      *store.Store
	feeds   []*feedRun // registration order
	byName  map[string]*feedRun
	onStale func(ctx context.Context, feed string, lastSuccess time.Time)
	now     func() time.Time
	after   func(d time.Duration) <-chan time.Time
	started time.Time // a feed that never succeeded is measured from here, or its earlier first attempt

	mu sync.Mutex // guards the feedRun fields below running
}

type feedRun struct {
	feed    Feed
	running sync.Mutex // held for the whole of a Sync; taken with TryLock

	lastSuccess  time.Time
	firstAttempt time.Time // the stored first attempt (store.FeedState.EarliestAttempt), or when this Runner first started a sync
	fails        int       // consecutive failures, FeedState.Fails
	notified     bool      // OnStale fired since the last success
}

// NewRunner returns a Runner for fs. Feed names must be unique.
func NewRunner(st *store.Store, fs []Feed, o RunnerOptions) *Runner {
	r := &Runner{st: st, byName: make(map[string]*feedRun, len(fs)), onStale: o.OnStale, now: o.Now, after: o.After}
	if r.now == nil {
		r.now = time.Now
	}
	if r.after == nil {
		r.after = time.After
	}
	for _, f := range fs {
		fr := &feedRun{feed: f}
		r.feeds = append(r.feeds, fr)
		r.byName[f.Name()] = fr
	}
	r.started = r.now()
	return r
}

// Run syncs every feed on its schedule and checks staleness every minute. It blocks until ctx is
// done, waits for in-flight syncs to return and then returns nil. Each feed's first sync follows its
// stored state: right away when it never ran, on the failure backoff after its last attempt when
// that failed (see nextDelay), and otherwise an Interval after its last attempt.
func (r *Runner) Run(ctx context.Context) error {
	log := logr.FromContextOrDiscard(ctx).WithName("feeds")
	var wg sync.WaitGroup
	for _, fr := range r.feeds {
		st, err := r.st.FeedState(ctx, fr.feed.Name())
		if err != nil {
			log.Error(err, "reading feed state; syncing now", "feed", fr.feed.Name())
			st = store.FeedState{}
		}
		r.mu.Lock()
		if st.LastSuccess.After(fr.lastSuccess) {
			fr.lastSuccess = st.LastSuccess
		}
		if fr.firstAttempt.IsZero() {
			fr.firstAttempt = st.EarliestAttempt()
		}
		if fr.fails == 0 {
			fr.fails = failsOf(st)
		}
		fails := fr.fails
		r.mu.Unlock()
		var first time.Duration
		if !st.LastAttempt.IsZero() {
			wait := fr.feed.Interval()
			if fails > 0 {
				wait = backoff(wait, fails)
			}
			first = max(st.LastAttempt.Add(wait).Sub(r.now()), 0)
		}
		wg.Go(func() { r.loop(ctx, fr, first) })
	}

	ticker := time.NewTicker(staleCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return nil
		case <-ticker.C:
			for _, fr := range r.feeds {
				r.checkStale(ctx, fr)
			}
		}
	}
}

// loop runs fr's scheduled syncs, the first after delay.
func (r *Runner) loop(ctx context.Context, fr *feedRun, delay time.Duration) {
	log := logr.FromContextOrDiscard(ctx).WithName("feeds").WithValues("feed", fr.feed.Name())
	for {
		if delay > 0 {
			select {
			case <-ctx.Done():
				return
			case <-r.after(delay):
			}
		}
		if ctx.Err() != nil {
			return
		}
		if err := r.syncFeed(ctx, fr); err != nil && !errors.Is(err, ErrRunning) && ctx.Err() == nil {
			log.Error(err, "feed sync failed")
		}
		delay = r.nextDelay(fr)
	}
}

// nextDelay is Interval±10% after a success and the failure backoff after failures.
func (r *Runner) nextDelay(fr *feedRun) time.Duration {
	r.mu.Lock()
	fails := fr.fails
	r.mu.Unlock()
	iv := fr.feed.Interval()
	if fails == 0 {
		return time.Duration(float64(iv) * (1 - jitterFraction + 2*jitterFraction*rand.Float64())) //nolint:gosec // G404: scheduling jitter needs no cryptographic randomness
	}
	return backoff(iv, fails)
}

// backoff is the wait after fails consecutive failures of a feed synced every iv:
// min(iv, 1m×2^(fails−1)).
func backoff(iv time.Duration, fails int) time.Duration {
	return min(iv, firstRetryDelay<<min(fails-1, maxBackoffShift))
}

// failsOf returns st's count of consecutive failures; a failed last attempt recorded by a version
// that did not count them is one.
func failsOf(st store.FeedState) int {
	if st.Fails == 0 && st.LastError != "" {
		return 1
	}
	return st.Fails
}

// SyncNow runs the named feed's Sync immediately. It returns ErrUnknownFeed for an unregistered
// name and ErrRunning when that feed is already syncing.
func (r *Runner) SyncNow(ctx context.Context, name string) error {
	fr, ok := r.byName[name]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownFeed, name)
	}
	return r.syncFeed(ctx, fr)
}

// syncFeed runs one Sync of fr unless one is already running, records its outcome and then
// evaluates staleness. A Sync that fails because ctx ended (shutdown) is not recorded at all: it is
// neither a failure nor an attempt, so the next start schedules from the attempt before it. Failing
// to store the first attempt beforehand is logged, not returned: record stores it with the outcome.
func (r *Runner) syncFeed(ctx context.Context, fr *feedRun) error {
	name := fr.feed.Name()
	if !fr.running.TryLock() {
		return fmt.Errorf("%w: %s", ErrRunning, name)
	}
	defer fr.running.Unlock()

	if err := r.markFirstAttempt(ctx, fr); err != nil {
		logr.FromContextOrDiscard(ctx).WithName("feeds").Error(err, "could not store the feed's first attempt ahead of its sync; it is stored with the outcome",
			"feed", name)
	}
	err := callSync(ctx, fr.feed)
	if err != nil && ctx.Err() != nil {
		return err
	}
	at := r.now()
	r.mu.Lock()
	if err == nil {
		fr.lastSuccess, fr.fails, fr.notified = at, 0, false
	} else {
		fr.fails++
	}
	outcome := attempt{at: at, err: err, fails: fr.fails, first: fr.firstAttempt}
	r.mu.Unlock()
	if recErr := r.record(context.WithoutCancel(ctx), name, outcome); recErr != nil {
		err = errors.Join(err, recErr)
	}
	r.checkStale(ctx, fr)
	return err
}

// markFirstAttempt notes now as fr's first attempt when it never succeeded and has none, and stores
// it before the Sync runs, so a restart during a long first sync still measures staleness from it.
// An earlier first attempt already stored (a SyncNow before Run has read the state) is adopted
// instead.
func (r *Runner) markFirstAttempt(ctx context.Context, fr *feedRun) error {
	now := r.now()
	r.mu.Lock()
	first := fr.lastSuccess.IsZero() && fr.firstAttempt.IsZero()
	if first {
		fr.firstAttempt = now
	}
	r.mu.Unlock()
	if !first {
		return nil
	}
	name := fr.feed.Name()
	st, err := r.st.FeedState(ctx, name)
	if err != nil {
		return fmt.Errorf("feeds: record the first attempt of %s: %w", name, err)
	}
	if stored := st.EarliestAttempt(); !stored.IsZero() && stored.Before(now) {
		r.mu.Lock()
		if stored.Before(fr.firstAttempt) {
			fr.firstAttempt = stored
		}
		r.mu.Unlock()
		now = stored
	}
	if !st.FirstAttempt.IsZero() {
		return nil
	}
	st.FirstAttempt = now
	if err := r.st.PutFeedState(ctx, st); err != nil {
		return fmt.Errorf("feeds: record the first attempt of %s: %w", name, err)
	}
	return nil
}

// callSync runs f.Sync under the sync timeout, turning a panic into an error.
func callSync(ctx context.Context, f Feed) (err error) {
	ctx, cancel := context.WithTimeout(ctx, max(2*f.Interval(), minSyncTimeout))
	defer cancel()
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("feeds: %s sync panicked: %v", f.Name(), p)
		}
	}()
	return f.Sync(ctx)
}

// attempt is the outcome of one sync, as record stores it.
type attempt struct {
	at    time.Time
	err   error
	fails int       // consecutive failures, counting this one
	first time.Time // the feed's first attempt
}

// record re-reads the feed's state, so the Watermark and Meta its Sync wrote are kept, and stores
// the attempt outcome on top of it.
func (r *Runner) record(ctx context.Context, name string, a attempt) error {
	st, err := r.st.FeedState(ctx, name)
	if err != nil {
		return fmt.Errorf("feeds: record %s: %w", name, err)
	}
	st.LastAttempt = a.at
	st.LastError = ""
	st.Fails = a.fails
	if st.FirstAttempt.IsZero() {
		st.FirstAttempt = a.first
	}
	if a.err == nil {
		st.LastSuccess = a.at
	} else {
		st.LastError = a.err.Error()
	}
	if err := r.st.PutFeedState(ctx, st); err != nil {
		return fmt.Errorf("feeds: record %s: %w", name, err)
	}
	return nil
}

// checkStale calls OnStale when fr has just become stale.
func (r *Runner) checkStale(ctx context.Context, fr *feedRun) {
	now := r.now()
	r.mu.Lock()
	fire := r.staleLocked(fr, now) && !fr.notified
	if fire {
		fr.notified = true
	}
	last := fr.lastSuccess
	r.mu.Unlock()
	if fire && r.onStale != nil {
		r.onStale(ctx, fr.feed.Name(), last)
	}
}

// staleLocked reports whether fr's last success is more than StaleAfter before now. A feed that
// never succeeded is measured from its first attempt, stored across restarts, or from the Runner
// start when that is earlier (store.FeedState.StaleFrom). A feed without a positive StaleAfter is
// never stale.
func (r *Runner) staleLocked(fr *feedRun, now time.Time) bool {
	limit := fr.feed.StaleAfter()
	if limit <= 0 {
		return false
	}
	ref := store.FeedState{LastSuccess: fr.lastSuccess, FirstAttempt: fr.firstAttempt}.StaleFrom(r.started)
	return now.Sub(ref) > limit
}

// Stale returns the sorted names of the feeds that are past their StaleAfter.
func (r *Runner) Stale() []string {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, fr := range r.feeds {
		if r.staleLocked(fr, now) {
			out = append(out, fr.feed.Name())
		}
	}
	slices.Sort(out)
	return out
}

// StaleAfter returns each registered feed's staleness threshold keyed by Feed.Name(). It is the
// single source of per-feed thresholds for wiring, notifications, metrics and the API.
func (r *Runner) StaleAfter() map[string]time.Duration {
	m := make(map[string]time.Duration, len(r.feeds))
	for _, fr := range r.feeds {
		m[fr.feed.Name()] = fr.feed.StaleAfter()
	}
	return m
}
