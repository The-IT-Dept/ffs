package feeds_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/feeds"
	"github.com/the-it-dept/ffs/internal/store"
)

var (
	ctx = context.Background()
	t0  = time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
)

const ms = time.Millisecond

func newStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "ffs.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	return st
}

type fakeFeed struct {
	name                 string
	interval, staleAfter time.Duration
	sync                 func(ctx context.Context) error // nil succeeds
	calls                atomic.Int32
}

func (f *fakeFeed) Name() string              { return f.name }
func (f *fakeFeed) Interval() time.Duration   { return f.interval }
func (f *fakeFeed) StaleAfter() time.Duration { return f.staleAfter }

func (f *fakeFeed) Sync(ctx context.Context) error {
	f.calls.Add(1)
	if f.sync != nil {
		return f.sync(ctx)
	}
	return nil
}

// fakeTimer is an injected clock: After registers a waiter that fires once Advance reaches it,
// and every requested duration is reported on asked.
type fakeTimer struct {
	mu      sync.Mutex
	now     time.Time
	waiters []waiter
	asked   chan time.Duration
}

type waiter struct {
	at time.Time
	ch chan time.Time
}

func newFakeTimer() *fakeTimer { return &fakeTimer{now: t0, asked: make(chan time.Duration, 64)} }

func (c *fakeTimer) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeTimer) After(d time.Duration) <-chan time.Time {
	ch := make(chan time.Time, 1)
	c.mu.Lock()
	c.waiters = append(c.waiters, waiter{at: c.now.Add(d), ch: ch})
	c.mu.Unlock()
	c.asked <- d
	return ch
}

func (c *fakeTimer) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	kept := c.waiters[:0]
	for _, w := range c.waiters {
		if w.at.After(c.now) {
			kept = append(kept, w)
			continue
		}
		w.ch <- c.now
	}
	c.waiters = kept
}

// nextAsk returns the next duration the runner asked After for.
func (c *fakeTimer) nextAsk(t *testing.T) time.Duration {
	t.Helper()
	select {
	case d := <-c.asked:
		return d
	case <-time.After(10 * time.Second):
		t.Fatal("runner never asked After for a delay")
		return 0
	}
}

func startRunner(t *testing.T, r *feeds.Runner) {
	t.Helper()
	c, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- r.Run(c) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
	})
}

func TestRunner_SchedulesWithJitter(t *testing.T) {
	st := newStore(t)
	clk := newFakeTimer()
	f := &fakeFeed{name: "fake", interval: 100 * ms, staleAfter: time.Hour}
	r := feeds.NewRunner(st, []feeds.Feed{f}, feeds.RunnerOptions{Now: clk.Now, After: clk.After})
	startRunner(t, r)

	for run := int32(1); run <= 5; run++ {
		d := clk.nextAsk(t)
		require.Equal(t, run, f.calls.Load(), "one sync per scheduled delay")
		require.GreaterOrEqual(t, d, 90*ms)
		require.LessOrEqual(t, d, 110*ms)
		clk.Advance(d)
	}
	clk.nextAsk(t)
	require.Equal(t, int32(6), f.calls.Load())
}

func TestRunner_NeverConcurrent(t *testing.T) {
	st := newStore(t)
	release := make(chan struct{})
	started := make(chan struct{}, 16)
	var inflight, maxInflight atomic.Int32
	f := &fakeFeed{name: "fake", interval: 10 * ms, staleAfter: time.Hour, sync: func(ctx context.Context) error {
		n := inflight.Add(1)
		defer inflight.Add(-1)
		for {
			m := maxInflight.Load()
			if n <= m || maxInflight.CompareAndSwap(m, n) {
				break
			}
		}
		started <- struct{}{}
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}}
	firesAtOnce := func(time.Duration) <-chan time.Time {
		ch := make(chan time.Time, 1)
		ch <- time.Now()
		return ch
	}
	r := feeds.NewRunner(st, []feeds.Feed{f}, feeds.RunnerOptions{After: firesAtOnce})
	startRunner(t, r)

	for range 5 {
		select {
		case <-started:
		case <-time.After(10 * time.Second):
			t.Fatal("scheduled sync never started")
		}
		require.ErrorIs(t, r.SyncNow(ctx, "fake"), feeds.ErrRunning)
		release <- struct{}{}
	}
	require.Equal(t, int32(1), maxInflight.Load())
	require.ErrorIs(t, r.SyncNow(ctx, "nope"), feeds.ErrUnknownFeed)
}

func TestRunner_RecordsFeedState(t *testing.T) {
	st := newStore(t)
	clk := newFakeTimer()
	var fail atomic.Bool
	f := &fakeFeed{name: "fake", interval: time.Hour, staleAfter: 24 * time.Hour, sync: func(ctx context.Context) error {
		s, err := st.FeedState(ctx, "fake")
		require.NoError(t, err)
		s.Watermark, s.Meta = "w1", map[string]string{"k": "v"}
		require.NoError(t, st.PutFeedState(ctx, s))
		if fail.Load() {
			return errors.New("boom")
		}
		return nil
	}}
	r := feeds.NewRunner(st, []feeds.Feed{f}, feeds.RunnerOptions{Now: clk.Now})

	require.NoError(t, r.SyncNow(ctx, "fake"))
	s, err := st.FeedState(ctx, "fake")
	require.NoError(t, err)
	require.True(t, s.LastSuccess.Equal(t0), "LastSuccess %v", s.LastSuccess)
	require.True(t, s.LastAttempt.Equal(t0))
	require.Empty(t, s.LastError)
	require.Equal(t, "w1", s.Watermark)
	require.Equal(t, map[string]string{"k": "v"}, s.Meta)

	clk.Advance(time.Minute)
	fail.Store(true)
	require.EqualError(t, r.SyncNow(ctx, "fake"), "boom")
	s, err = st.FeedState(ctx, "fake")
	require.NoError(t, err)
	require.True(t, s.LastSuccess.Equal(t0), "LastSuccess unchanged by a failure")
	require.True(t, s.LastAttempt.Equal(t0.Add(time.Minute)))
	require.Equal(t, "boom", s.LastError)
	require.Equal(t, "w1", s.Watermark)
	require.Equal(t, map[string]string{"k": "v"}, s.Meta)
}

func TestRunner_StaleFiresOnce(t *testing.T) {
	st := newStore(t)
	clk := newFakeTimer()
	var fail atomic.Bool
	fail.Store(true)
	f := &fakeFeed{name: "fake", interval: time.Hour, staleAfter: 100 * ms, sync: func(context.Context) error {
		if fail.Load() {
			return errors.New("boom")
		}
		return nil
	}}
	type staleCall struct {
		feed        string
		lastSuccess time.Time
	}
	var calls []staleCall
	r := feeds.NewRunner(st, []feeds.Feed{f}, feeds.RunnerOptions{
		Now: clk.Now,
		OnStale: func(_ context.Context, feed string, lastSuccess time.Time) {
			calls = append(calls, staleCall{feed, lastSuccess})
		},
	})

	require.Empty(t, r.Stale())
	clk.Advance(150 * ms)
	require.Error(t, r.SyncNow(ctx, "fake"))
	require.Error(t, r.SyncNow(ctx, "fake"))
	require.Equal(t, []staleCall{{"fake", time.Time{}}}, calls)
	require.Equal(t, []string{"fake"}, r.Stale())

	fail.Store(false)
	require.NoError(t, r.SyncNow(ctx, "fake"))
	succeeded := clk.Now()
	require.Empty(t, r.Stale())

	clk.Advance(150 * ms)
	fail.Store(true)
	require.Error(t, r.SyncNow(ctx, "fake"))
	require.Len(t, calls, 2)
	require.Equal(t, "fake", calls[1].feed)
	require.True(t, calls[1].lastSuccess.Equal(succeeded))
}

func TestRunner_ResumesFromPersistedState(t *testing.T) {
	st := newStore(t)
	clk := newFakeTimer()
	require.NoError(t, st.PutFeedState(ctx, store.FeedState{Name: "fake", LastAttempt: t0.Add(-10 * time.Minute)}))
	f := &fakeFeed{name: "fake", interval: time.Hour, staleAfter: 48 * time.Hour}
	r := feeds.NewRunner(st, []feeds.Feed{f}, feeds.RunnerOptions{Now: clk.Now, After: clk.After})
	startRunner(t, r)

	d := clk.nextAsk(t)
	require.Equal(t, 50*time.Minute, d)
	require.Zero(t, f.calls.Load(), "no sync before the persisted schedule is due")

	clk.Advance(d)
	clk.nextAsk(t)
	require.Equal(t, int32(1), f.calls.Load())
}

func TestRunner_StaleAfterMap(t *testing.T) {
	a := &fakeFeed{name: "a", interval: time.Hour, staleAfter: 2 * time.Hour}
	b := &fakeFeed{name: "b", interval: time.Hour, staleAfter: 24 * time.Hour}
	r := feeds.NewRunner(newStore(t), []feeds.Feed{a, b}, feeds.RunnerOptions{})
	require.Equal(t, map[string]time.Duration{"a": 2 * time.Hour, "b": 24 * time.Hour}, r.StaleAfter())
}

// TestRunner_RestartRetriesFailedFeedOnBackoff (F68, #6): after a restart, a feed whose last
// attempt failed is retried on the failure backoff from that attempt, min(Interval,
// 1m×2^(fails−1)), not a whole Interval later; the failure count is stored and carries on. A failed
// attempt stored by v0.0.1, which kept no count, counts as one failure.
func TestRunner_RestartRetriesFailedFeedOnBackoff(t *testing.T) {
	for name, tc := range map[string]struct {
		stored    store.FeedState
		wantFirst time.Duration
		wantFails int
	}{
		"three failures": {store.FeedState{Name: "fake", LastAttempt: t0.Add(-30 * time.Second), LastError: "boom", Fails: 3},
			4*time.Minute - 30*time.Second, 4},
		"stored by v0.0.1": {store.FeedState{Name: "fake", LastAttempt: t0.Add(-30 * time.Second), LastError: "boom"},
			30 * time.Second, 2},
		"capped at the interval": {store.FeedState{Name: "fake", LastAttempt: t0.Add(-30 * time.Second), LastError: "boom", Fails: 12},
			24*time.Hour - 30*time.Second, 13},
	} {
		t.Run(name, func(t *testing.T) {
			st := newStore(t)
			clk := newFakeTimer()
			require.NoError(t, st.PutFeedState(ctx, tc.stored))
			f := &fakeFeed{name: "fake", interval: 24 * time.Hour, staleAfter: 72 * time.Hour,
				sync: func(context.Context) error { return errors.New("still down") }}
			r := feeds.NewRunner(st, []feeds.Feed{f}, feeds.RunnerOptions{Now: clk.Now, After: clk.After})
			startRunner(t, r)

			d := clk.nextAsk(t)
			require.Equal(t, tc.wantFirst, d)
			require.Zero(t, f.calls.Load())
			clk.Advance(d)
			next := clk.nextAsk(t)
			require.Equal(t, int32(1), f.calls.Load())
			require.Equal(t, min(24*time.Hour, time.Minute<<(tc.wantFails-1)), next, "the backoff carries on")
			s, err := st.FeedState(ctx, "fake")
			require.NoError(t, err)
			require.Equal(t, tc.wantFails, s.Fails)
		})
	}
}

// TestRunner_NeverSyncedStaleAcrossRestarts (F67): the first attempt of a feed that never succeeded
// is stored, and after a restart the feed is stale StaleAfter from it, not from the restart.
func TestRunner_NeverSyncedStaleAcrossRestarts(t *testing.T) {
	st := newStore(t)
	clk := newFakeTimer()
	f := &fakeFeed{name: "fake", interval: time.Hour, staleAfter: time.Hour,
		sync: func(context.Context) error { return errors.New("unreachable") }}
	require.Error(t, feeds.NewRunner(st, []feeds.Feed{f}, feeds.RunnerOptions{Now: clk.Now}).SyncNow(ctx, "fake"))
	s, err := st.FeedState(ctx, "fake")
	require.NoError(t, err)
	require.True(t, s.FirstAttempt.Equal(t0), "FirstAttempt %v", s.FirstAttempt)
	require.Equal(t, 1, s.Fails)

	clk.Advance(50 * time.Minute) // the controller restarts
	started := make(chan struct{}, 1)
	f.sync = func(ctx context.Context) error {
		started <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	}
	r := feeds.NewRunner(st, []feeds.Feed{f}, feeds.RunnerOptions{Now: clk.Now, After: clk.After})
	startRunner(t, r)
	select {
	case <-started: // the stored state is read before the retry starts
	case <-time.After(10 * time.Second):
		t.Fatal("the failed feed was not retried")
	}
	require.Empty(t, r.Stale())
	clk.Advance(11 * time.Minute)
	require.Equal(t, []string{"fake"}, r.Stale(), "an hour after the first attempt, though 11 minutes after the restart")
	s, err = st.FeedState(ctx, "fake")
	require.NoError(t, err)
	require.True(t, s.FirstAttempt.Equal(t0))
}

// TestRunner_SyncNowAdoptsStoredFirstAttempt (W53): a SyncNow before Run has read the stored state
// takes the stored first attempt, or a v0.0.1 state's last attempt, instead of its own start, and
// stores the latter as the first attempt.
func TestRunner_SyncNowAdoptsStoredFirstAttempt(t *testing.T) {
	for name, stored := range map[string]store.FeedState{
		"stored":  {Name: "fake", FirstAttempt: t0.Add(-2 * time.Hour), LastAttempt: t0.Add(-time.Hour), LastError: "boom", Fails: 2},
		"v0.0.1":  {Name: "fake", LastAttempt: t0.Add(-2 * time.Hour), LastError: "boom"},
		"unknown": {Name: "fake"},
	} {
		t.Run(name, func(t *testing.T) {
			st := newStore(t)
			require.NoError(t, st.PutFeedState(ctx, stored))
			clk := newFakeTimer()
			f := &fakeFeed{name: "fake", interval: time.Hour, staleAfter: time.Hour,
				sync: func(context.Context) error { return errors.New("unreachable") }}
			r := feeds.NewRunner(st, []feeds.Feed{f}, feeds.RunnerOptions{Now: clk.Now})
			require.Error(t, r.SyncNow(ctx, "fake"))
			s, err := st.FeedState(ctx, "fake")
			require.NoError(t, err)
			if name == "unknown" {
				require.Empty(t, r.Stale())
				require.True(t, s.FirstAttempt.Equal(t0), "FirstAttempt %v", s.FirstAttempt)
				return
			}
			require.Equal(t, []string{"fake"}, r.Stale(), "an hour past the stored first attempt")
			require.True(t, s.FirstAttempt.Equal(t0.Add(-2*time.Hour)), "FirstAttempt %v", s.FirstAttempt)
		})
	}
}

// TestRunner_SyncTimeout (W17): a Sync may take twice the feed's interval, and never less than an
// hour, the least a diff of two production Grype DB builds needs.
func TestRunner_SyncTimeout(t *testing.T) {
	for _, tc := range []struct{ interval, want time.Duration }{
		{0, time.Hour},
		{10 * time.Minute, time.Hour},
		{time.Hour, 2 * time.Hour},
		{24 * time.Hour, 48 * time.Hour},
	} {
		t.Run(tc.interval.String(), func(t *testing.T) {
			require.Equal(t, tc.want, feeds.SyncTimeout(tc.interval))
			var budget time.Duration
			f := &fakeFeed{name: "fake", interval: tc.interval, staleAfter: 48 * time.Hour,
				sync: func(c context.Context) error {
					dl, ok := c.Deadline()
					require.True(t, ok)
					budget = time.Until(dl)
					return nil
				}}
			require.NoError(t, feeds.NewRunner(newStore(t), []feeds.Feed{f}, feeds.RunnerOptions{}).SyncNow(ctx, "fake"))
			require.InDelta(t, tc.want.Seconds(), budget.Seconds(), time.Minute.Seconds())
		})
	}
}

// TestRunner_FirstAttemptWriteFailureIsNotTheSyncs (W53): a sync that succeeds is a success even
// when storing its first attempt beforehand failed; recording the outcome stores it.
func TestRunner_FirstAttemptWriteFailureIsNotTheSyncs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ffs.db")
	st, err := store.Open(ctx, path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	inj, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, inj.Close()) })
	// The first-attempt write is the only one without an attempt time.
	_, err = inj.ExecContext(ctx, `CREATE TRIGGER fail_first BEFORE INSERT ON feeds WHEN NEW.last_attempt IS NULL
		BEGIN SELECT RAISE(ABORT, 'injected first-attempt failure'); END`)
	require.NoError(t, err)

	clk := newFakeTimer()
	f := &fakeFeed{name: "fake", interval: time.Hour, staleAfter: time.Hour}
	require.NoError(t, feeds.NewRunner(st, []feeds.Feed{f}, feeds.RunnerOptions{Now: clk.Now}).SyncNow(ctx, "fake"))
	s, err := st.FeedState(ctx, "fake")
	require.NoError(t, err)
	require.True(t, s.LastSuccess.Equal(t0))
	require.True(t, s.FirstAttempt.Equal(t0), "FirstAttempt %v", s.FirstAttempt)
	require.Empty(t, s.LastError)
}

// TestRunner_CancelledSyncNotRecorded (F54): a sync cut short by shutdown is not a failure: the
// stored attempt, error and failure count stay as they were.
func TestRunner_CancelledSyncNotRecorded(t *testing.T) {
	st := newStore(t)
	clk := newFakeTimer()
	ok := atomic.Bool{}
	ok.Store(true)
	started := make(chan struct{}, 1)
	f := &fakeFeed{name: "fake", interval: time.Hour, staleAfter: 24 * time.Hour, sync: func(ctx context.Context) error {
		if ok.Load() {
			return nil
		}
		started <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	}}
	r := feeds.NewRunner(st, []feeds.Feed{f}, feeds.RunnerOptions{Now: clk.Now})
	require.NoError(t, r.SyncNow(ctx, "fake"))
	before, err := st.FeedState(ctx, "fake")
	require.NoError(t, err)

	ok.Store(false)
	clk.Advance(time.Minute)
	c, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- r.SyncNow(c, "fake") }()
	<-started
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
	after, err := st.FeedState(ctx, "fake")
	require.NoError(t, err)
	require.Equal(t, before, after)
	require.Empty(t, after.LastError)
	require.Zero(t, after.Fails)
}
