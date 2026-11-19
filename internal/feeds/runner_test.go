package feeds_test

import (
	"context"
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
