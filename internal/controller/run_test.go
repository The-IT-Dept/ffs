package controller

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	kerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/the-it-dept/ffs/internal/controller/deps"
)

// fakeStore records Close.
type fakeStore struct {
	closed bool
	err    error
}

func (f *fakeStore) Close() error {
	f.closed = true
	return f.err
}

type startFunc func(ctx context.Context) error

func (f startFunc) Start(ctx context.Context) error { return f(ctx) }

// TestRunManager_ClosesTheStoreOnlyOnceRunnablesStopped: the store closes after Start returns, unless Start gave up
// waiting for the runnables, which may still be using it (F117). Only that error leaves it open: a runnable's own
// timeout, which also wraps context.DeadlineExceeded, comes once every runnable has returned (W58).
func TestRunManager_ClosesTheStoreOnlyOnceRunnablesStopped(t *testing.T) {
	timedOut := fmt.Errorf("failed waiting for all runnables to end within grace period of 30s: %w", context.DeadlineExceeded)
	for _, c := range []struct {
		name     string
		start    error
		closeErr error
		closed   bool
		want     []string
	}{
		{"clean stop", nil, nil, true, nil},
		{"a runnable failed", errors.New("engine: boom"), nil, true, []string{"engine: boom"}},
		{"a runnable timed out", fmt.Errorf("failed to start caches: %w", context.DeadlineExceeded), nil, true,
			[]string{"failed to start caches"}},
		{"close fails", nil, errors.New("disk gone"), true, []string{"close store: disk gone"}},
		{"grace period exceeded", timedOut, nil, false, []string{"within grace period"}},
		{"a runnable failed, then the grace period", kerrors.NewAggregate([]error{errors.New("engine: boom"), timedOut}), nil,
			false, []string{"engine: boom", "within grace period"}},
	} {
		st := &fakeStore{err: c.closeErr}
		err := runManager(t.Context(), startFunc(func(context.Context) error { return c.start }), st, logr.Discard())
		require.Equal(t, c.closed, st.closed, c.name)
		if c.want == nil {
			require.NoError(t, err, c.name)
			continue
		}
		for _, w := range c.want {
			require.ErrorContains(t, err, w, c.name)
		}
	}
}

// TestRunManager_RealManagerTimeout pins what runManager relies on: a controller-runtime manager whose runnable
// outlasts the graceful shutdown timeout returns an error that wraps context.DeadlineExceeded, and returns cleanly
// once its runnables stop in time.
func TestRunManager_RealManagerTimeout(t *testing.T) {
	needEnv(t)
	newManager := func(run func(ctx context.Context) error) manager.Manager {
		t.Helper()
		m, err := manager.New(env.Config, manager.Options{
			Metrics: metricsserver.Options{BindAddress: "0"}, HealthProbeBindAddress: "0",
			GracefulShutdownTimeout: ptr.To(200 * time.Millisecond),
		})
		require.NoError(t, err)
		require.NoError(t, m.Add(manager.RunnableFunc(run)))
		return m
	}
	// stopOnceStarted runs m, cancels it once its runnable has started, and returns runManager's result.
	stopOnceStarted := func(m manager.Manager, started <-chan struct{}, st *fakeStore) error {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		go func() {
			<-started
			cancel()
		}()
		return runManager(ctx, m, st, logr.Discard())
	}

	release := make(chan struct{})
	defer close(release)
	stuckStarted := make(chan struct{})
	stuck := newManager(func(context.Context) error {
		close(stuckStarted)
		<-release
		return nil
	})
	st := &fakeStore{}
	err := stopOnceStarted(stuck, stuckStarted, st)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.ErrorContains(t, err, shutdownTimedOutMsg, "the message shutdownTimedOut looks for")
	require.False(t, st.closed, "a runnable may still use the store")

	promptStarted := make(chan struct{})
	prompt := newManager(func(ctx context.Context) error {
		close(promptStarted)
		<-ctx.Done()
		return nil
	})
	st = &fakeStore{}
	require.NoError(t, stopOnceStarted(prompt, promptStarted, st))
	require.True(t, st.closed)
}

// TestRegister_NamesThePackage: a Registrar's error says which output package failed, and stops the rest (F55).
func TestRegister_NamesThePackage(t *testing.T) {
	boom := errors.New("index field: conflict")
	var ran []string
	rs := []registrar{
		{"crds", func(manager.Manager, deps.Deps) error { ran = append(ran, "crds"); return nil }},
		{"notify", func(manager.Manager, deps.Deps) error { ran = append(ran, "notify"); return boom }},
		{"web", func(manager.Manager, deps.Deps) error { ran = append(ran, "web"); return nil }},
	}
	err := register(nil, deps.Deps{}, rs)
	require.ErrorIs(t, err, boom)
	require.EqualError(t, err, "register notify: index field: conflict")
	require.Equal(t, []string{"crds", "notify"}, ran)

	names := map[string]bool{}
	for _, r := range registrars {
		require.NotEmpty(t, r.name)
		require.NotNil(t, r.add, r.name)
		require.False(t, names[r.name], "%s is listed twice", r.name)
		names[r.name] = true
	}
}
