package live_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/store"
	"github.com/the-it-dept/ffs/internal/web/live"
	"github.com/the-it-dept/ffs/internal/web/webtest"
)

func TestHub_ObserverScopes(t *testing.T) {
	f := webtest.Open(t)
	hub, fc, srv := newHub(t, live.Options{Store: f.Store})
	r, _ := connect(t, srv, "")

	hub.OwnersRecomputed(t.Context(), []string{webtest.Web.Key(), webtest.Cluster.Key(), "Nodes//test"})
	fc.Step(coalesce)
	_, _, data := readEvent(t, r)
	require.Equal(t, strs("findings", "inventory"), data["kinds"])
	scopes := data["scopes"].([]any)
	for _, want := range []string{"cluster", "workload:Deployment/shop/web", "namespace:shop", "image:" + webtest.DigestWeb,
		"image:" + webtest.DigestProxy, "controlplane", "nodegroup:*", "node:*"} {
		require.Contains(t, scopes, want)
	}
	for _, s := range scopes {
		require.NotContains(t, s, "image:k8s:", "synthetic digests are not image scopes")
		require.NotContains(t, s, "image:nodegroup:")
	}

	hub.MatchesReplaced(t.Context(), []string{"nodegroup:g1", "sha256:x"})
	fc.Step(coalesce)
	_, _, data = readEvent(t, r)
	require.Equal(t, strs("findings"), data["kinds"])
	require.Equal(t, strs("cluster", "image:sha256:x", "node:*", "nodegroup:*"), data["scopes"],
		"node groups are queried by their stable names, which the digest does not carry")
}

// fakeMarks returns the next marks of a script on each call: an error entry fails that call.
type fakeMarks struct {
	mu     sync.Mutex
	calls  int
	script []any // store.ChangeMarks or error
}

func (m *fakeMarks) ChangeMarks(context.Context) (store.ChangeMarks, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	next := m.script[min(m.calls, len(m.script)-1)]
	m.calls++
	if err, ok := next.(error); ok {
		return store.ChangeMarks{}, err
	}
	return next.(store.ChangeMarks), nil
}

func (m *fakeMarks) Calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

func TestHub_PollerPublishesMarkChanges(t *testing.T) {
	base := store.ChangeMarks{Images: "i1", Feeds: "f1", Exceptions: "e1", Suggestions: "s1", Nodes: "n1"}
	feeds, exceptions, images := base, base, base
	feeds.Feeds = "f2"
	exceptions.Feeds, exceptions.Exceptions = "f2", "e2"
	images.Feeds, images.Exceptions, images.Images = "f2", "e2", "i2"
	marks := &fakeMarks{script: []any{base, feeds, exceptions, exceptions, errors.New("database is locked"), exceptions, images}}
	var (
		nodeMu   sync.Mutex
		nodeMark = "a"
		logged   []string
		logMu    sync.Mutex
	)
	nodes := func(context.Context) (string, error) {
		nodeMu.Lock()
		defer nodeMu.Unlock()
		return nodeMark, nil
	}
	log := funcr.New(func(prefix, args string) {
		logMu.Lock()
		defer logMu.Unlock()
		logged = append(logged, args)
	}, funcr.Options{})
	// A coalescing window shorter than the poll interval keeps each poll's change in its own event.
	const poll, window = 2 * time.Second, time.Second
	_, fc, srv := newHub(t, live.Options{Marks: marks, Nodes: nodes, Poll: poll, Coalesce: window, Log: log})
	r, _ := connect(t, srv, "")
	// the poller's ticker and the stream's heartbeat
	require.Eventually(t, func() bool { return fc.Waiters() == 2 }, 2*time.Second, time.Millisecond)

	calls := func(n int) {
		t.Helper()
		require.Eventually(t, func() bool { return marks.Calls() == n }, 2*time.Second, time.Millisecond)
	}
	armed := func() {
		t.Helper()
		require.Eventually(t, func() bool { return fc.Waiters() == 3 }, 2*time.Second, time.Millisecond, "a flush is armed")
	}

	fc.Step(poll) // t=2s: the first poll sets the baseline
	calls(1)
	fc.Step(poll) // t=4s: feeds changed
	calls(2)
	armed()
	fc.Step(window) // t=5s: the flush
	_, _, data := readEvent(t, r)
	require.Equal(t, strs("feeds"), data["kinds"], "the first poll set the baseline and published nothing")
	require.Equal(t, strs("*"), data["scopes"])

	fc.Step(window) // t=6s: exceptions changed
	calls(3)
	armed()
	fc.Step(window)
	_, _, data = readEvent(t, r)
	require.Equal(t, strs("exceptions", "findings"), data["kinds"])

	nodeMu.Lock()
	nodeMark = "b"
	nodeMu.Unlock()
	fc.Step(window) // t=8s: only the node mark changed
	calls(4)
	armed()
	fc.Step(window)
	_, _, data = readEvent(t, r)
	require.Equal(t, strs("nodes"), data["kinds"])

	fc.Step(window) // t=10s: an error, logged, and no event
	calls(5)
	fc.Step(poll) // t=12s: the last good marks again, so no event
	calls(6)
	fc.Step(poll) // t=14s: images changed against the last good marks
	calls(7)
	armed()
	fc.Step(window)
	_, _, data = readEvent(t, r)
	require.Equal(t, strs("images"), data["kinds"], "neither the failed poll nor the one after it published")
	logMu.Lock()
	defer logMu.Unlock()
	require.Len(t, logged, 1)
	require.Contains(t, logged[0], "database is locked")
}

func TestStoreNodeMarks_IgnoresHeartbeats(t *testing.T) {
	f := webtest.Open(t)
	ctx := t.Context()
	marks := live.StoreNodeMarks(f.Store)
	before, err := marks(ctx)
	require.NoError(t, err)
	require.Len(t, before, 16)

	applied, err := f.Store.AcceptAgentReport(ctx, store.AgentReport{Node: "worker-1", AgentVersion: "v0.1.0", BootID: "boot-worker-1",
		StartedAt: webtest.Now.Add(-6 * time.Minute), Seq: 2, At: webtest.Now.Add(time.Minute)})
	require.NoError(t, err)
	require.True(t, applied)
	after, err := marks(ctx)
	require.NoError(t, err)
	require.Equal(t, before, after, "a heartbeat changes no mark")

	require.NoError(t, f.Store.ApplyNodeGrouping(ctx, store.NodeGrouping{
		Members: map[string]string{"worker-1": webtest.AgentGroupID, "worker-2": webtest.CP1GroupID, "cp-1": webtest.CP1GroupID},
		Exposed: map[string][]string{webtest.AgentGroupID: {"worker-1"}}, Now: webtest.Now,
	}))
	moved, err := marks(ctx)
	require.NoError(t, err)
	require.NotEqual(t, before, moved, "moving worker-2 changes the mark")
}
