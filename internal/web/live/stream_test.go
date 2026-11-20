package live_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	clocktesting "k8s.io/utils/clock/testing"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/web"
	"github.com/the-it-dept/ffs/internal/web/live"
	"github.com/the-it-dept/ffs/internal/web/webtest"
)

// coalesce is the hub's default coalescing window, which the tests step the fake clock by.
const coalesce = 2 * time.Second

// newHub is a hub on a fake clock at webtest.Now, started until the test ends, served over HTTP.
func newHub(t *testing.T, o live.Options) (*live.Hub, *clocktesting.FakeClock, *httptest.Server) {
	t.Helper()
	fc := clocktesting.NewFakeClock(webtest.Now)
	o.Clock, o.Now = fc, func() time.Time { return webtest.Now }
	hub := live.NewHub(o)
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan error, 1)
	go func() { started <- hub.Start(ctx) }()
	srv := httptest.NewServer(hub)
	t.Cleanup(func() {
		srv.CloseClientConnections()
		cancel()
		require.NoError(t, <-started)
		srv.Close()
	})
	return hub, fc, srv
}

// epoch is the id prefix of a hub created at webtest.Now.
var epoch = fmt.Sprintf("%x", webtest.Now.UnixNano())

func id(n int) string { return fmt.Sprintf("%s-%d", epoch, n) }

// connect opens a stream, with lastID as Last-Event-ID when it is not empty, and checks that it
// begins with the reconnect delay. It returns a reader of the stream and a function that closes it;
// the stream is closed when the test ends in any case.
func connect(t *testing.T, srv *httptest.Server, lastID string) (*bufio.Reader, func()) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/v1/stream", nil)
	require.NoError(t, err)
	if lastID != "" {
		req.Header.Set("Last-Event-ID", lastID)
	}
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	closeStream := func() { _ = resp.Body.Close() }
	t.Cleanup(closeStream)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))
	r := bufio.NewReader(resp.Body)
	require.Equal(t, []string{"retry: 3000"}, readBlock(t, r))
	return r, closeStream
}

// readBlock reads the lines of one block, up to the blank line that ends it; it fails after 2s.
func readBlock(t *testing.T, r *bufio.Reader) []string {
	t.Helper()
	type result struct {
		lines []string
		err   error
	}
	got := make(chan result, 1)
	go func() {
		var lines []string
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				got <- result{lines, err}
				return
			}
			line = strings.TrimSuffix(line, "\n")
			if line == "" {
				got <- result{lines, nil}
				return
			}
			lines = append(lines, line)
		}
	}()
	select {
	case res := <-got:
		require.NoError(t, res.err)
		return res.lines
	case <-time.After(2 * time.Second):
		require.FailNow(t, "no event within 2s")
		return nil
	}
}

// readEvent reads one event block: its id, event name and decoded data. It fails after 2s.
func readEvent(t *testing.T, r *bufio.Reader) (id, event string, data map[string]any) {
	t.Helper()
	for _, line := range readBlock(t, r) {
		k, v, _ := strings.Cut(line, ": ")
		switch k {
		case "id":
			id = v
		case "event":
			event = v
		case "data":
			require.NoError(t, json.Unmarshal([]byte(v), &data), line)
		}
	}
	require.Equal(t, "changed", event)
	return id, event, data
}

func strs(vs ...string) []any {
	out := make([]any, len(vs))
	for i, v := range vs {
		out[i] = v
	}
	return out
}

// publish publishes one change and lets the coalescing window pass, so it becomes one event.
func publish(hub *live.Hub, fc *clocktesting.FakeClock, kinds []live.Kind, scopes ...string) {
	hub.Publish(kinds, scopes)
	fc.Step(coalesce)
}

func TestStream_ForeignLastEventIDForcesFullRefresh(t *testing.T) {
	hub, fc, srv := newHub(t, live.Options{})

	// No Last-Event-ID: nothing is sent until something is published.
	quiet, _ := connect(t, srv, "")
	publish(hub, fc, []live.Kind{live.KindFeeds}, "*")
	gotID, _, data := readEvent(t, quiet)
	require.Equal(t, id(1), gotID)
	require.Equal(t, strs("feeds"), data["kinds"], "the first event is the published one, not a refresh")

	for range 299 {
		publish(hub, fc, []live.Kind{live.KindFindings}, "cluster")
	}
	for _, last := range []string{"deadbeef-3", "x", id(1)} {
		r, _ := connect(t, srv, last)
		gotID, _, data := readEvent(t, r)
		require.Equal(t, map[string]any{"seq": id(300), "kinds": strs("all"), "scopes": strs("*")}, data, last)
		require.Equal(t, data["seq"], gotID, last)
	}
}

func TestStream_ReplaysEventsAfterKnownID(t *testing.T) {
	hub, fc, srv := newHub(t, live.Options{})
	publish(hub, fc, []live.Kind{live.KindFindings}, "workload:Deployment/shop/web")
	publish(hub, fc, []live.Kind{live.KindImages}, "*")
	publish(hub, fc, []live.Kind{live.KindExceptions, live.KindFindings}, "*")

	fromFirst, _ := connect(t, srv, id(1))
	gotID, _, data := readEvent(t, fromFirst)
	require.Equal(t, id(2), gotID)
	require.Equal(t, map[string]any{"seq": id(2), "kinds": strs("images"), "scopes": strs("*")}, data)
	gotID, _, data = readEvent(t, fromFirst)
	require.Equal(t, id(3), gotID)
	require.Equal(t, map[string]any{"seq": id(3), "kinds": strs("exceptions", "findings"), "scopes": strs("*")}, data)

	fromLatest, _ := connect(t, srv, id(3))

	// The next event each stream reads is the fourth: nothing more was replayed, and no refresh.
	publish(hub, fc, []live.Kind{live.KindNodes}, "nodegroup:*")
	for _, r := range []*bufio.Reader{fromFirst, fromLatest} {
		gotID, _, data := readEvent(t, r)
		require.Equal(t, id(4), gotID)
		require.Equal(t, strs("nodes"), data["kinds"])
	}
}

func TestStream_HeartbeatAndCoalescing(t *testing.T) {
	hub, fc, srv := newHub(t, live.Options{})
	r, _ := connect(t, srv, "")

	hub.Publish([]live.Kind{live.KindFindings}, []string{"workload:a"})
	hub.Publish([]live.Kind{live.KindImages}, []string{"image:x"})
	fc.Step(coalesce)
	_, _, data := readEvent(t, r)
	require.Equal(t, map[string]any{"seq": id(1), "kinds": strs("findings", "images"), "scopes": strs("image:x", "workload:a")}, data)

	many := make([]string, 201)
	for i := range many {
		many[i] = fmt.Sprintf("workload:Deployment/shop/app-%03d", i)
	}
	hub.Publish([]live.Kind{live.KindInventory}, many)
	fc.Step(coalesce)
	gotID, _, data := readEvent(t, r)
	require.Equal(t, id(2), gotID, "the 201 scopes made exactly one event")
	require.Equal(t, strs("*"), data["scopes"])

	fc.Step(25 * time.Second)
	require.Equal(t, []string{": ping"}, readBlock(t, r))
}

func TestStream_TooManyStreams(t *testing.T) {
	hub, _, srv := newHub(t, live.Options{MaxStreams: 2})
	_, closeFirst := connect(t, srv, "")
	connect(t, srv, "")
	require.Equal(t, 2, hub.Streams())

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/api/v1/stream", nil)
	require.NoError(t, err)
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	require.Equal(t, "application/problem+json", resp.Header.Get("Content-Type"))
	var p map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&p))
	require.Equal(t, "too_many_streams", p["code"])
	require.InDelta(t, 503, p["status"], 0)
	require.Contains(t, p, "generatedAt")

	closeFirst()
	require.Eventually(t, func() bool { return hub.Streams() == 1 }, 2*time.Second, 10*time.Millisecond)
	connect(t, srv, "")
	require.Equal(t, 2, hub.Streams())
}

func TestStream_ShutdownEndsStreams(t *testing.T) {
	hub, _, srv := newHub(t, live.Options{})
	r, _ := connect(t, srv, "")
	hub.Close()
	read := make(chan error, 1)
	go func() {
		_, err := r.ReadString('\n')
		read <- err
	}()
	select {
	case err := <-read:
		require.ErrorIs(t, err, io.EOF)
	case <-time.After(time.Second):
		require.FailNow(t, "the stream did not end")
	}
	require.NotPanics(t, hub.Close, "Close twice is safe")

	// Behind the web server, shutting down ends the open streams through the shutdown hook.
	hub2 := live.NewHub(live.Options{Clock: clocktesting.NewFakeClock(webtest.Now), Now: func() time.Time { return webtest.Now }})
	cfg := config.Default()
	cfg.ClusterName = webtest.ClusterName
	ws := web.NewServer(cfg, web.Handlers{Stream: hub2}, hub2.Close)
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	served := make(chan error, 1)
	go func() { served <- ws.Server.Serve(ln) }()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+ln.Addr().String()+"/api/v1/stream", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, []string{"retry: 3000"}, readBlock(t, bufio.NewReader(resp.Body)))
	require.Equal(t, 1, hub2.Streams())

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	start := time.Now()
	require.NoError(t, ws.Server.Shutdown(ctx))
	require.Less(t, time.Since(start), 2*time.Second)
	require.True(t, errors.Is(<-served, http.ErrServerClosed))
}

// stuckWriter is a stream's response writer whose client stops reading once stuck is closed: from
// then on every write blocks until the write deadline the stream set, and fails then. Without a
// deadline it blocks for good.
type stuckWriter struct {
	header   http.Header
	stuck    chan struct{}
	mu       sync.Mutex
	deadline time.Time
	written  strings.Builder
}

func newStuckWriter() *stuckWriter {
	return &stuckWriter{header: http.Header{}, stuck: make(chan struct{})}
}

func (w *stuckWriter) Header() http.Header { return w.header }
func (w *stuckWriter) WriteHeader(int)     {}
func (w *stuckWriter) FlushError() error   { return nil }

func (w *stuckWriter) SetWriteDeadline(t time.Time) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.deadline = t
	return nil
}

func (w *stuckWriter) Write(p []byte) (int, error) {
	select {
	case <-w.stuck:
	default:
		w.mu.Lock()
		defer w.mu.Unlock()
		return w.written.Write(p)
	}
	w.mu.Lock()
	deadline := w.deadline
	w.mu.Unlock()
	if deadline.IsZero() {
		select {} // a client that never reads, and no deadline to give up on it
	}
	time.Sleep(time.Until(deadline))
	return 0, os.ErrDeadlineExceeded
}

// V55: every write to a stream has a deadline, so a client that stops reading releases its handler,
// and Close ends a stream blocked in a write.
func TestStream_StuckClientIsReleased(t *testing.T) {
	for _, closeHub := range []bool{false, true} {
		hub, fc, _ := newHub(t, live.Options{WriteTimeout: 50 * time.Millisecond})
		w := newStuckWriter()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/stream", nil)
		done := make(chan struct{})
		go func() {
			defer close(done)
			hub.ServeHTTP(w, req)
		}()
		require.Eventually(t, func() bool { return hub.Streams() == 1 }, 2*time.Second, 5*time.Millisecond)
		close(w.stuck)
		hub.Publish([]live.Kind{live.KindFindings}, []string{"cluster"})
		fc.Step(coalesce)
		if closeHub {
			hub.Close()
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			require.FailNow(t, "the stream stayed blocked on a client that stopped reading", "close=%t", closeHub)
		}
		require.Zero(t, hub.Streams())
	}
}
