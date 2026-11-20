package agent

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/agentapi/wire"
	"github.com/the-it-dept/ffs/internal/sbom"
)

// logEntry is one log call.
type logEntry struct {
	err bool
	msg string
	kv  []any
}

// recordingSink is a logr sink that keeps every entry.
type recordingSink struct {
	mu      sync.Mutex
	entries []logEntry
}

func (s *recordingSink) Init(logr.RuntimeInfo)          {}
func (s *recordingSink) Enabled(int) bool               { return true }
func (s *recordingSink) WithName(string) logr.LogSink   { return s }
func (s *recordingSink) WithValues(...any) logr.LogSink { return s }

func (s *recordingSink) Info(_ int, msg string, kv ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, logEntry{msg: msg, kv: kv})
}

func (s *recordingSink) Error(_ error, msg string, kv ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, logEntry{err: true, msg: msg, kv: kv})
}

func (s *recordingSink) all() []logEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.entries)
}

// errors returns the messages logged as errors.
func (s *recordingSink) errors() []string {
	var out []string
	for _, e := range s.all() {
		if e.err {
			out = append(out, e.msg)
		}
	}
	return out
}

// withRecorder makes the env's agent log to a recording sink.
func (e *env) withRecorder() *recordingSink {
	rec := &recordingSink{}
	e.opts.Log = logr.New(rec)
	return rec
}

// countingHost makes the cataloguer answer each host-dir job with a distinct document and counts them.
func countingHost(e *env) *atomic.Int32 {
	var n atomic.Int32
	e.runner.setFn(func(_ context.Context, req sbom.CatalogRequest) (*sbom.CatalogResponse, error) {
		if req.Source == sbom.CatalogSourceHostDir {
			i := n.Add(1)
			return &sbom.CatalogResponse{SyftJSON: json.RawMessage(fmt.Sprintf(`{"artifacts":[],"source":{"id":"host-%d"}}`, i))}, nil
		}
		return &sbom.CatalogResponse{SyftJSON: json.RawMessage(imageJSON)}, nil
	})
	return &n
}

// spooled lists the spooled SBOM files in the scratch dir.
func spooled(t *testing.T, scratch string) []string {
	t.Helper()
	entries, err := os.ReadDir(scratch)
	require.NoError(t, err)
	var out []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "sbom-") {
			out = append(out, e.Name())
		}
	}
	return out
}

// nextFull returns the next full report the controller received.
func (c *fakeController) nextFull(t *testing.T) wire.Report {
	t.Helper()
	for {
		if r := c.next(t); r.Kind == wire.KindFull {
			return r
		}
	}
}

// answerFull answers full reports with f and images reports with an applied response.
func answerFull(f func(r wire.Report) (int, wire.ReportResponse)) func(r wire.Report) (int, wire.ReportResponse) {
	return func(r wire.Report) (int, wire.ReportResponse) {
		if r.Kind == wire.KindFull {
			return f(r)
		}
		return http.StatusOK, wire.ReportResponse{Applied: true, Config: testConfig()}
	}
}

func testConfig() wire.AgentConfig {
	return wire.AgentConfig{ReportIntervalSeconds: 3600, ImageListIntervalSeconds: 1, MaxReportBytes: 32 << 20}
}

func TestRun_FullRetryReusesHostInventory(t *testing.T) {
	e := newEnv(t)
	hosts := countingHost(e)
	var fulls atomic.Int32
	e.ctl.setAnswer(answerFull(func(wire.Report) (int, wire.ReportResponse) {
		if fulls.Add(1) == 1 {
			return http.StatusInternalServerError, wire.ReportResponse{}
		}
		return http.StatusOK, wire.ReportResponse{Applied: true, Config: testConfig()}
	}))
	e.startCataloguer(t)
	e.run(t)

	first := e.ctl.nextFull(t)
	require.NotNil(t, first.Host)
	second := e.ctl.nextFull(t)
	require.NotNil(t, second.Host)
	require.Greater(t, second.Seq, first.Seq)
	require.JSONEq(t, string(first.Host.SyftJSON), string(second.Host.SyftJSON), "the retry resends the inventory it collected")
	require.Equal(t, first.Host.Binaries, second.Host.Binaries)
	require.Equal(t, int32(1), hosts.Load(), "the host is staged and catalogued once")
	require.Eventually(t, func() bool { return len(spooled(t, e.scratch)) == 0 }, waitFor, 5*time.Millisecond,
		"the spooled host SBOM is removed once the controller stored it")
}

func TestRun_ImagesSuccessDoesNotResetFullBackoff(t *testing.T) {
	e := newEnv(t)
	backoffBase = 40 * time.Millisecond // fastTimers restores it
	hosts := countingHost(e)
	e.ctl.setAnswer(answerFull(func(wire.Report) (int, wire.ReportResponse) {
		return http.StatusInternalServerError, wire.ReportResponse{}
	}))
	e.startCataloguer(t)
	e.run(t)

	var fulls []time.Time
	require.Eventually(t, func() bool {
		events, times := e.ctl.log()
		fulls = fulls[:0]
		images := 0
		for i, ev := range events {
			switch ev {
			case wire.KindFull:
				fulls = append(fulls, times[i])
			case wire.KindImages:
				images++
			}
		}
		return len(fulls) >= 5 && images >= 3
	}, waitFor, 5*time.Millisecond)
	// With no jitter the full backoff is 32, 64, 128 and 256ms. Had the images reports in between reset it, the
	// gaps would stay near 32ms.
	require.GreaterOrEqual(t, fulls[4].Sub(fulls[3]), 200*time.Millisecond, "the full backoff kept growing: %v", fulls)
	require.Equal(t, int32(1), hosts.Load(), "the failing full reports reuse one host inventory")
}

func TestRun_HonoursRetryAfter(t *testing.T) {
	e := newEnv(t)
	hosts := countingHost(e)
	var fulls atomic.Int32
	e.ctl.setAnswer(answerFull(func(wire.Report) (int, wire.ReportResponse) {
		if fulls.Add(1) == 1 {
			return http.StatusTooManyRequests, wire.ReportResponse{}
		}
		return http.StatusOK, wire.ReportResponse{Applied: true, Config: testConfig()}
	}))
	e.ctl.setHeaders(func(r wire.Report) http.Header {
		if r.Kind == wire.KindFull && fulls.Load() <= 1 {
			return http.Header{"Retry-After": {"1"}}
		}
		return nil
	})
	e.startCataloguer(t)
	e.run(t)

	first := e.ctl.nextFull(t)
	second := e.ctl.nextFull(t)
	require.NotNil(t, second.Host)
	events, times := e.ctl.log()
	var at []time.Time
	for i, ev := range events {
		if ev == wire.KindFull {
			at = append(at, times[i])
		}
	}
	require.Len(t, at, 2)
	require.GreaterOrEqual(t, at[1].Sub(at[0]), time.Second, "the full report waits at least Retry-After")
	require.JSONEq(t, string(first.Host.SyftJSON), string(second.Host.SyftJSON))
	require.Equal(t, int32(1), hosts.Load(), "the resend does not catalogue the host again")
}

func TestRun_HostRetryResendsWithoutRecatalogue(t *testing.T) {
	e := newEnv(t)
	hosts := countingHost(e)
	var fulls atomic.Int32
	e.ctl.setAnswer(answerFull(func(wire.Report) (int, wire.ReportResponse) {
		// The first full report is applied, but its host part is not stored.
		return http.StatusOK, wire.ReportResponse{Applied: true, HostRetry: fulls.Add(1) == 1, Config: testConfig()}
	}))
	e.startCataloguer(t)
	e.run(t)

	first := e.ctl.nextFull(t)
	start := time.Now()
	second := e.ctl.nextFull(t)
	require.Less(t, time.Since(start), time.Second, "the host part is resent on the full backoff, not the report interval")
	require.NotNil(t, second.Host)
	require.JSONEq(t, string(first.Host.SyftJSON), string(second.Host.SyftJSON))
	require.Equal(t, int32(1), hosts.Load())
	require.Eventually(t, func() bool { return len(spooled(t, e.scratch)) == 0 }, waitFor, 5*time.Millisecond)
}

func TestRun_ProbeFailureSkipsHostCollection(t *testing.T) {
	e := newEnv(t)
	rec := e.withRecorder()
	hosts := countingHost(e)
	var probes atomic.Int32
	e.ctl.setConfig(func() (int, wire.AgentConfig) {
		if probes.Add(1) <= 3 {
			return http.StatusServiceUnavailable, wire.AgentConfig{}
		}
		return http.StatusOK, testConfig()
	})
	e.startCataloguer(t)
	e.run(t)

	r := e.ctl.nextFull(t)
	require.Equal(t, uint64(1), r.Seq, "no report is sent while the controller does not answer")
	require.NotNil(t, r.Host)
	require.GreaterOrEqual(t, probes.Load(), int32(4))
	require.Equal(t, int32(1), hosts.Load(), "the host is catalogued only once the controller answers")
	require.Empty(t, rec.errors(), "a controller that is starting is logged at Info")
	infos := 0
	for _, en := range rec.all() {
		if en.msg == "the controller did not answer; the full report waits" {
			infos++
		}
	}
	require.Equal(t, 3, infos)
}

func TestRun_ConnectionRefusedLogsAtInfo(t *testing.T) {
	e := newEnv(t)
	rec := e.withRecorder()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	e.opts.Controller = "https://" + ln.Addr().String()
	require.NoError(t, ln.Close())
	hosts := countingHost(e)
	e.startCataloguer(t)
	e.run(t)

	require.Eventually(t, func() bool { return len(rec.all()) >= 3 }, waitFor, 5*time.Millisecond)
	require.Empty(t, rec.errors())
	require.Zero(t, hosts.Load(), "nothing is collected for a controller that refuses connections")
}

func TestLogFailure_ErrorAfterAReportIntervalWithoutAnswer(t *testing.T) {
	refused := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	for _, tc := range []struct {
		err      error
		silence  time.Duration
		wantInfo bool
	}{
		{refused, time.Minute, true},
		{&StatusError{Code: http.StatusServiceUnavailable}, time.Minute, true},
		{&StatusError{Code: http.StatusTooManyRequests, RetryAfter: time.Second}, time.Minute, true},
		{&StatusError{Code: http.StatusInternalServerError}, time.Minute, false},
		{&StatusError{Code: http.StatusForbidden}, time.Minute, false},
		{refused, 7 * time.Hour, false},
		{&StatusError{Code: http.StatusServiceUnavailable}, 7 * time.Hour, false},
	} {
		rec := &recordingSink{}
		now := time.Now()
		a := &agent{o: Options{Log: logr.New(rec), Now: func() time.Time { return now }}, cfg: fallbackConfig,
			lastContact: now.Add(-tc.silence)}
		a.logFailure(tc.err, "sending a full report")
		entries := rec.all()
		require.Len(t, entries, 1)
		require.Equal(t, !tc.wantInfo, entries[0].err, "%v after %s", tc.err, tc.silence)
	}
}

func TestRun_InstanceIsRandomPerProcess(t *testing.T) {
	e := newEnv(t)
	e.startCataloguer(t)
	e.run(t)
	r1, r2 := e.ctl.next(t), e.ctl.next(t)
	require.Len(t, r1.Instance, 32)
	_, err := hex.DecodeString(r1.Instance)
	require.NoError(t, err)
	require.Equal(t, r1.Instance, r2.Instance, "one process keeps its instance")
	require.False(t, r1.StartedAt.IsZero(), "StartedAt is still sent")
	o := e.opts
	o.Scratch = t.TempDir()
	other, err := newAgent(o)
	require.NoError(t, err)
	require.NotEqual(t, r1.Instance, other.instance, "a new process has a new instance")
}

func TestRun_LogsRepeatedUnappliedReports(t *testing.T) {
	e := newEnv(t)
	rec := e.withRecorder()
	e.ctl.setAnswer(func(wire.Report) (int, wire.ReportResponse) {
		return http.StatusOK, wire.ReportResponse{Applied: false, Config: testConfig()}
	})
	e.startCataloguer(t)
	e.run(t)
	for range 3 {
		e.ctl.next(t)
	}
	require.Eventually(t, func() bool {
		for _, en := range rec.all() {
			if en.msg == "the controller has not applied this agent's last reports" {
				return !en.err && slices.Contains(en.kv, any(3))
			}
		}
		return false
	}, waitFor, 5*time.Millisecond)
}

func TestRun_HeartbeatDuringLongSleep(t *testing.T) {
	e := newEnv(t)
	long := wire.AgentConfig{ReportIntervalSeconds: 36000, ImageListIntervalSeconds: 3600}
	e.ctl.setConfig(func() (int, wire.AgentConfig) { return http.StatusOK, long })
	e.ctl.setAnswer(func(wire.Report) (int, wire.ReportResponse) {
		return http.StatusOK, wire.ReportResponse{Applied: true, Config: long}
	})
	e.startCataloguer(t)
	e.run(t)
	require.Equal(t, wire.KindFull, e.ctl.next(t).Kind)

	// The next report is due in 6 minutes: the heartbeat keeps moving while the agent sleeps.
	time.Sleep(50 * time.Millisecond)
	beats := map[int64]bool{}
	require.Eventually(t, func() bool {
		beats[mtimeNano(e.opts.Heartbeat)] = true
		return len(beats) >= 3
	}, waitFor, 2*time.Millisecond)
	select {
	case r := <-e.ctl.reports:
		t.Fatalf("unexpected report %s while sleeping", r.Kind)
	default:
	}
}

func TestPulse_StopsWhenLeaseLapses(t *testing.T) {
	fastTimers(t)
	p := filepath.Join(t.TempDir(), "heartbeat")
	a := &agent{o: Options{Heartbeat: p, Log: logr.Discard()}}
	a.lease(30 * time.Millisecond)
	stop := a.startPulse()
	defer stop()
	require.Eventually(t, func() bool { return mtimeNano(p) != 0 }, waitFor, time.Millisecond, "the pulse touches while the lease holds")
	time.Sleep(200 * time.Millisecond)
	last := mtimeNano(p)
	time.Sleep(100 * time.Millisecond)
	require.Equal(t, last, mtimeNano(p), "a wedged loop no longer renews its lease, so the heartbeat goes stale")
	a.lease(time.Second)
	require.Eventually(t, func() bool { return mtimeNano(p) != last }, waitFor, time.Millisecond)
}

func TestRun_ImagesReportBetweenJobs(t *testing.T) {
	e := newEnv(t)
	platform := "linux/" + runtime.GOARCH
	e.runner.setFn(func(ctx context.Context, req sbom.CatalogRequest) (*sbom.CatalogResponse, error) {
		if req.Source == sbom.CatalogSourceHostDir {
			return &sbom.CatalogResponse{SyftJSON: json.RawMessage(hostJSON)}, nil
		}
		if filepath.Base(req.Path) == "work-w1" {
			select { // longer than the 100ms image-list interval
			case <-time.After(400 * time.Millisecond):
			case <-ctx.Done():
			}
		}
		return &sbom.CatalogResponse{SyftJSON: json.RawMessage(imageJSON)}, nil
	})
	var offered atomic.Bool
	e.ctl.setAnswer(func(r wire.Report) (int, wire.ReportResponse) {
		resp := wire.ReportResponse{Applied: true, Config: testConfig()}
		if r.Kind == wire.KindFull && offered.CompareAndSwap(false, true) {
			deadline := time.Now().Add(5 * time.Minute)
			for _, id := range []string{"w1", "w2"} {
				resp.Work = append(resp.Work, wire.WorkRequest{ID: id, Digest: e.config, Platform: platform, Deadline: deadline})
			}
		}
		return http.StatusOK, resp
	})
	e.startCataloguer(t)
	e.run(t)
	require.Equal(t, "w1", e.ctl.nextSBOM(t).ID)
	require.Equal(t, "w2", e.ctl.nextSBOM(t).ID)
	events, _ := e.ctl.log()
	i1, i2 := slices.Index(events, "sbom:w1"), slices.Index(events, "sbom:w2")
	require.Contains(t, events[i1+1:i2], wire.KindImages, "an images report is sent between the jobs: %v", events)
}
