//go:build memharness

package memharness

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/metrics"
	"runtime/pprof"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// sampleEvery is how often the sampler reads the runtime's metrics.
const sampleEvery = 10 * time.Millisecond

// The runtime/metrics the sampler reads.
const (
	metricLive     = "/gc/heap/live:bytes"
	metricObjects  = "/memory/classes/heap/objects:bytes"
	metricUnused   = "/memory/classes/heap/unused:bytes"
	metricTotal    = "/memory/classes/total:bytes"
	metricReleased = "/memory/classes/heap/released:bytes"
	metricCycles   = "/gc/cycles/total:gc-cycles"
)

// memSample is one reading: the live heap as of the last GC (go_gc_heap_live_bytes), the heap in use (objects
// and the free space in their spans, MemStats.HeapInuse), and the memory the runtime has mapped and not
// returned to the OS.
type memSample struct {
	at                      time.Duration
	live, heapInUse, mapped uint64
	cycles                  uint64
}

// peaks are the highest of each reading over a run, the last phase marked before the live peak, and the
// process's peak resident set size when the sampler stopped.
type peaks struct {
	live, heapInUse, mapped memSample
	livePhase               string
	maxRSS                  uint64
}

// sampler reads the runtime's heap metrics until stopped, writes a heap profile whenever a GC leaves more live
// heap than any before (so the last one written is the peak's), and a timeline once a second.
type sampler struct {
	t       *testing.T
	out     string
	start   time.Time
	samples []metrics.Sample
	first   memSample
	quit    chan struct{}
	done    chan struct{}

	mu    sync.Mutex
	peaks peaks
	phase string
	marks []string
}

func startSampler(t *testing.T, out string) *sampler {
	t.Helper()
	s := &sampler{t: t, out: out, start: time.Now(), quit: make(chan struct{}), done: make(chan struct{}), phase: "start"}
	for _, name := range []string{metricLive, metricObjects, metricUnused, metricTotal, metricReleased, metricCycles} {
		s.samples = append(s.samples, metrics.Sample{Name: name})
	}
	s.first = s.read()
	tl, err := os.Create(filepath.Join(out, "timeline.tsv")) //nolint:gosec // a file under the harness's work directory
	require.NoError(t, err)
	_, _ = fmt.Fprintln(tl, "seconds\tlive_mib\theap_in_use_mib\tmapped_mib\tgc_cycles\tphase")
	go s.loop(tl)
	return s
}

func (s *sampler) read() memSample {
	metrics.Read(s.samples)
	v := func(i int) uint64 { return s.samples[i].Value.Uint64() }
	return memSample{at: time.Since(s.start), live: v(0), heapInUse: v(1) + v(2), mapped: v(3) - v(4), cycles: v(5)}
}

func (s *sampler) loop(tl *os.File) {
	defer close(s.done)
	defer func() { _ = tl.Close() }()
	tick := time.NewTicker(sampleEvery)
	defer tick.Stop()
	var lastLine time.Duration
	var lastCycles uint64
	for {
		select {
		case <-s.quit:
			return
		case <-tick.C:
		}
		m := s.read()
		s.mu.Lock()
		p := &s.peaks
		newPeak := m.cycles != lastCycles && m.live > p.live.live
		if newPeak {
			p.live, p.livePhase = m, s.phase
		}
		if m.heapInUse > p.heapInUse.heapInUse {
			p.heapInUse = m
		}
		if m.mapped > p.mapped.mapped {
			p.mapped = m
		}
		phase := s.phase
		s.mu.Unlock()
		lastCycles = m.cycles
		if newPeak {
			s.writeProfile()
		}
		if m.at-lastLine >= time.Second {
			lastLine = m.at
			_, _ = fmt.Fprintf(tl, "%.1f\t%.1f\t%.1f\t%.1f\t%d\t%s\n", m.at.Seconds(), mibf(m.live), mibf(m.heapInUse), mibf(m.mapped), m.cycles, phase)
		}
	}
}

// writeProfile writes the heap profile, which describes the heap as of the last GC, to heap-peak.pb.gz.
func (s *sampler) writeProfile() {
	path := filepath.Join(s.out, "heap-peak.pb.gz")
	f, err := os.Create(path + ".tmp") //nolint:gosec // a file under the harness's work directory
	if err != nil {
		return
	}
	err = pprof.Lookup("heap").WriteTo(f, 0)
	if cerr := f.Close(); err == nil && cerr == nil {
		_ = os.Rename(path+".tmp", path)
	}
}

// mark names the phase the run is in from now on, and logs it with the live heap.
func (s *sampler) mark(phase string) {
	m := s.read()
	s.mu.Lock()
	s.phase = phase
	s.marks = append(s.marks, phase)
	s.mu.Unlock()
	fmt.Fprintf(os.Stderr, "%s memharness: %s (live %s, heap in use %s)\n", time.Now().Format("15:04:05.000"), phase, mib(m.live),
		mib(m.heapInUse))
}

func (s *sampler) stop() peaks {
	close(s.quit)
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peaks.maxRSS = maxRSS()
	return s.peaks
}

func mibf(b uint64) float64 { return float64(b) / (1 << 20) }

func mib(b uint64) string { return fmt.Sprintf("%.0f MiB", mibf(b)) }

// maxRSS is the process's peak resident set size.
func maxRSS() uint64 {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	if runtime.GOOS == "darwin" {
		return uint64(ru.Maxrss) // bytes
	}
	return uint64(ru.Maxrss) << 10 // KiB
}

// pprofTop is go tool pprof's top allocators of the heap profile at path, by bytes in use, and by cumulative
// bytes in use; "" when it cannot run.
func pprofTop(ctx context.Context, path string) string {
	if _, err := os.Stat(path); err != nil { //nolint:gosec // G703: the harness's own profile
		return ""
	}
	var out []byte
	for _, flag := range []string{"-top", "-cum"} {
		args := []string{"tool", "pprof", "-sample_index=inuse_space", "-nodecount=30", "-top"}
		if flag == "-cum" {
			args = append(args, "-cum")
		}
		b, err := exec.CommandContext(ctx, "go", append(args, path)...).CombinedOutput() //nolint:gosec // the harness's own profile
		if err != nil {
			return ""
		}
		out = append(out, b...)
		out = append(out, '\n')
	}
	return string(out)
}
