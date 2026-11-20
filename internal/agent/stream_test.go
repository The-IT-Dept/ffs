package agent

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/agentapi/wire"
	"github.com/the-it-dept/ffs/internal/sbom"
)

// largeSBOMBytes is the size of the synthetic syft-json document: past the point where holding it more than once
// would not fit the collector's 128Mi limit.
const largeSBOMBytes = 40 << 20

// writeLargeSBOM writes a syft-json document of at least largeSBOMBytes to w and returns its sha256. Each
// artifact is built in one reused buffer, so writing it adds next to nothing to the heap.
func writeLargeSBOM(w io.Writer) ([sha256.Size]byte, error) {
	h := sha256.New()
	bw := bufio.NewWriterSize(io.MultiWriter(w, h), 64<<10)
	pad := strings.Repeat("x", 900)
	written := 0
	buf := make([]byte, 0, 2048)
	put := func(b []byte) error {
		written += len(b)
		_, err := bw.Write(b)
		return err
	}
	if err := put([]byte(`{"artifacts":[`)); err != nil {
		return [sha256.Size]byte{}, err
	}
	for i := int64(0); written < largeSBOMBytes; i++ {
		buf = buf[:0]
		if i > 0 {
			buf = append(buf, ',')
		}
		buf = append(buf, `{"id":"`...)
		buf = strconv.AppendInt(buf, i, 10)
		buf = append(buf, `","name":"example.com/pkg-`...)
		buf = strconv.AppendInt(buf, i, 10)
		buf = append(buf, `","version":"v1.0.0","type":"go-module","metadata":{"padding":"`...)
		buf = append(buf, pad...)
		buf = append(buf, `"}}`...)
		if err := put(buf); err != nil {
			return [sha256.Size]byte{}, err
		}
	}
	if err := put([]byte(`],"source":{"id":"large","type":"directory"},"descriptor":{"name":"syft"}}`)); err != nil {
		return [sha256.Size]byte{}, err
	}
	if err := bw.Flush(); err != nil {
		return [sha256.Size]byte{}, err
	}
	var sum [sha256.Size]byte
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

// serveLargeCataloguer answers every catalog job on socket with the large document, written as it is generated so
// the test's own heap stays flat. It returns the document's hash once a job has been answered.
func serveLargeCataloguer(t *testing.T, socket string) func() [sha256.Size]byte {
	t.Helper()
	var (
		mu  sync.Mutex
		sum [sha256.Size]byte
	)
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socket)
	require.NoError(t, err)
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req sbom.CatalogRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"syftJSON":`)
		s, err := writeLargeSBOM(w)
		if err != nil {
			return
		}
		_, _ = io.WriteString(w, `,"coverage":{"Notes":["large"]}}`+"\n")
		mu.Lock()
		sum = s
		mu.Unlock()
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return func() [sha256.Size]byte {
		mu.Lock()
		defer mu.Unlock()
		return sum
	}
}

// savingController is the controller's agent API that saves each request body to a file without reading it into
// memory, and answers config, reports and SBOM results.
func savingController(t *testing.T, caFile string) (url string, saved func(path string) string) {
	t.Helper()
	ca := newCA(t, "agent-api-ca")
	leaf := newLeaf(t, ca, "127.0.0.1")
	writeTestFile(t, caFile, ca.pem)
	dir := t.TempDir()
	var mu sync.Mutex
	files := map[string]string{}
	save := func(r *http.Request) error {
		f, err := os.CreateTemp(dir, "body-*")
		if err != nil {
			return err
		}
		defer f.Close() //nolint:errcheck // the test reads it back
		if _, err := io.Copy(f, r.Body); err != nil {
			return err
		}
		mu.Lock()
		files[r.URL.Path] = f.Name()
		mu.Unlock()
		return nil
	}
	cfg := wire.AgentConfig{ReportIntervalSeconds: 3600, ImageListIntervalSeconds: 600, MaxReportBytes: 128 << 20}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+wire.PathConfig, func(w http.ResponseWriter, _ *http.Request) { reply(w, http.StatusOK, cfg) })
	mux.HandleFunc("POST "+wire.PathReport, func(w http.ResponseWriter, r *http.Request) {
		if err := save(r); err != nil {
			reply(w, http.StatusInternalServerError, nil)
			return
		}
		reply(w, http.StatusOK, wire.ReportResponse{Applied: true, Config: cfg})
	})
	mux.HandleFunc("POST "+wire.PathSBOM, func(w http.ResponseWriter, r *http.Request) {
		if err := save(r); err != nil {
			reply(w, http.StatusInternalServerError, nil)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	url = tlsServer(t, mux, func() *tls.Certificate { return &leaf })
	return url, func(path string) string {
		mu.Lock()
		defer mu.Unlock()
		return files[path]
	}
}

// peakHeapGrowth runs f while sampling the heap every millisecond, with the collector tuned to keep garbage
// small, and returns the largest growth over the heap before f.
func peakHeapGrowth(t *testing.T, f func()) uint64 {
	t.Helper()
	defer debug.SetGCPercent(debug.SetGCPercent(10))
	read := func() uint64 {
		s := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
		metrics.Read(s)
		return s[0].Value.Uint64()
	}
	runtime.GC()
	base := read()
	var peak atomic.Uint64
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		for {
			if v := read(); v > peak.Load() {
				peak.Store(v)
			}
			select {
			case <-done:
				return
			case <-tick.C:
			}
		}
	})
	f()
	close(done)
	wg.Wait()
	if p := peak.Load(); p > base {
		return p - base
	}
	return 0
}

// TestCollectorStreamsLargeSBOM: an SBOM passes from the cataloguer to the controller without the collector
// holding it in memory, for an image job (POST /sbom) and for the host part of a full report.
func TestCollectorStreamsLargeSBOM(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	docSum := serveLargeCataloguer(t, e.socket)
	e.opts.CAFile = filepath.Join(t.TempDir(), "ca.crt")
	url, saved := savingController(t, e.opts.CAFile)
	e.opts.Controller = url
	limit := uint64(largeSBOMBytes / 2)

	t.Run("image SBOM", func(t *testing.T) {
		a, err := newAgent(e.opts)
		require.NoError(t, err)
		w := wire.WorkRequest{ID: "w1", Digest: e.config, Platform: "linux/" + runtime.GOARCH, Deadline: time.Now().Add(5 * time.Minute)}
		growth := peakHeapGrowth(t, func() { a.runJob(ctx, w, time.Now()) })
		require.Less(t, growth, limit, "peak heap growth %d MiB for a %d MiB SBOM", growth>>20, largeSBOMBytes>>20)

		body, err := os.ReadFile(saved(wire.PathSBOM))
		require.NoError(t, err)
		var res wire.SBOMResult
		require.NoError(t, json.Unmarshal(body, &res))
		require.Equal(t, "w1", res.ID)
		require.GreaterOrEqual(t, len(res.SyftJSON), largeSBOMBytes)
		require.Equal(t, docSum(), sha256.Sum256(res.SyftJSON), "the SBOM arrives byte for byte")
		require.Equal(t, []string{"large"}, res.Coverage.Notes)
		require.Empty(t, spooled(t, e.scratch), "the spooled SBOM is deleted after it is sent")
	})

	t.Run("host SBOM", func(t *testing.T) {
		a, err := newAgent(e.opts)
		require.NoError(t, err)
		growth := peakHeapGrowth(t, func() { a.fullReport(ctx, &schedule{}) })
		require.Less(t, growth, limit, "peak heap growth %d MiB for a %d MiB SBOM", growth>>20, largeSBOMBytes>>20)

		body, err := os.ReadFile(saved(wire.PathReport))
		require.NoError(t, err)
		var r wire.Report
		require.NoError(t, json.Unmarshal(body, &r))
		require.Equal(t, wire.KindFull, r.Kind)
		require.NotNil(t, r.Host)
		require.Equal(t, docSum(), sha256.Sum256(r.Host.SyftJSON), "the host SBOM arrives byte for byte")
		require.Nil(t, a.host, "the controller stored the host part")
		require.Empty(t, spooled(t, e.scratch), "the spooled host SBOM is deleted once stored")
	})
}
