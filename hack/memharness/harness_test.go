//go:build memharness

package memharness

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/the-it-dept/ffs/internal/agentapi"
	"github.com/the-it-dept/ffs/internal/agentapi/wire"
	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/engine"
	"github.com/the-it-dept/ffs/internal/feeds/grypedb"
	"github.com/the-it-dept/ffs/internal/match"
	"github.com/the-it-dept/ffs/internal/match/grype"
	"github.com/the-it-dept/ffs/internal/match/k8s"
	"github.com/the-it-dept/ffs/internal/match/osvfast"
	"github.com/the-it-dept/ffs/internal/match/upstream"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/nodegroup"
	"github.com/the-it-dept/ffs/internal/sbom"
	"github.com/the-it-dept/ffs/internal/store"
)

const (
	envDir     = "FFS_MEMHARNESS_DIR"
	envLabel   = "FFS_MEMHARNESS_LABEL"
	envCompare = "FFS_MEMHARNESS_COMPARE"
	envWindow  = "FFS_MEMHARNESS_OSV_WINDOW"
	envHosts   = "FFS_MEMHARNESS_HOSTS"

	defaultDir    = "/tmp/ffs-memharness"
	defaultWindow = 336 * time.Hour

	advisoriesDB  = "advisories.db"
	clusterName   = "test"
	kernelRelease = "7.0.0-34-generic"
	// groupCount node groups of nodeCount nodes: worker-n is in group (n-1) mod groupCount.
	groupCount = 5
	nodeCount  = 8
	// agentBackoff is the node agent's first backoff before it sends a report again whose host part was not
	// stored (HostRetry).
	agentBackoff = 10 * time.Second
)

func workDir() string {
	if d := os.Getenv(envDir); d != "" {
		return d
	}
	return defaultDir
}

func osvWindow(t *testing.T) time.Duration {
	v := os.Getenv(envWindow)
	if v == "" {
		return defaultWindow
	}
	d, err := time.ParseDuration(v)
	require.NoError(t, err, envWindow)
	return d
}

func hostPath(dir string, group int) string {
	return filepath.Join(dir, "hosts", fmt.Sprintf("group-%d.json", group))
}

// harnessConfig is the chart's default controller configuration, with the agent on and the data directory
// under dir.
func harnessConfig(dir string) config.Config {
	cfg := config.Default()
	cfg.ClusterName = clusterName
	cfg.DataDir = filepath.Join(dir, "data")
	cfg.NodeAgent.Enabled = true
	return cfg
}

// newEngine builds the engine and its matchers as the controller does (internal/controller wire).
func newEngine(cfg config.Config, st *store.Store, log logr.Logger) (*engine.Engine, *grype.Matcher) {
	gm := grype.New(st)
	osvMatcher, upstreamMatcher, k8sMatcher := osvfast.New(st), upstream.New(st), k8s.New(st)
	return engine.New(engine.Options{
		Config: cfg, Store: st, Exceptions: st, Grype: gm,
		Matchers: []match.Matcher{osvMatcher, upstreamMatcher, k8sMatcher},
		Records:  []match.RecordMatcher{osvMatcher, upstreamMatcher, k8sMatcher},
		CNA:      upstreamMatcher,
		Log:      log,
	}), gm
}

// stepLogger logs Info lines (not V(1)) to stderr with the time: components log from goroutines that may
// outlive a test's last t.Log.
func stepLogger(*testing.T) logr.Logger {
	return funcr.New(func(prefix, args string) {
		fmt.Fprintf(os.Stderr, "%s %s %s\n", time.Now().Format("15:04:05.000"), prefix, args)
	}, funcr.Options{})
}

// nodeAuth authenticates the bearer token as the node it names.
type nodeAuth struct{}

func (nodeAuth) Authenticate(_ context.Context, token string) (agentapi.Identity, error) {
	return agentapi.Identity{Node: token, Pod: "ffs-agent-" + token, ServiceAccount: "ffs-agent", Namespace: "ffs-agent"}, nil
}

// nodeMap is the controller's Node cache.
type nodeMap map[string]*corev1.Node

func (m nodeMap) GetNode(_ context.Context, name string) (*corev1.Node, bool, error) {
	n, ok := m[name]
	return n, ok, nil
}

// noPods is a pod index with no pods: the harness has no workloads.
type noPods struct{}

func (noPods) DigestsOnNode(context.Context, string) (map[string]bool, error) {
	return map[string]bool{}, nil
}

func nodeName(i int) string { return fmt.Sprintf("worker-%d", i+1) }

func harnessNode(name string) *corev1.Node {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name,
		Labels: map[string]string{"kubernetes.io/os": "linux", "kubernetes.io/arch": "amd64"}}, Status: corev1.NodeStatus{
		NodeInfo: corev1.NodeSystemInfo{OSImage: "Ubuntu 26.04.1 LTS", ContainerRuntimeVersion: "containerd://2.2.1",
			KubeletVersion: "v1.37.1", Architecture: "amd64", KernelVersion: kernelRelease, OperatingSystem: "linux"},
		Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
	}}
}

// TestFirstIngest replays a cluster's first node-agent ingest on a copy of the prepared store and measures the
// controller's memory over it (see the package documentation).
func TestFirstIngest(t *testing.T) {
	dir := workDir()
	for _, m := range []string{"advisories.ok", filepath.Join("hosts", "hosts.ok")} {
		_, err := os.Stat(filepath.Join(dir, m))
		require.NoError(t, err, "run TestPrepare first")
	}
	label := os.Getenv(envLabel)
	if label == "" {
		label = "run"
	}
	out := filepath.Join(dir, label)
	resetDir(t, out)
	dbPath := filepath.Join(out, "ffs.db")
	copyFile(t, filepath.Join(dir, advisoriesDB), dbPath)
	hosts := make([][]byte, groupCount)
	for g := range hosts {
		var err error
		hosts[g], err = os.ReadFile(hostPath(dir, g))
		require.NoError(t, err)
	}

	ctx := context.Background()
	log := stepLogger(t)
	cfg := harnessConfig(dir)
	st, err := store.Open(ctx, dbPath)
	require.NoError(t, err)
	defer func() { require.NoError(t, st.Close()) }()
	eng, gm := newEngine(cfg, st, log.WithName("engine"))
	path, built, ok, err := grypedb.New(grypedb.Options{Config: cfg.Feeds.GrypeDB.Feed(), DataDir: cfg.DataDir, Store: st}).Current(ctx)
	require.NoError(t, err)
	require.True(t, ok, "the prepared store has a Grype DB")
	require.NoError(t, gm.Load(path, built))

	acq := sbom.NewAcquirer(sbom.AcquirerOptions{Store: st, Concurrency: cfg.Catalog.Concurrency, OnCatalogued: eng.OnImageCatalogued,
		JobTimeout: cfg.Catalog.Timeout + 5*time.Minute, Log: log.WithName("sbom")})
	nodes := nodeMap{}
	objs := make([]client.Object, 0, nodeCount)
	for i := range nodeCount {
		n := harnessNode(nodeName(i))
		nodes[n.Name] = n
		objs = append(objs, n)
	}
	rec := agentapi.NewReconciler(agentapi.ReconcilerOptions{Store: st, Engine: eng, Nodes: fake.NewClientBuilder().WithObjects(objs...).Build(),
		Pods: noPods{}, Config: cfg, Log: log.WithName("nodeagent")})
	ing := agentapi.NewIngester(agentapi.IngesterOptions{Store: st, Acquirer: acq, Nodes: nodes, Trigger: rec.Trigger, Config: cfg.NodeAgent,
		Log: log.WithName("nodeagent")})
	handler := agentapi.NewServer(agentapi.ServerOptions{Auth: nodeAuth{}, Reports: ing, MaxReportBytes: cfg.NodeAgent.MaxReportBytes,
		Log: log.WithName("nodeagent")}).Handler()

	runtime.GC()
	debug.FreeOSMemory()
	s := startSampler(t, out)
	s.mark("loaded")
	runCtx, stop := context.WithCancel(ctx)
	var wg sync.WaitGroup
	for _, run := range []func(context.Context) error{acq.Start, eng.Start, rec.Start} {
		wg.Go(func() { _ = run(runCtx) })
	}
	start := time.Now()
	sendReports(t, ctx, handler, hosts, s)
	s.mark("reports answered")
	digests := waitFirstIngest(t, ctx, st, eng, s)
	elapsed := time.Since(start)
	s.mark("first ingest done")
	peak := s.stop()
	stop()
	wg.Wait()

	res := results(t, ctx, st, digests)
	resJSON, err := json.MarshalIndent(res, "", " ")
	require.NoError(t, err)
	writeFile(t, filepath.Join(out, "results.json"), resJSON)

	var sum strings.Builder
	fmt.Fprintf(&sum, "label %s\nGOMEMLIMIT %d\nwall time %s\n", label, debug.SetMemoryLimit(-1), elapsed.Round(time.Second))
	fmt.Fprintf(&sum, "before the reports: live %s, heap in use %s\n", mib(s.first.live), mib(s.first.heapInUse))
	fmt.Fprintf(&sum, "peak live heap %s (at %s, after %q)\n", mib(peak.live.live), peak.live.at.Round(time.Millisecond), peak.livePhase)
	fmt.Fprintf(&sum, "peak heap in use %s\npeak Go memory mapped and not released %s\nmax RSS %s\n",
		mib(peak.heapInUse.heapInUse), mib(peak.mapped.mapped), mib(peak.maxRSS))
	fmt.Fprintf(&sum, "groups %d, matches %d, findings %d\n", len(digests), len(res.Matches), len(res.Findings))
	for _, src := range []model.MatchSource{model.SourceGrype, model.SourceOSV, model.SourceUpstream} {
		fmt.Fprintf(&sum, "  %s matches %d\n", src, countSource(res.Matches, src))
	}
	t.Log("\n" + sum.String())
	writeFile(t, filepath.Join(out, "summary.txt"), []byte(sum.String()))

	if top := pprofTop(ctx, filepath.Join(out, "heap-peak.pb.gz")); top != "" {
		t.Log("\n" + top)
		writeFile(t, filepath.Join(out, "top.txt"), []byte(top))
	}
	if other := os.Getenv(envCompare); other != "" {
		compareResults(t, filepath.Join(dir, other, "results.json"), res)
	}
}

// sendReports sends every node's first full report at once and waits for their answers. Like the agent, a node
// answered 429 sends the same report again after Retry-After, and one answered HostRetry sends its next report
// after agentBackoff.
func sendReports(t *testing.T, ctx context.Context, h http.Handler, hosts [][]byte, s *sampler) {
	t.Helper()
	started := time.Now().UTC()
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		errs []error
	)
	for i := range nodeCount {
		name, g := nodeName(i), i%groupCount
		wg.Go(func() {
			seq := uint64(1)
			for {
				r := wire.Report{Node: name, AgentVersion: "v0.0.2", BootID: "boot-" + name, Instance: fmt.Sprintf("%032x", i+1),
					StartedAt: started, Seq: seq, Kind: wire.KindFull, CollectedAt: time.Now().UTC(), KernelRelease: kernelRelease,
					Arch: "amd64", Host: &wire.Host{PackageDB: "dpkg", Binaries: hostBinaries, SyftJSON: hosts[g]}}
				code, header, resp, err := postReport(ctx, h, name, r)
				switch {
				case err != nil:
					mu.Lock()
					errs = append(errs, fmt.Errorf("%s: %w", name, err))
					mu.Unlock()
					return
				case code == http.StatusTooManyRequests:
					wait, _ := strconv.Atoi(header.Get("Retry-After"))
					s.mark(fmt.Sprintf("%s deferred %ds", name, wait))
					time.Sleep(time.Duration(wait) * time.Second)
					continue
				case code != http.StatusOK:
					mu.Lock()
					errs = append(errs, fmt.Errorf("%s: answered %d", name, code))
					mu.Unlock()
					return
				case resp.HostRetry:
					s.mark(name + " host retry")
					seq++
					time.Sleep(agentBackoff)
					continue
				}
				s.mark(fmt.Sprintf("%s report applied=%t", name, resp.Applied))
				return
			}
		})
	}
	wg.Wait()
	for _, err := range errs {
		t.Error(err)
	}
	require.Empty(t, errs)
}

func postReport(ctx context.Context, h http.Handler, node string, r wire.Report) (int, http.Header, wire.ReportResponse, error) {
	var resp wire.ReportResponse
	body, err := json.Marshal(r)
	if err != nil {
		return 0, nil, resp, err
	}
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, wire.PathReport, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+node)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			return 0, nil, resp, err
		}
	}
	return w.Code, w.Header(), resp, nil
}

// waitFirstIngest waits until every node's host SBOM is stored, every group SBOM is matched, the Nodes owner
// runs every group and the engine is idle, three checks a second apart in a row, and returns the group digests.
func waitFirstIngest(t *testing.T, ctx context.Context, st *store.Store, eng *engine.Engine, s *sampler) []string {
	t.Helper()
	matched := map[string]bool{}
	stable := 0
	for {
		digests, done, err := firstIngestDone(ctx, st, eng, matched, s)
		require.NoError(t, err)
		if done {
			if stable++; stable == 3 {
				return digests
			}
		} else {
			stable = 0
		}
		time.Sleep(time.Second)
	}
}

func firstIngestDone(ctx context.Context, st *store.Store, eng *engine.Engine, matched map[string]bool, s *sampler) ([]string, bool, error) {
	rows, err := st.AgentNodes(ctx)
	if err != nil {
		return nil, false, err
	}
	var digests []string
	for _, r := range rows {
		if r.Fingerprint == "" {
			return nil, false, nil
		}
		digests = append(digests, nodegroup.GroupDigest(r.Fingerprint))
	}
	slices.Sort(digests)
	digests = slices.Compact(digests)
	if len(rows) < nodeCount || len(digests) < groupCount {
		return nil, false, nil
	}
	unmatched, err := st.UnmatchedDigests(ctx, digests)
	if err != nil {
		return nil, false, err
	}
	for _, d := range digests {
		img, ok, err := st.GetImage(ctx, d)
		if err != nil {
			return nil, false, err
		}
		if ok && img.Status == model.ImageCatalogued && !slices.Contains(unmatched, d) && !matched[d] {
			matched[d] = true
			s.mark(fmt.Sprintf("group %d of %d matched", len(matched), groupCount))
		}
	}
	if len(matched) < groupCount {
		return nil, false, nil
	}
	o, ok, err := st.GetOwner(ctx, model.NodesOwner(clusterName).Key())
	if err != nil || !ok {
		return nil, false, err
	}
	running := map[string]bool{}
	for _, c := range o.Containers {
		running[c.Digest] = true
	}
	for _, d := range digests {
		if !running[d] {
			return nil, false, nil
		}
	}
	return digests, eng.Idle(), nil
}

// harnessResults are the matches and findings a run stored, without the times that differ between runs.
type harnessResults struct {
	Matches  []model.Match   `json:"matches"`
	Findings []model.Finding `json:"findings"`
}

func results(t *testing.T, ctx context.Context, st *store.Store, digests []string) harnessResults {
	t.Helper()
	ms, err := st.MatchesForDigests(ctx, digests)
	require.NoError(t, err)
	for i := range ms {
		ms[i].ObservedAt, ms[i].DBBuilt = time.Time{}, time.Time{}
		slices.Sort(ms[i].FixedVersions)
	}
	slices.SortFunc(ms, func(a, b model.Match) int {
		return strings.Compare(matchKey(a), matchKey(b))
	})
	fs, err := st.FindingsForOwner(ctx, model.NodesOwner(clusterName).Key())
	require.NoError(t, err)
	for i := range fs {
		fs[i].Observed, fs[i].Matched, fs[i].LastSeen, fs[i].ResolvedAt = time.Time{}, time.Time{}, time.Time{}, nil
	}
	slices.SortFunc(fs, func(a, b model.Finding) int { return strings.Compare(a.Fingerprint, b.Fingerprint) })
	return harnessResults{Matches: ms, Findings: fs}
}

func matchKey(m model.Match) string {
	return strings.Join([]string{m.ImageDigest, m.PackageID, m.AdvisoryID, string(m.Source), m.Namespace}, "\x00")
}

func countSource(ms []model.Match, src model.MatchSource) int {
	n := 0
	for _, m := range ms {
		if m.Source == src {
			n++
		}
	}
	return n
}

// compareResults fails the test when res differs from the results stored at path, listing the first rows
// that differ.
func compareResults(t *testing.T, path string, res harnessResults) {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // G304: an earlier run's results in the work directory
	require.NoError(t, err, "results to compare with")
	var other harnessResults
	require.NoError(t, json.Unmarshal(b, &other))
	diff := func(what string, a, b []string) {
		onlyA, onlyB := missing(a, b), missing(b, a)
		if len(onlyA)+len(onlyB) == 0 {
			t.Logf("%s identical to %s: %d rows", what, path, len(a))
			return
		}
		t.Errorf("%s differ from %s: %d rows only in this run, %d only in that one", what, path, len(onlyA), len(onlyB))
		for _, r := range onlyA[:min(len(onlyA), 5)] {
			t.Errorf("  this run: %s", r)
		}
		for _, r := range onlyB[:min(len(onlyB), 5)] {
			t.Errorf("  that run: %s", r)
		}
	}
	diff("matches", rowsOf(t, res.Matches), rowsOf(t, other.Matches))
	diff("findings", rowsOf(t, res.Findings), rowsOf(t, other.Findings))
}

func rowsOf[T any](t *testing.T, xs []T) []string {
	t.Helper()
	out := make([]string, len(xs))
	for i, x := range xs {
		b, err := json.Marshal(x)
		require.NoError(t, err)
		out[i] = string(b)
	}
	slices.Sort(out)
	return out
}

// missing returns the rows of a that b lacks.
func missing(a, b []string) []string {
	var out []string
	for _, r := range a {
		if _, ok := slices.BinarySearch(b, r); !ok {
			out = append(out, r)
		}
	}
	return out
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	in, err := os.Open(from) //nolint:gosec // the harness's own prepared store
	require.NoError(t, err)
	defer func() { _ = in.Close() }()
	o, err := os.Create(to) //nolint:gosec // a file under the harness's work directory
	require.NoError(t, err)
	_, err = io.Copy(o, in)
	require.NoError(t, err)
	require.NoError(t, o.Close())
}
