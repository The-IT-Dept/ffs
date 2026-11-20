package agentapi

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/the-it-dept/ffs/internal/agentapi/wire"
	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/nodegroup"
	"github.com/the-it-dept/ffs/internal/output/metrics"
	"github.com/the-it-dept/ffs/internal/sbom"
	"github.com/the-it-dept/ffs/internal/store"
)

const runningKernel = "7.0.0-34-generic"

var (
	ubuntu  = &linux.Release{ID: "ubuntu", VersionID: "26.04", VersionCodename: "resolute"}
	worker1 = Identity{Node: "worker-1", Pod: "ffs-agent-x7k2p", PodUID: "uid-1", ServiceAccount: "ffs-agent", Namespace: "ffs-agent"}
)

// testNode is a Ready node as the manager's cache holds it.
func testNode(name, osImage string, images ...corev1.ContainerImage) *corev1.Node {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}, Status: corev1.NodeStatus{
		NodeInfo: corev1.NodeSystemInfo{OSImage: osImage, ContainerRuntimeVersion: "containerd://2.2.1", KubeletVersion: "v1.37.1",
			Architecture: "amd64", KernelVersion: runningKernel},
		Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
		Images:     images,
	}}
}

type fakeNodes map[string]*corev1.Node

func (f fakeNodes) GetNode(_ context.Context, name string) (*corev1.Node, bool, error) {
	n, ok := f[name]
	return n, ok, nil
}

type ingestCall struct {
	req  sbom.Request
	res  sbom.Result
	prov *store.AgentProvenance // IngestFromNode only
}

// fakeIngest records Ingest calls and, unless err is set, stores the image catalogued with its packages as
// the acquirer does.
type fakeIngest struct {
	st     *store.Store
	mu     sync.Mutex
	calls  []ingestCall
	err    error
	during func()
}

func (f *fakeIngest) Ingest(ctx context.Context, r sbom.Request, res *sbom.Result) error {
	return f.ingest(ctx, nil, r, res)
}

// IngestFromNode is Ingest that, like the acquirer, refuses an image catalogued from another node's agent
// SBOM and records prov for a stored SBOM.
func (f *fakeIngest) IngestFromNode(ctx context.Context, prov store.AgentProvenance, r sbom.Request, res *sbom.Result) error {
	prov.Digest = r.Digest
	return f.ingest(ctx, &prov, r, res)
}

func (f *fakeIngest) ingest(ctx context.Context, prov *store.AgentProvenance, r sbom.Request, res *sbom.Result) error {
	f.mu.Lock()
	f.calls = append(f.calls, ingestCall{req: r, res: *res, prov: prov})
	err, during := f.err, f.during
	f.mu.Unlock()
	if during != nil {
		during()
	}
	if err != nil {
		return err
	}
	if prov != nil {
		img, ok, err := f.st.GetImage(ctx, r.Digest)
		if err != nil {
			return err
		}
		stored, has, err := f.st.AgentProvenanceOf(ctx, r.Digest)
		if err != nil {
			return err
		}
		if ok && img.Status == model.ImageCatalogued && has && stored.Node != prov.Node {
			return sbom.ErrOtherNode
		}
	}
	doc, err := sbom.DecodeSyftJSON(res.SyftJSON)
	if err != nil {
		return &sbom.AcquireError{Kind: sbom.FailCounted, Reason: "decoding SBOM", Err: err}
	}
	pkgs, cov := sbom.Normalize(r.Digest, doc)
	if err := f.st.PutSBOM(ctx, r.Digest, res.SyftJSON, pkgs); err != nil {
		return err
	}
	if err := f.st.UpsertImage(ctx, model.Image{Digest: r.Digest, Repo: r.Repo, Platform: r.Platform, Status: model.ImageCatalogued,
		Source: sbom.SourceAgent, Coverage: cov, CataloguedAt: t0}); err != nil {
		return err
	}
	if prov != nil {
		return f.st.PutAgentProvenance(ctx, *prov)
	}
	return nil
}

func (f *fakeIngest) setErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func (f *fakeIngest) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

type fakeOfferer struct {
	work  []wire.WorkRequest
	err   error
	calls []string
}

func (f *fakeOfferer) Offer(_ context.Context, node string) ([]wire.WorkRequest, error) {
	f.calls = append(f.calls, node)
	return f.work, f.err
}

// harness is an Ingester over a fresh store with fakes, counting triggers and host preparations.
type harness struct {
	st       *store.Store
	ing      *Ingester
	fake     *fakeIngest
	nodes    fakeNodes
	clk      *clock
	offer    *fakeOfferer
	cfg      config.NodeAgentConfig
	triggers int
	prepares int
}

func newHarness(t *testing.T, node *corev1.Node) *harness {
	t.Helper()
	st := newStore(t)
	h := &harness{st: st, fake: &fakeIngest{st: st}, nodes: fakeNodes{node.Name: node}, clk: newClock(t0), offer: &fakeOfferer{},
		cfg: config.Default().NodeAgent}
	h.ing = NewIngester(IngesterOptions{Store: st, Acquirer: h.fake, Nodes: h.nodes, Work: h.offer, Trigger: func() { h.triggers++ },
		Config: h.cfg, Now: h.clk.Now, Log: logr.Discard()})
	h.ing.prepare = func(r *wire.Report, n *corev1.Node, now time.Time) (hostPrep, error) {
		h.prepares++
		return prepareHost(r, n, now)
	}
	return h
}

func (h *harness) report(t *testing.T, r *wire.Report) wire.ReportResponse {
	t.Helper()
	resp, err := h.ing.Report(context.Background(), worker1, r)
	require.NoError(t, err)
	return resp
}

func (h *harness) agentNode(t *testing.T) store.AgentNode {
	t.Helper()
	rows, err := h.st.AgentNodes(context.Background())
	require.NoError(t, err)
	require.Len(t, rows, 1)
	return rows[0]
}

func (h *harness) group(t *testing.T, id string) model.NodeGroup {
	t.Helper()
	g, ok, err := h.st.NodeGroup(context.Background(), id)
	require.NoError(t, err)
	require.True(t, ok, "group %s stored", id)
	return g
}

func (h *harness) job(t *testing.T) (store.AgentJob, bool) {
	t.Helper()
	j, ok, err := h.st.AgentJobOf(context.Background(), "nodehost:worker-1")
	require.NoError(t, err)
	return j, ok
}

// fullReport is a full report from worker-1's agent process started at t0.
func fullReport(seq uint64, host *wire.Host, images *wire.Images, problems ...wire.Problem) *wire.Report {
	return &wire.Report{Node: "worker-1", AgentVersion: "v0.0.1", BootID: "boot-1", StartedAt: t0, Seq: seq, Kind: wire.KindFull,
		CollectedAt: t0, KernelRelease: runningKernel, Arch: "amd64", Host: host, Images: images, Problems: problems}
}

func imagesReport(seq uint64, images *wire.Images) *wire.Report {
	r := fullReport(seq, nil, images)
	r.Kind = wire.KindImages
	return r
}

// ubuntuDoc is an Ubuntu host with two installed kernels (7.0.0-34 running, 7.0.0-38 newer), openssl at
// opensslVersion and containerd.
func ubuntuDoc(t *testing.T, opensslVersion string) []byte {
	t.Helper()
	return syftDoc(t, ubuntu,
		debPkg("linux-image-7.0.0-34-generic", "7.0.0-34.34"),
		debPkg("linux-modules-7.0.0-34-generic", "7.0.0-34.34"),
		debPkg("linux-image-7.0.0-38-generic", "7.0.0-38.38"),
		debPkg("openssl", opensslVersion),
		goPkg("github.com/containerd/containerd/v2", "v2.2.1", "/usr/bin/containerd", "github.com/containerd/containerd/v2"))
}

func ubuntuHost(t *testing.T, opensslVersion string) *wire.Host {
	t.Helper()
	return &wire.Host{PackageDB: "dpkg", Binaries: []wire.Binary{{Name: "containerd", Path: "/usr/bin/containerd", Size: 1}},
		SyftJSON: ubuntuDoc(t, opensslVersion)}
}

// wantSplit computes the running-kernel split of a host document as the test expects it.
func wantSplit(t *testing.T, doc []byte, release string) nodegroup.KernelSplit {
	t.Helper()
	d, err := sbom.DecodeSyftJSON(doc)
	require.NoError(t, err)
	pkgs, _ := sbom.Normalize("nodegroup:pending", d)
	return nodegroup.SplitKernels(pkgs, release)
}

func wantFingerprint(t *testing.T, doc []byte, release string) string {
	t.Helper()
	split := wantSplit(t, doc, release)
	d, err := sbom.DecodeSyftJSON(doc)
	require.NoError(t, err)
	var distro *model.Distro
	if ld := d.Artifacts.LinuxDistribution; ld != nil {
		distro = &model.Distro{ID: ld.ID, VersionID: ld.VersionID, Codename: ld.VersionCodename}
	}
	return nodegroup.Fingerprint(nodegroup.FingerprintInput{Packages: split.Running, Distro: distro, Kernel: split.Kernel,
		KernelRelease: release, RuntimeVersion: "containerd://2.2.1"})
}

func TestIngest_NoPackageDatabaseIsCoverageGap(t *testing.T) {
	h := newHarness(t, testNode("worker-1", "Talos (v1.9.0)"))
	doc := syftDoc(t, nil, goPkg("github.com/containerd/containerd/v2", "v2.2.1", "/usr/local/bin/containerd", "github.com/containerd/containerd/v2"))
	r := fullReport(1, &wire.Host{PackageDB: "", Binaries: []wire.Binary{{Name: "containerd", Path: "/usr/local/bin/containerd", Size: 1}},
		SyftJSON: doc}, &wire.Images{ContentStore: true}, wire.Problem{Code: wire.ProblemNoPackageDB, Detail: "no dpkg, rpm or apk database found"})
	r.KernelRelease = "6.12.6-talos"
	require.True(t, h.report(t, r).Applied)

	gap := []model.NodeCoverageGap{{Code: "no_package_database", Detail: "no package database (image-based OS)"}}
	n := h.agentNode(t)
	require.Equal(t, gap, n.Coverage)
	require.Equal(t, 1, h.fake.count(), "never an empty clean set: the host's binaries are still stored")
	ingested, err := sbom.DecodeSyftJSON(h.fake.calls[0].res.SyftJSON)
	require.NoError(t, err)
	require.Equal(t, 1, ingested.Artifacts.Packages.PackageCount())
	require.NotEmpty(t, n.Fingerprint)
	g := h.group(t, n.Fingerprint)
	require.Empty(t, g.PackageDB)
	require.Equal(t, 1, g.PackageCount)
	require.Equal(t, "talos-1.9.0-k6.12.6", g.Name)
	require.Nil(t, g.Kernel)

	// The same gap without the problem: no package database and no permission problem.
	r = fullReport(2, &wire.Host{SyftJSON: doc}, &wire.Images{ContentStore: true})
	r.KernelRelease = "6.12.6-talos"
	h.report(t, r)
	require.Equal(t, gap, h.agentNode(t).Coverage)

	// An Ubuntu node whose package database the chart did not mount is not an image-based OS: its
	// os-release says Ubuntu.
	u := newHarness(t, testNode("worker-1", "Ubuntu 26.04 LTS"))
	ubuntuBins := syftDoc(t, ubuntu, goPkg("github.com/containerd/containerd/v2", "v2.2.1", "/usr/bin/containerd",
		"github.com/containerd/containerd/v2"))
	r = fullReport(1, &wire.Host{SyftJSON: ubuntuBins}, &wire.Images{ContentStore: true},
		wire.Problem{Code: wire.ProblemNoPackageDB, Detail: "no dpkg, rpm or apk database found"})
	require.True(t, u.report(t, r).Applied)
	require.Equal(t, []model.NodeCoverageGap{{Code: "no_package_database",
		Detail: "package database not mounted; set nodeAgent.packageDatabases"}}, u.agentNode(t).Coverage)
}

func TestIngest_OnlyRunningKernelIngested(t *testing.T) {
	h := newHarness(t, testNode("worker-1", "Ubuntu 26.04 LTS"))
	host := ubuntuHost(t, "3.0.13-0ubuntu3.5")
	require.True(t, h.report(t, fullReport(1, host, &wire.Images{ContentStore: true})).Applied)

	split := wantSplit(t, host.SyftJSON, runningKernel)
	fp := wantFingerprint(t, host.SyftJSON, runningKernel)
	require.Equal(t, 1, h.fake.count())
	call := h.fake.calls[0]
	require.Equal(t, sbom.Request{Repo: "host", Digest: "nodegroup:" + fp, Platform: "linux/amd64"}, call.req)
	require.Equal(t, "agent", call.res.Source)

	original, err := sbom.DecodeSyftJSON(host.SyftJSON)
	require.NoError(t, err)
	var removed artifact.ID
	for _, p := range original.Artifacts.Packages.Sorted() {
		if p.Name == "linux-image-7.0.0-38-generic" {
			removed = p.ID()
		}
	}
	require.NotEmpty(t, removed)
	related := false
	for _, rel := range original.Relationships {
		related = related || rel.From.ID() == removed
	}
	require.True(t, related, "the fixture relates the removed package")

	doc, err := sbom.DecodeSyftJSON(call.res.SyftJSON)
	require.NoError(t, err)
	for _, p := range doc.Artifacts.Packages.Sorted() {
		require.NotContains(t, p.Name, "7.0.0-38")
	}
	require.NotEmpty(t, doc.Relationships)
	for _, rel := range doc.Relationships {
		require.NotEqual(t, removed, rel.From.ID())
		require.NotEqual(t, removed, rel.To.ID())
	}

	n := h.agentNode(t)
	require.Equal(t, fp, n.Fingerprint)
	require.True(t, n.RebootPending)
	require.Equal(t, "installed kernel 7.0.0-38-generic is newer than the running kernel 7.0.0-34-generic", n.RebootReason)
	require.Equal(t, "dpkg", n.PackageDB)
	require.Empty(t, n.LastError)

	g := h.group(t, fp)
	require.Equal(t, model.NodeGroupAgent, g.Kind)
	require.Equal(t, "ubuntu-26.04-k7.0.0-34", g.Name)
	require.Equal(t, g.Name+"-"+fp[:6], g.Label)
	require.Equal(t, "nodegroup:"+fp, g.Digest)
	require.Equal(t, &model.Distro{ID: "ubuntu", VersionID: "26.04", Codename: "resolute"}, g.Distro)
	require.Equal(t, "Ubuntu 26.04 LTS", g.OSImage)
	require.Equal(t, "containerd://2.2.1", g.ContainerRuntimeVersion)
	require.Equal(t, "v1.37.1", g.KubeletVersion)
	require.Equal(t, runningKernel, g.KernelRelease)
	require.Equal(t, "amd64", g.Arch)
	require.Equal(t, "dpkg", g.PackageDB)
	require.Equal(t, len(split.Running), g.PackageCount)
	require.NotNil(t, g.Kernel)
	require.Equal(t, "linux-image-7.0.0-34-generic", g.Kernel.Package)
	require.Equal(t, []model.NodeBinary{{Name: "containerd", Path: "/usr/bin/containerd", Module: "github.com/containerd/containerd/v2",
		Version: "v2.2.1"}}, g.Binaries)
}

func TestIngest_DuplicateReportWritesNothing(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, testNode("worker-1", "Ubuntu 26.04 LTS"))
	first := fullReport(1, ubuntuHost(t, "3.0.13-0ubuntu3.5"), &wire.Images{ContentStore: true,
		Digests: []wire.CachedImage{{Digest: "sha256:aa", MediaType: "application/vnd.oci.image.manifest.v1+json", Size: 1, Complete: true}}})
	require.True(t, h.report(t, first).Applied)
	before, err := h.st.NodeImages(ctx, "worker-1")
	require.NoError(t, err)
	require.Len(t, before, 1)

	// A leftover host acquisition record: reaching the host gate would count it.
	_, err = h.st.BeginAcquire(ctx, "nodehost:worker-1", t0)
	require.NoError(t, err)
	dup := fullReport(1, ubuntuHost(t, "3.0.13-0ubuntu3.6"), &wire.Images{ContentStore: true,
		Digests: []wire.CachedImage{{Digest: "sha256:bb", MediaType: "application/vnd.oci.image.manifest.v1+json"}}})
	resp := h.report(t, dup)
	require.False(t, resp.Applied)
	require.Nil(t, resp.Work)
	require.Equal(t, WireConfig(h.cfg), resp.Config)

	require.Equal(t, 1, h.prepares, "the duplicate's host SBOM is never decoded")
	require.Equal(t, 1, h.fake.count())
	require.Equal(t, 1, h.triggers)
	require.Len(t, h.offer.calls, 1)
	_, ok := h.job(t)
	require.False(t, ok, "the duplicate never reached the host gate")
	after, err := h.st.NodeImages(ctx, "worker-1")
	require.NoError(t, err)
	require.Equal(t, before, after)
}

func TestIngest_KnownFingerprintSkipsIngest(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, testNode("worker-1", "Ubuntu 26.04 LTS"))
	host := ubuntuHost(t, "3.0.13-0ubuntu3.5")
	fp := wantFingerprint(t, host.SyftJSON, runningKernel)
	digest := nodegroup.GroupDigest(fp)
	require.NoError(t, h.st.PutSBOM(ctx, digest, host.SyftJSON, nil))
	require.NoError(t, h.st.UpsertImage(ctx, model.Image{Digest: digest, Repo: "host", Platform: "linux/amd64",
		Status: model.ImageCatalogued, Source: sbom.SourceAgent, CataloguedAt: t0}))
	_, ok, err := h.st.NodeGroup(ctx, fp)
	require.NoError(t, err)
	require.False(t, ok)

	require.True(t, h.report(t, fullReport(1, host, &wire.Images{ContentStore: true})).Applied)
	require.Zero(t, h.fake.count(), "a catalogued group SBOM is not ingested again")
	require.Equal(t, fp, h.agentNode(t).Fingerprint)
	h.group(t, fp) // the group row is put even when the digest was already catalogued
}

func TestIngest_FailedIngestKeepsCurrentGroup(t *testing.T) {
	h := newHarness(t, testNode("worker-1", "Ubuntu 26.04 LTS"))
	h.report(t, fullReport(1, ubuntuHost(t, "3.0.13-0ubuntu3.5"), &wire.Images{ContentStore: true}))
	fpOld := h.agentNode(t).Fingerprint
	require.NotEmpty(t, fpOld)

	h.fake.setErr(&sbom.AcquireError{Kind: sbom.FailCounted, Reason: "cataloguer exploded"})
	require.True(t, h.report(t, fullReport(2, ubuntuHost(t, "3.0.13-0ubuntu3.6"), &wire.Images{ContentStore: true})).Applied)
	n := h.agentNode(t)
	require.Equal(t, fpOld, n.Fingerprint, "the node stays on its current group")
	require.True(t, strings.HasPrefix(n.LastError, "host inventory not stored: "), n.LastError)

	h.fake.setErr(nil)
	h.report(t, fullReport(3, ubuntuHost(t, "3.0.13-0ubuntu3.6"), &wire.Images{ContentStore: true}))
	n = h.agentNode(t)
	require.Empty(t, n.LastError)
	require.NotEqual(t, fpOld, n.Fingerprint)
}

func TestIngest_UndecodableHostStillHeartbeats(t *testing.T) {
	h := newHarness(t, testNode("worker-1", "Ubuntu 26.04 LTS"))
	h.clk.Add(time.Minute)
	resp := h.report(t, fullReport(1, &wire.Host{PackageDB: "dpkg", SyftJSON: []byte(`"not a document"`)}, &wire.Images{ContentStore: true}))
	require.True(t, resp.Applied)
	n := h.agentNode(t)
	require.Equal(t, t0.Add(time.Minute), n.LastReport)
	require.Zero(t, h.fake.count())
	require.True(t, strings.HasPrefix(n.LastError, "host inventory could not be read: "), n.LastError)
	require.Empty(t, n.Fingerprint)
}

func TestIngest_ImagesMergeNodeStatus(t *testing.T) {
	ctx := context.Background()
	a, b, c := "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64), "sha256:"+strings.Repeat("c", 64)
	ca := "sha256:" + strings.Repeat("d", 64)
	node := testNode("worker-1", "Ubuntu 26.04 LTS",
		corev1.ContainerImage{Names: []string{"docker.io/library/nginx@" + a, "docker.io/library/nginx:1.30.6"}, SizeBytes: 70},
		corev1.ContainerImage{Names: []string{"registry.k8s.io/pause@" + c}, SizeBytes: 1},
		corev1.ContainerImage{Names: []string{"example.com/sideloaded:dev"}, SizeBytes: 9})
	h := newHarness(t, node)
	h.report(t, imagesReport(1, &wire.Images{ContentStore: true, Digests: []wire.CachedImage{
		{Digest: a, MediaType: "application/vnd.oci.image.manifest.v1+json", ConfigDigest: ca, Size: 70, Complete: true},
		{Digest: b, MediaType: "application/vnd.oci.image.index.v1+json", Manifests: []string{a}, Complete: false},
	}}))

	imgs, err := h.st.NodeImages(ctx, "worker-1")
	require.NoError(t, err)
	type row struct {
		Digest, Kind, ConfigDigest string
		Names                      []string
		Size                       int64
		Complete                   bool
		Source                     string
	}
	var got []row
	for _, img := range imgs {
		got = append(got, row{img.Digest, img.Kind, img.ConfigDigest, img.Names, img.SizeBytes, img.Complete, img.Source})
	}
	require.Equal(t, []row{
		{a, "manifest", ca, []string{"docker.io/library/nginx:1.30.6", "docker.io/library/nginx@" + a}, 70, true, "both"},
		{b, "index", "", nil, 0, false, "content-store"},
		{c, "manifest", "", []string{"registry.k8s.io/pause@" + c}, 1, false, "status"},
	}, got, "the tag-only status entry has no key and is not stored")

	h.report(t, imagesReport(2, nil))
	after, err := h.st.NodeImages(ctx, "worker-1")
	require.NoError(t, err)
	require.Equal(t, imgs, after, "an images report without Images leaves the rows")
}

func TestIngest_CoverageGapsFromProblems(t *testing.T) {
	h := newHarness(t, testNode("worker-1", "Ubuntu 26.04 LTS"))
	contentStore := model.NodeCoverageGap{Code: "content_store_unreadable",
		Detail: "no containerd content store on this node; side-loaded images cannot be catalogued from it"}

	h.report(t, fullReport(1, nil, &wire.Images{ContentStore: false}))
	require.Equal(t, []model.NodeCoverageGap{contentStore}, h.agentNode(t).Coverage)
	h.report(t, fullReport(2, nil, nil))
	require.Equal(t, []model.NodeCoverageGap{contentStore}, h.agentNode(t).Coverage, "carried over while Images is absent")
	h.report(t, fullReport(3, nil, &wire.Images{ContentStore: true}))
	require.Empty(t, h.agentNode(t).Coverage)

	h.report(t, fullReport(4, nil, &wire.Images{ContentStore: true},
		wire.Problem{Code: "permission_denied", Path: "/var/lib/rpm", Detail: "open /host/var/lib/rpm: permission denied"}))
	n := h.agentNode(t)
	require.Equal(t, []model.NodeCoverageGap{{Code: "node_agent_blocked", Detail: "node agent cannot read /var/lib/rpm: permission denied"}}, n.Coverage)
	require.Equal(t, []string{"/var/lib/rpm: open /host/var/lib/rpm: permission denied"}, n.Problems)

	doc := syftDoc(t, nil, goPkg("github.com/containerd/containerd/v2", "v2.2.1", "/usr/bin/containerd", "github.com/containerd/containerd/v2"))
	h.report(t, fullReport(5, &wire.Host{PackageDB: "", SyftJSON: doc}, &wire.Images{ContentStore: true},
		wire.Problem{Code: "permission_denied", Path: "/var/lib/dpkg/status", Detail: "permission denied"}))
	require.Equal(t, []model.NodeCoverageGap{{Code: "node_agent_blocked", Detail: "node agent cannot read /var/lib/dpkg/status: permission denied"}},
		h.agentNode(t).Coverage, "a denied package database is not an image-based OS")
}

func TestIngest_GroupRowSurvivesConcurrentGrouping(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, testNode("worker-1", "Ubuntu 26.04 LTS"))
	h.fake.during = func() {
		// A reconcile pass landing mid-report.
		require.NoError(t, h.st.ApplyNodeGrouping(ctx, store.NodeGrouping{Now: t0}))
	}
	host := ubuntuHost(t, "3.0.13-0ubuntu3.5")
	h.report(t, fullReport(1, host, &wire.Images{ContentStore: true}))
	fp := wantFingerprint(t, host.SyftJSON, runningKernel)
	h.group(t, fp)
	require.Equal(t, fp, h.agentNode(t).Fingerprint)

	// A pass after the report keeps the row: the node's fingerprint names it.
	require.NoError(t, h.st.ApplyNodeGrouping(ctx, store.NodeGrouping{Now: t0}))
	h.group(t, fp)
}

func TestIngest_HostPoisonPill(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, testNode("worker-1", "Ubuntu 26.04 LTS"))
	h.fake.setErr(&sbom.AcquireError{Kind: sbom.FailTransient, Reason: "an acquisition of the image is in progress"})

	_, err := h.st.BeginAcquire(ctx, "nodehost:worker-1", t0) // left by a controller that stopped
	require.NoError(t, err)
	h.report(t, fullReport(1, ubuntuHost(t, "3.0.13-0ubuntu3.5"), &wire.Images{ContentStore: true}))
	job, ok := h.job(t)
	require.True(t, ok)
	require.Equal(t, 1, job.Attempts)
	require.True(t, job.QuarantinedUntil.IsZero())
	require.Equal(t, 1, h.prepares)
	require.Equal(t, 1, h.fake.count(), "one stale record is counted, and the host is still processed")

	_, err = h.st.BeginAcquire(ctx, "nodehost:worker-1", t0)
	require.NoError(t, err)
	h.report(t, fullReport(2, ubuntuHost(t, "3.0.13-0ubuntu3.5"), &wire.Images{ContentStore: true}))
	job, _ = h.job(t)
	require.Equal(t, 2, job.Attempts)
	require.Equal(t, t0.Add(24*time.Hour), job.QuarantinedUntil)

	h.clk.Add(time.Hour)
	resp := h.report(t, fullReport(3, ubuntuHost(t, "3.0.13-0ubuntu3.5"), &wire.Images{ContentStore: true}))
	require.True(t, resp.Applied, "a quarantined host's report is still a heartbeat")
	require.Equal(t, 1, h.prepares, "a quarantined host is never decoded")
	require.Equal(t, 1, h.fake.count())
	n := h.agentNode(t)
	require.Equal(t, t0.Add(time.Hour), n.LastReport)
	require.True(t, strings.HasPrefix(n.LastError, "host inventory quarantined until "), n.LastError)

	t.Run("ingest failures", func(t *testing.T) {
		h := newHarness(t, testNode("worker-1", "Ubuntu 26.04 LTS"))
		h.fake.setErr(&sbom.AcquireError{Kind: sbom.FailTransient, Reason: "busy"})
		h.report(t, fullReport(1, ubuntuHost(t, "3.0.13-0ubuntu3.5"), &wire.Images{ContentStore: true}))
		_, ok := h.job(t)
		require.False(t, ok, "a transient failure is never counted")

		h.fake.setErr(&sbom.AcquireError{Kind: sbom.FailCounted, Reason: "decoding SBOM"})
		h.report(t, fullReport(2, ubuntuHost(t, "3.0.13-0ubuntu3.5"), &wire.Images{ContentStore: true}))
		job, ok := h.job(t)
		require.True(t, ok)
		require.Equal(t, 1, job.Attempts)
		require.True(t, job.QuarantinedUntil.IsZero())

		h.fake.setErr(nil)
		h.report(t, fullReport(3, ubuntuHost(t, "3.0.13-0ubuntu3.5"), &wire.Images{ContentStore: true}))
		_, ok = h.job(t)
		require.False(t, ok, "a successful host ingest clears the record")

		h.fake.setErr(&sbom.AcquireError{Kind: sbom.FailQuarantine, Reason: "SBOM too large"})
		h.report(t, fullReport(4, ubuntuHost(t, "3.0.13-0ubuntu3.6"), &wire.Images{ContentStore: true}))
		job, ok = h.job(t)
		require.True(t, ok)
		require.Equal(t, 1, job.Attempts)
		require.Equal(t, t0.Add(24*time.Hour), job.QuarantinedUntil, "an oversized SBOM quarantines at once")
	})
}

// requireHostReleased asserts that the Ingester holds nothing for worker-1's host: every slot is free, the node
// is not busy and its acquisition record is ended.
func (h *harness) requireHostReleased(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	require.True(t, h.ing.slots.TryAcquire(hostConcurrency), "every host slot is free")
	h.ing.slots.Release(hostConcurrency)
	h.ing.mu.Lock()
	busy := h.ing.busy["worker-1"]
	h.ing.mu.Unlock()
	require.False(t, busy, "the node is not left busy")
	stale, err := h.st.BeginAcquire(ctx, "nodehost:worker-1", h.clk.Now())
	require.NoError(t, err)
	require.False(t, stale, "the host acquisition record is ended")
	require.NoError(t, h.st.EndAcquire(ctx, "nodehost:worker-1"))
}

func TestIngest_PreparePanicReleasesAndCounts(t *testing.T) {
	h := newHarness(t, testNode("worker-1", "Ubuntu 26.04 LTS"))
	h.ing.prepare = func(*wire.Report, *corev1.Node, time.Time) (hostPrep, error) {
		h.prepares++
		panic("decoder blew up")
	}

	resp := h.report(t, fullReport(1, ubuntuHost(t, "3.0.13-0ubuntu3.5"), &wire.Images{ContentStore: true}))
	require.True(t, resp.Applied, "a report whose host panics is still a heartbeat")
	h.requireHostReleased(t)
	job, ok := h.job(t)
	require.True(t, ok)
	require.Equal(t, 1, job.Attempts)
	require.Equal(t, "preparing the host inventory: panic: decoder blew up", job.LastError)
	require.True(t, job.QuarantinedUntil.IsZero())
	require.Equal(t, "host inventory could not be read: panic: decoder blew up", h.agentNode(t).LastError)
	require.Zero(t, h.fake.count())

	h.report(t, fullReport(2, ubuntuHost(t, "3.0.13-0ubuntu3.5"), &wire.Images{ContentStore: true}))
	require.Equal(t, 2, h.prepares, "the next report's host is processed")
	h.requireHostReleased(t)
	job, _ = h.job(t)
	require.Equal(t, 2, job.Attempts)
	require.Equal(t, t0.Add(24*time.Hour), job.QuarantinedUntil, "a second panic quarantines the host")

	h.report(t, fullReport(3, ubuntuHost(t, "3.0.13-0ubuntu3.5"), &wire.Images{ContentStore: true}))
	require.Equal(t, 2, h.prepares, "a quarantined host is never decoded")
	require.True(t, strings.HasPrefix(h.agentNode(t).LastError, "host inventory quarantined until "), h.agentNode(t).LastError)
}

func TestIngest_IngestPanicIsCounted(t *testing.T) {
	h := newHarness(t, testNode("worker-1", "Ubuntu 26.04 LTS"))
	h.fake.during = func() { panic("acquirer blew up") }

	resp := h.report(t, fullReport(1, ubuntuHost(t, "3.0.13-0ubuntu3.5"), &wire.Images{ContentStore: true}))
	require.True(t, resp.Applied)
	h.requireHostReleased(t)
	job, ok := h.job(t)
	require.True(t, ok)
	require.Equal(t, 1, job.Attempts)
	require.True(t, job.QuarantinedUntil.IsZero())
	n := h.agentNode(t)
	require.Equal(t, "host inventory not stored: storing the host inventory panicked: acquirer blew up", n.LastError)
	require.Empty(t, n.Fingerprint)
}

func TestIngest_HostGateErrorReleasesNode(t *testing.T) {
	h := newHarness(t, testNode("worker-1", "Ubuntu 26.04 LTS"))
	require.NoError(t, h.ing.slots.Acquire(context.Background(), hostConcurrency)) // every slot is taken
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	// The report waits for a slot until its deadline (or, on a very slow machine, fails at an earlier store
	// call): either way it fails without leaving the node busy or its record open.
	_, err := h.ing.Report(ctx, worker1, fullReport(1, ubuntuHost(t, "3.0.13-0ubuntu3.5"), &wire.Images{ContentStore: true}))
	require.Error(t, err)
	h.ing.slots.Release(hostConcurrency)
	h.requireHostReleased(t)
	require.Zero(t, h.prepares)

	h.report(t, fullReport(1, ubuntuHost(t, "3.0.13-0ubuntu3.5"), &wire.Images{ContentStore: true}))
	require.Equal(t, 1, h.prepares)
	require.NotEmpty(t, h.agentNode(t).Fingerprint)
}

func TestIngest_KeepsRebootSignalWithoutHost(t *testing.T) {
	h := newHarness(t, testNode("worker-1", "Ubuntu 26.04 LTS"))
	h.report(t, fullReport(1, ubuntuHost(t, "3.0.13-0ubuntu3.5"), &wire.Images{ContentStore: true}))
	want := h.agentNode(t)
	require.True(t, want.RebootPending)

	for seq, host := range map[uint64]*wire.Host{
		2: nil,
		3: {PackageDB: "dpkg", SyftJSON: []byte(`"not a document"`)},
	} {
		h.report(t, fullReport(seq, host, &wire.Images{ContentStore: true}))
		n := h.agentNode(t)
		require.True(t, n.RebootPending, "seq %d", seq)
		require.Equal(t, want.RebootReason, n.RebootReason, "seq %d", seq)
		require.Equal(t, "dpkg", n.PackageDB, "seq %d", seq)
	}
}

func TestIngest_CanonicalisesForkModules(t *testing.T) {
	h := newHarness(t, testNode("worker-1", "Ubuntu 26.04 LTS"))
	fork := goPkg("github.com/k3s-io/containerd/v2", "v2.1.4-k3s2", "/usr/local/bin/k3s", "github.com/k3s-io/k3s")
	require.Equal(t, "pkg:golang/github.com/k3s-io/containerd/v2@v2.1.4-k3s2", fork.PURL)
	doc := syftDoc(t, ubuntu, debPkg("openssl", "3.0.13-0ubuntu3.5"), fork)
	original, err := sbom.DecodeSyftJSON(doc)
	require.NoError(t, err)
	var forkID artifact.ID
	for _, p := range original.Artifacts.Packages.Sorted(pkg.GoModulePkg) {
		forkID = p.ID()
	}

	h.report(t, fullReport(1, &wire.Host{PackageDB: "dpkg", SyftJSON: doc}, &wire.Images{ContentStore: true}))
	require.Equal(t, 1, h.fake.count())
	ingested, err := sbom.DecodeSyftJSON(h.fake.calls[0].res.SyftJSON)
	require.NoError(t, err)
	mods := ingested.Artifacts.Packages.Sorted(pkg.GoModulePkg)
	require.Len(t, mods, 1)
	require.Equal(t, "github.com/containerd/containerd/v2", mods[0].Name)
	require.Equal(t, "v2.1.4", mods[0].Version)
	require.Equal(t, "pkg:golang/github.com/containerd/containerd/v2@v2.1.4", mods[0].PURL)
	require.Equal(t, forkID, mods[0].ID(), "the artifact ID is kept")
	for _, p := range ingested.Artifacts.Packages.Sorted() {
		require.NotContains(t, p.Name, "k3s-io/containerd")
	}
}

func TestIngest_RejectsUnknownNodeAndBadKind(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, testNode("worker-1", "Ubuntu 26.04 LTS"))
	r := fullReport(1, nil, &wire.Images{ContentStore: true})
	r.Node = "worker-9"
	_, err := h.ing.Report(ctx, Identity{Node: "worker-9"}, r)
	require.ErrorIs(t, err, ErrForbidden)
	require.EqualError(t, err, "agentapi: forbidden: node worker-9 is not in the cluster")
	rows, err := h.st.AgentNodes(ctx)
	require.NoError(t, err)
	require.Empty(t, rows)

	r = fullReport(1, nil, nil)
	r.Kind = "partial"
	_, err = h.ing.Report(ctx, worker1, r)
	require.ErrorIs(t, err, ErrBadRequest)
}

func TestIngest_TriggersAndOffers(t *testing.T) {
	h := newHarness(t, testNode("worker-1", "Ubuntu 26.04 LTS"))
	h.offer.work = []wire.WorkRequest{{ID: "w1", Digest: "sha256:aa", Platform: "linux/amd64", Deadline: t0.Add(30 * time.Minute)}}
	resp := h.report(t, imagesReport(1, nil))
	require.True(t, resp.Applied)
	require.Equal(t, 1, h.triggers)
	require.Equal(t, []string{"worker-1"}, h.offer.calls)
	require.Equal(t, h.offer.work, resp.Work)
	require.Equal(t, WireConfig(h.cfg), resp.Config)

	h.offer.err = errors.New("store busy")
	resp = h.report(t, imagesReport(2, nil))
	require.True(t, resp.Applied, "an offer failure does not fail the report")
	require.Nil(t, resp.Work)
	require.Equal(t, 2, h.triggers)
}

func TestIngest_CountsAppliedAndDuplicate(t *testing.T) {
	count := func(result string) float64 { return testutil.ToFloat64(metrics.AgentReports.WithLabelValues(result)) }
	h := newHarness(t, testNode("worker-1", "Ubuntu 26.04 LTS"))
	applied, duplicate := count(metrics.AgentReportApplied), count(metrics.AgentReportDuplicate)

	require.True(t, h.report(t, imagesReport(1, nil)).Applied)
	require.Equal(t, applied+1, count(metrics.AgentReportApplied))
	require.Equal(t, duplicate, count(metrics.AgentReportDuplicate))

	require.False(t, h.report(t, imagesReport(1, nil)).Applied)
	require.Equal(t, applied+1, count(metrics.AgentReportApplied))
	require.Equal(t, duplicate+1, count(metrics.AgentReportDuplicate))
}
