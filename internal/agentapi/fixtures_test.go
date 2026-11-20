package agentapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	syftsbom "github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/engine"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/nodegroup"
	"github.com/the-it-dept/ffs/internal/sbom"
	"github.com/the-it-dept/ffs/internal/store"
)

var t0 = time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)

// clock is a settable test clock.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock(at time.Time) *clock { return &clock{now: at} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "ffs.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	return st
}

// syftDoc is a host syft-json document of pkgs (each given its ID), with one evident-by relationship from each
// package to its first location, as the cataloguer produces.
func syftDoc(t *testing.T, distro *linux.Release, pkgs ...pkg.Package) []byte {
	t.Helper()
	var rels []artifact.Relationship
	for i := range pkgs {
		pkgs[i].SetID()
		if locs := pkgs[i].Locations.ToSlice(); len(locs) > 0 {
			rels = append(rels, artifact.Relationship{From: pkgs[i], To: locs[0].Coordinates, Type: artifact.EvidentByRelationship})
		}
	}
	doc := &syftsbom.SBOM{
		Artifacts:     syftsbom.Artifacts{Packages: pkg.NewCollection(pkgs...), LinuxDistribution: distro},
		Relationships: rels,
		Source:        source.Description{ID: "host", Name: "host", Metadata: source.DirectoryMetadata{Path: "/"}},
		Descriptor:    syftsbom.Descriptor{Name: "syft", Version: "1.57.2"},
	}
	b, err := sbom.EncodeSyftJSON(doc)
	require.NoError(t, err)
	return b
}

// debPkg is a dpkg package of the host.
func debPkg(name, version string) pkg.Package {
	return pkg.Package{Name: name, Version: version, Type: pkg.DebPkg, PURL: "pkg:deb/ubuntu/" + name + "@" + version,
		Locations: file.NewLocationSet(file.NewLocation("/var/lib/dpkg/status")),
		Metadata:  pkg.DpkgDBEntry{Package: name, Version: version, Architecture: "amd64"}}
}

// goPkg is a Go module found in the binary at path, whose main module is mainModule.
func goPkg(name, version, path, mainModule string) pkg.Package {
	return pkg.Package{Name: name, Version: version, Type: pkg.GoModulePkg, PURL: "pkg:golang/" + name + "@" + version,
		Locations: file.NewLocationSet(file.NewLocation(path)),
		Metadata:  pkg.GolangBinaryBuildinfoEntry{MainModule: mainModule, GoCompiledVersion: "go1.25.4", Architecture: "amd64"}}
}

// agentPod is a running pod on node whose containers report imageIDs.
func agentPod(ns, name, uid, node string, imageIDs ...string) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID(uid)},
		Spec:       corev1.PodSpec{NodeName: node, Containers: []corev1.Container{{Name: "c", Image: "example"}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	for i, id := range imageIDs {
		p.Status.ContainerStatuses = append(p.Status.ContainerStatuses, corev1.ContainerStatus{
			Name: "c" + string(rune('0'+i)), ImageID: id, Ready: true})
	}
	return p
}

// writeCert writes a self-signed ECDSA P-256 certificate for localhost with the given serial to dir as
// tls.crt and tls.key. Both files get an mtime derived from the serial, so each pair is told apart.
func writeCert(t *testing.T, dir string, serial int64) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	kd, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	at := time.Unix(1_800_000_000+serial, 0)
	for name, b := range map[string][]byte{
		"tls.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		"tls.key": pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}),
	} {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, b, 0o600))
		require.NoError(t, os.Chtimes(p, at, at))
	}
}

// reviewer is a client whose TokenReview Create records each spec and answers with answer's status, or
// fails with its error.
func reviewer(t *testing.T, answer func(spec authenticationv1.TokenReviewSpec) (authenticationv1.TokenReviewStatus, error),
) (client.Client, *[]authenticationv1.TokenReviewSpec) {
	t.Helper()
	var (
		mu    sync.Mutex
		specs []authenticationv1.TokenReviewSpec
	)
	c := fake.NewClientBuilder().WithInterceptorFuncs(interceptor.Funcs{
		Create: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.CreateOption) error {
			tr := obj.(*authenticationv1.TokenReview)
			mu.Lock()
			specs = append(specs, tr.Spec)
			mu.Unlock()
			st, err := answer(tr.Spec)
			if err != nil {
				return err
			}
			tr.Status = st
			return nil
		},
	}).Build()
	return c, &specs
}

// fakePods is a PodIndex: node → the digests its pods run.
type fakePods struct {
	mu    sync.Mutex
	nodes map[string]map[string]bool
}

func newFakePods() *fakePods { return &fakePods{nodes: map[string]map[string]bool{}} }

// run records that a pod on node runs each digest.
func (f *fakePods) run(node string, digests ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.nodes[node] == nil {
		f.nodes[node] = map[string]bool{}
	}
	for _, d := range digests {
		f.nodes[node][d] = true
	}
}

func (f *fakePods) DigestsOnNode(_ context.Context, node string) (map[string]bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]bool{}
	for d := range f.nodes[node] {
		out[d] = true
	}
	return out, nil
}

// hexDigest is a sha256 digest whose hex is c repeated.
func hexDigest(c string) string { return "sha256:" + strings.Repeat(c, 64) }

// testCluster is the cluster name of the reconciler tests.
const testCluster = "test"

// Host fingerprints of the reconciler tests' agent groups.
var (
	grpA, grpB, grpC = strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	testNodesKey     = model.NodesOwner(testCluster).Key()
)

// hostPkg is a package of the host SBOM stored under digest.
func hostPkg(digest, ecosystem, name, version, path string) model.Package {
	p := model.Package{ImageDigest: digest, Ecosystem: ecosystem, Name: name, Version: version, Path: path}
	if ecosystem == "deb" {
		p.Distro, p.Arch, p.SourceName = &model.Distro{ID: "ubuntu", VersionID: "26.04"}, "amd64", name
	}
	p.ID = model.PackageID(digest, p)
	return p
}

// seedGroup stores agent group id (arch amd64) with its host SBOM catalogued from the agent and matched.
// Each package's ImageDigest must be the group's digest.
func seedGroup(t *testing.T, st *store.Store, id string, pkgs ...model.Package) model.NodeGroup {
	t.Helper()
	ctx := context.Background()
	name := "ubuntu-26.04-k7.0.0-34"
	g := model.NodeGroup{ID: id, Kind: model.NodeGroupAgent, Name: name, Label: nodegroup.GroupLabel(name, id),
		Digest: nodegroup.GroupDigest(id), Distro: &model.Distro{ID: "ubuntu", VersionID: "26.04"}, OSImage: "Ubuntu 26.04 LTS",
		KernelRelease: runningKernel, ContainerRuntimeVersion: "containerd://2.2.1", KubeletVersion: "v1.37.1", Arch: "amd64",
		PackageDB: "dpkg", PackageCount: len(pkgs)}
	require.NoError(t, st.PutNodeGroup(ctx, g, t0))
	require.NoError(t, st.UpsertImage(ctx, model.Image{Digest: g.Digest, Repo: model.HostRepo, Platform: "linux/amd64",
		Status: model.ImageCatalogued, Source: sbom.SourceAgent, CataloguedAt: t0}))
	require.NoError(t, st.PutSBOM(ctx, g.Digest, []byte(`{"artifacts":[]}`), pkgs))
	return g
}

// seedMatch stores grype's match of pkg on advisory, fixed in fixed, and the advisory.
func seedMatch(t *testing.T, st *store.Store, pkg model.Package, advisory, fixed string) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, st.UpsertAdvisory(ctx, model.Advisory{ID: advisory, Title: advisory, Published: t0.Add(-48 * time.Hour),
		Observed: t0.Add(-24 * time.Hour), CNASeverity: model.SeverityHigh, CNASource: "github"}))
	m := model.Match{ImageDigest: pkg.ImageDigest, PackageID: pkg.ID, AdvisoryID: advisory, Source: model.SourceGrype,
		FixState: model.FixFixed, FixedVersions: []string{fixed}, VendorSeverity: model.SeverityHigh,
		VendorSeveritySource: "github", DBBuilt: t0.Add(-time.Hour)}
	_, err := st.ReplaceMatches(ctx, store.MatchScope{Source: model.SourceGrype, Digests: []string{pkg.ImageDigest},
		AdvisoryIDs: []string{advisory}}, []model.Match{m})
	require.NoError(t, err)
}

// report accepts a full report from node's agent at at, the next in its sequence.
func report(t *testing.T, st *store.Store, node string, at time.Time) {
	t.Helper()
	ctx := context.Background()
	rows, err := st.AgentNodes(ctx)
	require.NoError(t, err)
	var seq uint64
	for _, r := range rows {
		if r.Node == node {
			seq = r.Seq
		}
	}
	applied, err := st.AcceptAgentReport(ctx, store.AgentReport{Node: node, AgentVersion: "v0.0.1", BootID: "boot-" + node,
		StartedAt: t0.Add(-time.Hour), Seq: seq + 1, At: at, Full: true, KernelRelease: runningKernel, Arch: "amd64", PackageDB: "dpkg"})
	require.NoError(t, err)
	require.True(t, applied)
}

// countMarker counts MarkCluster calls.
type countMarker struct {
	mu sync.Mutex
	n  int
}

func (c *countMarker) MarkCluster() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
}

func (c *countMarker) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// recFixture is a Reconciler over a fresh store and a fake client holding nodes.
type recFixture struct {
	st     *store.Store
	cl     client.Client
	pods   *fakePods
	marker *countMarker
	clk    *clock
	cfg    config.Config
	eng    *engine.Engine // the real engine, when the reconciler uses it
	rec    *Reconciler
}

// newRecFixture holds nodes, by default worker-1, worker-2 and cp-1, all Ready. With rh nil the reconciler
// uses a real engine over the store.
func newRecFixture(t *testing.T, rh Rehomer, nodes ...*corev1.Node) *recFixture {
	t.Helper()
	if len(nodes) == 0 {
		nodes = []*corev1.Node{testNode("worker-1", "Ubuntu 26.04 LTS"), testNode("worker-2", "Ubuntu 26.04 LTS"),
			testNode("cp-1", "Ubuntu 26.04 LTS")}
	}
	objs := make([]client.Object, len(nodes))
	for i, n := range nodes {
		objs[i] = n
	}
	f := &recFixture{st: newStore(t), cl: fake.NewClientBuilder().WithObjects(objs...).Build(), pods: newFakePods(),
		marker: &countMarker{}, clk: newClock(t0), cfg: config.Default()}
	f.cfg.ClusterName = testCluster
	if rh == nil {
		f.eng = engine.New(engine.Options{Config: f.cfg, Store: f.st, Now: f.clk.Now, Log: logr.Discard()})
		rh = f.eng
	}
	f.rec = NewReconciler(ReconcilerOptions{Store: f.st, Engine: rh, Inventory: f.marker, Nodes: f.cl, Pods: f.pods,
		Config: f.cfg, Now: f.clk.Now, Log: logr.Discard()})
	return f
}

// setConfig changes the reconciler's configuration.
func (f *recFixture) setConfig(change func(c *config.Config)) {
	change(&f.cfg)
	f.rec.o.Config = f.cfg
}

// pass runs one reconcile pass and, with the real engine, drains its queue.
func (f *recFixture) pass(t *testing.T) {
	t.Helper()
	require.NoError(t, f.rec.ReconcileOnce(context.Background()))
	f.drain(t)
}

func (f *recFixture) drain(t *testing.T) {
	t.Helper()
	if f.eng != nil {
		require.NoError(t, f.eng.Drain(context.Background()))
	}
}

func (f *recFixture) state(t *testing.T) store.NodesState {
	t.Helper()
	s, err := f.st.NodesState(context.Background())
	require.NoError(t, err)
	return s
}

func (f *recFixture) groupOf(t *testing.T, node string) model.NodeGroup {
	t.Helper()
	g, ok, err := f.st.NodeGroupOfNode(context.Background(), node)
	require.NoError(t, err)
	require.True(t, ok, "%s has a group", node)
	return g
}

func (f *recFixture) fingerprint(t *testing.T, node, fp string) {
	t.Helper()
	require.NoError(t, f.st.SetAgentFingerprint(context.Background(), node, fp))
}

func (f *recFixture) maxTransition(t *testing.T) int64 {
	t.Helper()
	id, err := f.st.MaxTransitionID(context.Background())
	require.NoError(t, err)
	return id
}

func (f *recFixture) transitionsAfter(t *testing.T, mark int64) []model.Transition {
	t.Helper()
	ts, err := f.st.TransitionsAfter(context.Background(), mark, 0)
	require.NoError(t, err)
	return ts
}

// findings returns the owner's findings by advisory.
func (f *recFixture) findings(t *testing.T, key string) map[string]model.Finding {
	t.Helper()
	fs, err := f.st.FindingsForOwner(context.Background(), key)
	require.NoError(t, err)
	out := map[string]model.Finding{}
	for _, x := range fs {
		out[x.AdvisoryID] = x
	}
	return out
}
