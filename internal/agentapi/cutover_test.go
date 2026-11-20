package agentapi

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/nodegroup"
)

const (
	rtDigest      = "runtime:containerd@2.2.1"
	containerdV2  = "github.com/containerd/containerd/v2"
	runcModule    = "github.com/opencontainers/runc"
	cveContainerd = "CVE-2026-0002"
	cveRunc       = "CVE-2026-0003"
	cveHostOnly   = "CVE-2026-0001"
)

var rtRef = model.OwnerRef{Kind: model.OwnerKindContainerRuntime, Name: "containerd"}

// cutoverFixture is the cutover fixture: the ContainerRuntime owner on runtime:containerd@2.2.1 and group A,
// both holding containerd v2.2.1 matched by CVE-2026-0002; group A also holds runc and openssl. The runtime
// owner's finding is stored; the Nodes owner is not yet.
type cutoverFixture struct {
	*recFixture
	rtOwner              model.Owner
	runcPkg, opensslPkg  model.Package
	fpRT, fpNodes, fpRun string
}

func newCutoverFixture(t *testing.T, nodes ...*corev1.Node) *cutoverFixture {
	t.Helper()
	ctx := context.Background()
	if len(nodes) == 0 {
		nodes = []*corev1.Node{testNode("worker-1", "Ubuntu 26.04 LTS")}
	}
	x := &cutoverFixture{recFixture: newRecFixture(t, nil, nodes...)}
	st := x.st
	x.rtOwner = model.Owner{Ref: rtRef, Containers: []model.ContainerUse{{Name: "containerd", Kind: model.ContainerRegular,
		ImageRef: "containerd://2.2.1", Repo: "containerd", Digest: rtDigest}}}
	rtPkg := hostPkg(rtDigest, "go-module", containerdV2, "v2.2.1", "/usr/bin/containerd")
	require.NoError(t, st.UpsertImage(ctx, model.Image{Digest: rtDigest, Repo: "containerd", Platform: "linux/amd64",
		Status: model.ImageCatalogued, Source: "registry", CataloguedAt: t0}))
	require.NoError(t, st.PutSBOM(ctx, rtDigest, []byte(`{"artifacts":[]}`), []model.Package{rtPkg}))
	seedMatch(t, st, rtPkg, cveContainerd, "2.2.2")

	digest := nodegroup.GroupDigest(grpA)
	grpPkg := hostPkg(digest, "go-module", containerdV2, "v2.2.1", "/usr/bin/containerd")
	x.runcPkg = hostPkg(digest, "go-module", runcModule, "v1.3.0", "/usr/bin/runc")
	x.opensslPkg = hostPkg(digest, "deb", "openssl", "3.0.13-0ubuntu1", "")
	seedGroup(t, st, grpA, grpPkg, x.runcPkg, x.opensslPkg)
	seedMatch(t, st, grpPkg, cveContainerd, "2.2.2")

	require.NoError(t, st.UpsertOwner(ctx, x.rtOwner))
	require.NoError(t, x.eng.Recompute(ctx, []string{rtRef.Key()}, model.TriggerInventoryChange))
	x.fpRT = model.FindingFingerprint(testCluster, rtRef, "containerd", cveContainerd)
	x.fpNodes = model.FindingFingerprint(testCluster, model.NodesOwner(testCluster), model.HostRepo, cveContainerd)
	x.fpRun = model.FindingFingerprint(testCluster, model.NodesOwner(testCluster), model.HostRepo, cveRunc)
	require.Equal(t, x.fpRT, x.findings(t, rtRef.Key())[cveContainerd].Fingerprint)

	report(t, st, "worker-1", t0)
	x.fingerprint(t, "worker-1", grpA)
	return x
}

// restoreRuntimeOwner does what inventory does after MarkCluster on a back cutover: it stores the
// ContainerRuntime owner again and announces it.
func (x *cutoverFixture) restoreRuntimeOwner(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, x.st.UpsertOwner(ctx, x.rtOwner))
	require.NoError(t, x.eng.OnOwnersChanged(ctx, []string{rtRef.Key()}))
	x.drain(t)
}

func (x *cutoverFixture) runtimeOwnerStored(t *testing.T) bool {
	t.Helper()
	_, ok, err := x.st.GetOwner(context.Background(), rtRef.Key())
	require.NoError(t, err)
	return ok
}

// requireForward asserts the containerd finding is on the Nodes owner and the runtime owner is retired.
func (x *cutoverFixture) requireForward(t *testing.T) {
	t.Helper()
	f, ok := x.findings(t, testNodesKey)[cveContainerd]
	require.True(t, ok)
	require.Equal(t, x.fpNodes, f.Fingerprint)
	require.Equal(t, model.StateOpen, f.State)
	require.False(t, x.runtimeOwnerStored(t))
	require.True(t, x.state(t).RuntimeRetired)
}

// requireBack asserts the containerd finding is back on the ContainerRuntime owner.
func (x *cutoverFixture) requireBack(t *testing.T) {
	t.Helper()
	f, ok := x.findings(t, rtRef.Key())[cveContainerd]
	require.True(t, ok)
	require.Equal(t, x.fpRT, f.Fingerprint)
	require.Equal(t, model.StateOpen, f.State)
	_, ok = x.findings(t, testNodesKey)[cveContainerd]
	require.False(t, ok)
	require.False(t, x.state(t).RuntimeRetired)
}

func TestCutover_GraceAndRehomeEmitNoTransitions(t *testing.T) {
	ctx := context.Background()
	x := newCutoverFixture(t)
	mark := x.maxTransition(t)

	// Every Ready node is fresh: forward.
	x.pass(t)
	x.requireForward(t)
	require.Equal(t, 1, x.marker.count())
	require.Empty(t, x.transitionsAfter(t, mark))

	// The report goes stale: retired still, until runtimeGrace has passed.
	x.clk.Add(31 * time.Minute)
	x.pass(t)
	require.True(t, x.state(t).RuntimeRetired)
	require.Equal(t, x.clk.Now(), x.state(t).NotFreshSince)
	x.clk.Add(time.Hour)
	x.pass(t)
	require.True(t, x.state(t).RuntimeRetired)
	require.Equal(t, 1, x.marker.count())

	// Grace (2h) reached: back.
	x.clk.Add(time.Hour)
	x.pass(t)
	x.requireBack(t)
	require.Equal(t, 2, x.marker.count())
	x.restoreRuntimeOwner(t)
	require.Empty(t, x.transitionsAfter(t, mark))
	require.Equal(t, model.StateOpen, x.findings(t, rtRef.Key())[cveContainerd].State)

	// Fresh again: forward again.
	report(t, x.st, "worker-1", x.clk.Now())
	x.pass(t)
	x.requireForward(t)
	require.Equal(t, 3, x.marker.count())
	require.Empty(t, x.transitionsAfter(t, mark))

	// A host-only finding, detected now.
	seedMatch(t, x.st, x.opensslPkg, cveHostOnly, "3.0.15-0ubuntu1")
	require.NoError(t, x.eng.OnOwnersChanged(ctx, []string{testNodesKey}))
	x.drain(t)
	ts := x.transitionsAfter(t, mark)
	require.Len(t, ts, 1)
	require.Equal(t, cveHostOnly, ts[0].AdvisoryID)
	mark = x.maxTransition(t)

	// Disabled while retired: back at once, the Nodes owner deleted, host-only findings resolved.
	x.setConfig(func(c *config.Config) { c.NodeAgent.Enabled = false })
	x.pass(t)
	x.requireBack(t)
	require.Equal(t, 4, x.marker.count())
	_, ok, err := x.st.GetOwner(ctx, testNodesKey)
	require.NoError(t, err)
	require.False(t, ok, "Nodes owner deleted")
	x.restoreRuntimeOwner(t)
	ts = x.transitionsAfter(t, mark)
	require.Len(t, ts, 1, "only the host-only finding moves")
	require.Equal(t, cveHostOnly, ts[0].AdvisoryID)
	require.Equal(t, model.StateResolved, ts[0].ToState)
	require.Equal(t, model.TriggerInventoryChange, ts[0].Trigger)
	require.Equal(t, model.StateOpen, x.findings(t, rtRef.Key())[cveContainerd].State)

	t.Run("runc-only findings resolve on a back cutover and are detected again", func(t *testing.T) {
		x := newCutoverFixture(t)
		seedMatch(t, x.st, x.runcPkg, cveRunc, "1.3.1")
		mark := x.maxTransition(t)

		x.pass(t)
		x.requireForward(t)
		ts := x.transitionsAfter(t, mark)
		require.Len(t, ts, 1)
		require.Equal(t, x.fpRun, ts[0].Fingerprint)
		require.Equal(t, model.StateOpen, ts[0].ToState)
		mark = x.maxTransition(t)

		x.clk.Add(31 * time.Minute)
		x.pass(t)
		x.clk.Add(2 * time.Hour)
		x.pass(t)
		x.requireBack(t)
		_, ok, err := x.st.GetOwner(ctx, testNodesKey)
		require.NoError(t, err)
		require.True(t, ok, "the stale node keeps its group, so the Nodes owner stays")
		x.restoreRuntimeOwner(t)
		ts = x.transitionsAfter(t, mark)
		require.Len(t, ts, 1, "runc is suppressed again; the containerd finding moved without a transition")
		require.Equal(t, x.fpRun, ts[0].Fingerprint)
		require.Equal(t, model.StateResolved, ts[0].ToState)
		require.Equal(t, model.TriggerInventoryChange, ts[0].Trigger)
		mark = x.maxTransition(t)

		report(t, x.st, "worker-1", x.clk.Now())
		x.pass(t)
		x.requireForward(t)
		ts = x.transitionsAfter(t, mark)
		require.Len(t, ts, 1)
		require.Equal(t, x.fpRun, ts[0].Fingerprint)
		require.Equal(t, model.StateOpen, ts[0].ToState, "detected again")
	})
}

func TestCutover_FreshNeedsAReadyNode(t *testing.T) {
	notReady := testNode("worker-1", "Ubuntu 26.04 LTS")
	notReady.Status.Conditions[0].Status = corev1.ConditionFalse
	x := newCutoverFixture(t, notReady)
	x.pass(t)
	require.False(t, x.state(t).RuntimeRetired, "no Ready node: never fresh")
	require.True(t, x.runtimeOwnerStored(t))
	require.Zero(t, x.marker.count())

	x = newCutoverFixture(t)
	x.clk.Add(31 * time.Minute) // worker-1 reported at t0, older than staleAfter (30m)
	x.pass(t)
	require.False(t, x.state(t).RuntimeRetired)
	require.True(t, x.runtimeOwnerStored(t))
	require.Zero(t, x.marker.count())
	require.Equal(t, grpA, x.groupOf(t, "worker-1").ID, "the stale node is still grouped")
}

// TestCutover_RacingFlushDoesNotResurrectRuntimeOwner: an inventory flush that read the state before the
// cutover cannot store the retired ContainerRuntime owner again, and an owner left from before (a crash,
// an older version) is re-homed onto the Nodes owner and dropped by the next retired pass.
func TestCutover_RacingFlushDoesNotResurrectRuntimeOwner(t *testing.T) {
	ctx := context.Background()
	x := newCutoverFixture(t)
	read, err := x.st.NodesState(ctx) // the flush reads the state ...
	require.NoError(t, err)
	require.False(t, read.RuntimeRetired)
	x.pass(t) // ... the cutover commits ...
	x.requireForward(t)
	mark := x.maxTransition(t)

	// ... and the flush stores the owner it built from the state it read.
	require.NoError(t, x.st.UpsertOwner(ctx, x.rtOwner))
	require.NoError(t, x.eng.OnOwnersChanged(ctx, []string{rtRef.Key()}))
	x.drain(t)
	require.False(t, x.runtimeOwnerStored(t), "the retired owner is not stored again")
	require.Empty(t, x.transitionsAfter(t, mark), "nothing is detected again")
	x.pass(t)
	x.requireForward(t)

	// An owner stored while the runtime was not retired, left behind: the next retired pass heals it.
	retired := x.state(t)
	notRetired := retired
	notRetired.RuntimeRetired = false
	require.NoError(t, x.st.PutNodesState(ctx, notRetired))
	require.NoError(t, x.st.UpsertOwner(ctx, x.rtOwner))
	require.NoError(t, x.st.PutNodesState(ctx, retired))
	require.NoError(t, x.eng.Recompute(ctx, []string{rtRef.Key()}, model.TriggerInventoryChange))
	require.Equal(t, model.StateOpen, x.findings(t, rtRef.Key())[cveContainerd].State, "the zombie owner duplicates the finding")
	x.pass(t)
	x.requireForward(t)
	require.Empty(t, x.findings(t, rtRef.Key()), "its findings moved onto the Nodes owner")
	require.Equal(t, x.fpNodes, x.findings(t, testNodesKey)[cveContainerd].Fingerprint)
}

// TestCutover_UnsupportedNodesDoNotBlockCutover: nodes the agent DaemonSet does not schedule on (another
// architecture, a nodeSelector mismatch) are left out of fresh and recorded with why.
func TestCutover_UnsupportedNodesDoNotBlockCutover(t *testing.T) {
	labelled := func(name, arch, os string) *corev1.Node {
		n := testNode(name, "Ubuntu 26.04 LTS")
		n.Labels = map[string]string{"kubernetes.io/arch": arch, "kubernetes.io/os": os}
		return n
	}
	x := newCutoverFixture(t, labelled("worker-1", "amd64", "linux"), labelled("arm-1", "arm64", "linux"),
		labelled("win-1", "amd64", "windows"))
	x.setConfig(func(c *config.Config) {
		c.NodeAgent.Architectures, c.NodeAgent.NodeSelector = []string{}, map[string]string{}
	})
	x.pass(t)
	require.False(t, x.state(t).RuntimeRetired, "every Ready node counts while the config says the agent runs everywhere")
	require.Nil(t, x.state(t).Unsupported)

	x.setConfig(func(c *config.Config) { // amd64 only, on Linux
		c.NodeAgent.Architectures, c.NodeAgent.NodeSelector = []string{"amd64"}, config.Default().NodeAgent.NodeSelector
	})
	x.pass(t)
	x.requireForward(t)
	st := x.state(t)
	require.Equal(t, map[string]string{"arm-1": "architecture arm64 is not in nodeAgent.architectures",
		"win-1": "node labels do not match nodeAgent.nodeSelector"}, st.Unsupported)
	require.Equal(t, 6*time.Hour+36*time.Minute+30*time.Minute, st.FullReportOverdue, "reportInterval with jitter, plus staleAfter")

	x.setConfig(func(c *config.Config) { c.NodeAgent.Enabled = false })
	x.pass(t)
	st = x.state(t)
	require.Nil(t, st.Unsupported, "nothing is unsupported while the agent is disabled")
	require.Zero(t, st.FullReportOverdue)
}
