package agentapi

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/engine"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/nodegroup"
	"github.com/the-it-dept/ffs/internal/store"
)

// fakeRehomer records the reconciler's engine calls. Rehome stores its State, as the engine does in the same
// write; OnOwnersChanged and Recompute also record the stored baseline time they ran under.
type fakeRehomer struct {
	st            *store.Store
	mu            sync.Mutex
	rehomes       []engine.Rehome
	changed       [][]string
	changedDuring []time.Time // the stored BaselineReadyAt at each OnOwnersChanged
	rehomedDuring []time.Time // the stored BaselineReadyAt at each Rehome, before its State is written
	recomputes    []recomputeCall
}

type recomputeCall struct {
	keys           []string
	trig           model.Trigger
	baselineDuring time.Time
}

func (f *fakeRehomer) Rehome(ctx context.Context, r engine.Rehome) error {
	st, err := f.st.NodesState(ctx)
	if err != nil {
		return err
	}
	if r.State != nil {
		if err := f.st.PutNodesState(ctx, *r.State); err != nil {
			return err
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rehomes = append(f.rehomes, r)
	f.rehomedDuring = append(f.rehomedDuring, st.BaselineReadyAt)
	return nil
}

func (f *fakeRehomer) OnOwnersChanged(ctx context.Context, keys []string) error {
	st, err := f.st.NodesState(ctx)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.changed = append(f.changed, keys)
	f.changedDuring = append(f.changedDuring, st.BaselineReadyAt)
	return nil
}

func (f *fakeRehomer) Recompute(ctx context.Context, keys []string, trig model.Trigger) error {
	st, err := f.st.NodesState(ctx)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recomputes = append(f.recomputes, recomputeCall{keys: keys, trig: trig, baselineDuring: st.BaselineReadyAt})
	return nil
}

func TestReconciler_NodeMovesGroupWithoutTransitions(t *testing.T) {
	ctx := context.Background()
	f := newRecFixture(t, nil)
	const cve1, cve2 = "CVE-2026-0001", "CVE-2026-0002"
	pkgA := hostPkg(nodegroup.GroupDigest(grpA), "deb", "openssl", "3.0.13-0ubuntu1", "")
	pkgB := hostPkg(nodegroup.GroupDigest(grpB), "deb", "openssl", "3.0.14-0ubuntu1", "")
	pkgC := hostPkg(nodegroup.GroupDigest(grpC), "deb", "openssl", "3.0.15-0ubuntu1", "")
	seedGroup(t, f.st, grpA, pkgA)
	gb := seedGroup(t, f.st, grpB, pkgB)
	seedMatch(t, f.st, pkgA, cve1, "3.0.15-0ubuntu1")
	seedMatch(t, f.st, pkgB, cve1, "3.0.15-0ubuntu1")
	seedMatch(t, f.st, pkgA, cve2, "3.0.14-0ubuntu1")
	require.NoError(t, f.st.PutNodesState(ctx, store.NodesState{AgentEnabled: true, RuntimeRetired: true}))
	for _, n := range []string{"worker-1", "worker-2"} {
		report(t, f.st, n, t0)
		f.fingerprint(t, n, grpA)
	}
	groups, err := f.st.NodeGroups(ctx)
	require.NoError(t, err)
	require.Empty(t, groups, "seeded groups are memberless: membership must not depend on NodeGroups")

	f.pass(t)
	require.Equal(t, grpA, f.groupOf(t, "worker-1").ID)
	require.Equal(t, grpA, f.groupOf(t, "worker-2").ID)
	require.Equal(t, model.NodeGroupNodeInfo, f.groupOf(t, "cp-1").Kind)
	fs := f.findings(t, testNodesKey)
	require.Len(t, fs, 2)
	for _, adv := range []string{cve1, cve2} {
		require.Equal(t, model.FindingFingerprint(testCluster, model.NodesOwner(testCluster), model.HostRepo, adv), fs[adv].Fingerprint)
		require.Equal(t, model.StateOpen, fs[adv].State)
	}
	fp1 := fs[cve1].Fingerprint
	mark := f.maxTransition(t)

	_, ok, err := f.st.NodeGroup(ctx, grpB)
	require.NoError(t, err)
	require.False(t, ok, "the pass dropped group B: no member and no fingerprint named it")

	// worker-2 moves to B: the finding spans both groups with no transition. Ingestion names the
	// fingerprint, then writes the group row.
	f.fingerprint(t, "worker-2", grpB)
	require.NoError(t, f.st.PutNodeGroup(ctx, gb, t0))
	f.pass(t)
	require.Equal(t, grpB, f.groupOf(t, "worker-2").ID)
	fs = f.findings(t, testNodesKey)
	require.Equal(t, fp1, fs[cve1].Fingerprint)
	require.Equal(t, []string{nodegroup.GroupDigest(grpA), nodegroup.GroupDigest(grpB)}, fs[cve1].Digests)
	require.Empty(t, f.transitionsAfter(t, mark))

	// A fingerprint whose group is catalogued but not matched yet does not move the node.
	seedGroup(t, f.st, grpC, pkgC)
	require.NoError(t, f.st.MarkUnmatched(ctx, nodegroup.GroupDigest(grpC), t0))
	f.fingerprint(t, "worker-1", grpC)
	f.pass(t)
	require.Equal(t, grpA, f.groupOf(t, "worker-1").ID)
	require.Empty(t, f.transitionsAfter(t, mark))

	// worker-1 moves to B too: A has no member and no fingerprint names it, so it goes.
	f.fingerprint(t, "worker-1", grpB)
	f.pass(t)
	_, ok, err = f.st.NodeGroup(ctx, grpA)
	require.NoError(t, err)
	require.False(t, ok, "group A is gone")
	fs = f.findings(t, testNodesKey)
	require.Equal(t, fp1, fs[cve1].Fingerprint)
	require.Equal(t, []string{nodegroup.GroupDigest(grpB)}, fs[cve1].Digests)
	require.Equal(t, model.StateOpen, fs[cve1].State)
	ts := f.transitionsAfter(t, mark)
	require.Len(t, ts, 1)
	require.Equal(t, cve2, ts[0].AdvisoryID)
	require.Equal(t, model.StateResolved, ts[0].ToState)
	require.Equal(t, model.TriggerInventoryChange, ts[0].Trigger)
}

// TestReconciler_BaselineReadyAfterFirstGroupsMatched: the baseline is ready once every scheduled Ready
// node is in a matched agent group, or, when some never are, min(staleAfter, 10m) after the first fresh
// report; never while an agent group is unmatched.
func TestReconciler_BaselineReadyAfterFirstGroupsMatched(t *testing.T) {
	ctx := context.Background()
	newFixture := func(t *testing.T, enabled bool) (*recFixture, *fakeRehomer) {
		t.Helper()
		fr := &fakeRehomer{}
		f := newRecFixture(t, fr)
		fr.st = f.st
		f.setConfig(func(c *config.Config) { c.NodeAgent.Enabled = enabled })
		seedGroup(t, f.st, grpA, hostPkg(nodegroup.GroupDigest(grpA), "deb", "openssl", "3.0.13-0ubuntu1", ""))
		require.NoError(t, f.st.MarkUnmatched(ctx, nodegroup.GroupDigest(grpA), t0))
		report(t, f.st, "worker-1", t0)
		f.fingerprint(t, "worker-1", grpA)
		return f, fr
	}

	f, fr := newFixture(t, true)
	f.pass(t)
	groups, err := f.st.NodeGroups(ctx)
	require.NoError(t, err)
	for _, g := range groups {
		require.Equal(t, model.NodeGroupNodeInfo, g.Kind, "no agent group has members while A is unmatched")
	}
	require.True(t, f.state(t).BaselineReadyAt.IsZero())
	require.Equal(t, t0, f.state(t).FirstReportAt, "the settle window starts at the first fresh report")
	require.Empty(t, fr.recomputes)

	// A is matched, but worker-2 and cp-1 have not reported: the baseline waits for the settle window.
	require.NoError(t, f.st.MarkMatched(ctx, nodegroup.GroupDigest(grpA)))
	f.clk.Add(time.Minute)
	f.pass(t)
	require.Equal(t, grpA, f.groupOf(t, "worker-1").ID)
	require.True(t, f.state(t).BaselineReadyAt.IsZero())
	require.Empty(t, fr.recomputes)

	f.clk.Add(9 * time.Minute) // min(staleAfter 30m, 10m) after the first report
	f.pass(t)
	require.Len(t, fr.recomputes, 1)
	require.Equal(t, []string{testNodesKey}, fr.recomputes[0].keys)
	require.Equal(t, model.TriggerInventoryChange, fr.recomputes[0].trig)
	require.True(t, fr.recomputes[0].baselineDuring.IsZero(), "the baseline is marked only after the recompute")
	readyAt := f.clk.Now()
	require.Equal(t, readyAt, f.state(t).BaselineReadyAt)

	f.clk.Add(time.Minute)
	f.pass(t)
	require.Len(t, fr.recomputes, 1)
	require.Equal(t, readyAt, f.state(t).BaselineReadyAt)

	f.setConfig(func(c *config.Config) { c.NodeAgent.Enabled = false })
	f.pass(t)
	st := f.state(t)
	require.True(t, st.BaselineReadyAt.IsZero())
	require.True(t, st.FirstReportAt.IsZero())
	require.False(t, st.AgentEnabled)

	// Re-enabled: the settle window starts again.
	f.setConfig(func(c *config.Config) { c.NodeAgent.Enabled = true })
	f.clk.Add(time.Minute)
	f.pass(t)
	require.Len(t, fr.recomputes, 1)
	require.True(t, f.state(t).BaselineReadyAt.IsZero())
	require.True(t, f.state(t).AgentEnabled)
	f.clk.Add(10 * time.Minute)
	f.pass(t)
	require.Len(t, fr.recomputes, 2)
	require.Equal(t, f.clk.Now(), f.state(t).BaselineReadyAt)

	f, fr = newFixture(t, false)
	require.NoError(t, f.st.MarkMatched(ctx, nodegroup.GroupDigest(grpA)))
	f.pass(t)
	f.clk.Add(time.Hour)
	f.pass(t)
	require.True(t, f.state(t).BaselineReadyAt.IsZero())
	require.Empty(t, fr.recomputes)
}

// TestReconciler_BaselineWaitsForStaggeredGroups: node pools whose groups match minutes apart share one
// baseline. It is ready when the last scheduled Ready node joins a matched group, before the settle window,
// so the later group's advisories are in the baseline rather than alerting one by one (spec §9.9).
func TestReconciler_BaselineWaitsForStaggeredGroups(t *testing.T) {
	ctx := context.Background()
	fr := &fakeRehomer{}
	f := newRecFixture(t, fr)
	fr.st = f.st
	seedGroup(t, f.st, grpA, hostPkg(nodegroup.GroupDigest(grpA), "deb", "openssl", "3.0.13-0ubuntu1", ""))
	seedGroup(t, f.st, grpB, hostPkg(nodegroup.GroupDigest(grpB), "deb", "openssl", "3.0.14-0ubuntu1", ""))
	for _, g := range []string{grpA, grpB} {
		require.NoError(t, f.st.MarkUnmatched(ctx, nodegroup.GroupDigest(g), t0))
	}
	for node, g := range map[string]string{"worker-1": grpA, "worker-2": grpB, "cp-1": grpB} {
		report(t, f.st, node, t0)
		f.fingerprint(t, node, g)
	}
	f.pass(t)
	require.True(t, f.state(t).BaselineReadyAt.IsZero())

	// Group A matches first: worker-1 joins it, the others are still in nodeinfo groups.
	require.NoError(t, f.st.MarkMatched(ctx, nodegroup.GroupDigest(grpA)))
	f.clk.Add(time.Minute)
	f.pass(t)
	require.Equal(t, grpA, f.groupOf(t, "worker-1").ID)
	require.Equal(t, model.NodeGroupNodeInfo, f.groupOf(t, "worker-2").Kind)
	require.True(t, f.state(t).BaselineReadyAt.IsZero(), "one matched group of two is not the baseline")
	require.Empty(t, fr.recomputes)

	// Group B matches two minutes later: every node is in a matched group, so the baseline is ready now,
	// well inside the settle window, with both groups in it.
	require.NoError(t, f.st.MarkMatched(ctx, nodegroup.GroupDigest(grpB)))
	f.clk.Add(2 * time.Minute)
	f.pass(t)
	require.Equal(t, grpB, f.groupOf(t, "worker-2").ID)
	require.Equal(t, grpB, f.groupOf(t, "cp-1").ID)
	require.Equal(t, t0.Add(3*time.Minute), f.state(t).BaselineReadyAt)
	require.Len(t, fr.recomputes, 1)
	o, ok, err := f.st.GetOwner(ctx, testNodesKey)
	require.NoError(t, err)
	require.True(t, ok)
	require.Len(t, o.Containers, 2, "the baseline recompute covers both groups")
}

// TestReconciler_DisableClearsBaselineBeforeHostFindingsGo: disabling clears the baseline before the pass
// moves findings back or deletes the Nodes owner, so a notify pass in between holds those transitions.
func TestReconciler_DisableClearsBaselineBeforeHostFindingsGo(t *testing.T) {
	ctx := context.Background()
	fr := &fakeRehomer{}
	f := newRecFixture(t, fr)
	fr.st = f.st
	seedGroup(t, f.st, grpA, hostPkg(nodegroup.GroupDigest(grpA), "deb", "openssl", "3.0.13-0ubuntu1", ""))
	for _, n := range []string{"worker-1", "worker-2", "cp-1"} {
		report(t, f.st, n, t0)
		f.fingerprint(t, n, grpA)
	}
	f.pass(t)
	st := f.state(t)
	require.Equal(t, t0, st.BaselineReadyAt, "every node fresh in a matched group: ready at once")
	require.True(t, st.RuntimeRetired)
	require.Len(t, fr.rehomes, 1)
	require.NotNil(t, fr.rehomes[0].State, "the cutover writes the state with its moves")
	require.True(t, fr.rehomes[0].State.RuntimeRetired)

	f.setConfig(func(c *config.Config) { c.NodeAgent.Enabled = false })
	changed := len(fr.changed)
	f.pass(t)
	require.Len(t, fr.rehomes, 2, "the back cutover")
	require.True(t, fr.rehomedDuring[1].IsZero(), "the baseline is cleared before the findings move back")
	require.False(t, fr.rehomes[1].State.RuntimeRetired)
	require.True(t, fr.rehomes[1].State.BaselineReadyAt.IsZero())
	require.Greater(t, len(fr.changed), changed)
	for i := changed; i < len(fr.changed); i++ {
		require.Equal(t, []string{testNodesKey}, fr.changed[i])
		require.True(t, fr.changedDuring[i].IsZero(), "the baseline is cleared before the Nodes owner is deleted")
	}
	_, ok, err := f.st.GetOwner(ctx, testNodesKey)
	require.NoError(t, err)
	require.False(t, ok)
}

func TestReconciler_MembershipRules(t *testing.T) {
	ctx := context.Background()
	fr := &fakeRehomer{}
	f := newRecFixture(t, fr)
	fr.st = f.st
	seedGroup(t, f.st, grpA, hostPkg(nodegroup.GroupDigest(grpA), "deb", "openssl", "3.0.13-0ubuntu1", ""))
	report(t, f.st, "worker-1", t0)
	f.fingerprint(t, "worker-1", grpA)
	f.pass(t)
	require.Equal(t, grpA, f.groupOf(t, "worker-1").ID)
	for _, n := range []string{"worker-2", "cp-1"} {
		g := f.groupOf(t, n)
		require.Equal(t, model.NodeGroupNodeInfo, g.Kind, "%s never reported", n)
		require.Equal(t, nodegroup.FallbackID(nodeInfo(testNode(n, "Ubuntu 26.04 LTS"), t0)), g.ID)
	}

	// A fingerprint whose group SBOM is not catalogued keeps the current group, even with a group row.
	gb := f.groupOf(t, "worker-1")
	gb.ID, gb.Label, gb.Digest = grpB, nodegroup.GroupLabel(gb.Name, grpB), nodegroup.GroupDigest(grpB)
	require.NoError(t, f.st.PutNodeGroup(ctx, gb, t0))
	f.fingerprint(t, "worker-1", grpB)
	f.pass(t)
	require.Equal(t, grpA, f.groupOf(t, "worker-1").ID)

	// A catalogued, matched fingerprint whose group row is not written yet keeps the current group.
	require.NoError(t, f.st.UpsertImage(ctx, model.Image{Digest: nodegroup.GroupDigest(grpC), Repo: model.HostRepo,
		Platform: "linux/amd64", Status: model.ImageCatalogued, Source: "agent", CataloguedAt: t0}))
	f.fingerprint(t, "worker-1", grpC)
	f.pass(t)
	require.Equal(t, grpA, f.groupOf(t, "worker-1").ID)

	// A row for a node that is gone is pruned.
	report(t, f.st, "worker-9", t0)

	// Disabled: every node falls back.
	f.setConfig(func(c *config.Config) { c.NodeAgent.Enabled = false })
	f.pass(t)
	for _, n := range []string{"worker-1", "worker-2", "cp-1"} {
		require.Equal(t, model.NodeGroupNodeInfo, f.groupOf(t, n).Kind, n)
	}
	require.False(t, f.state(t).AgentEnabled)
	rows, err := f.st.AgentNodes(ctx)
	require.NoError(t, err)
	var names []string
	for _, r := range rows {
		names = append(names, r.Node)
		require.Empty(t, r.GroupID, "%s is in no agent group", r.Node)
	}
	require.Equal(t, []string{"worker-1"}, names, "worker-9 is not in the cluster")
}

func TestReconciler_NodesOwnerShape(t *testing.T) {
	ctx := context.Background()
	fr := &fakeRehomer{}
	f := newRecFixture(t, fr)
	fr.st = f.st
	ga := seedGroup(t, f.st, grpA, hostPkg(nodegroup.GroupDigest(grpA), "deb", "openssl", "3.0.13-0ubuntu1", ""))
	gb := seedGroup(t, f.st, grpB, hostPkg(nodegroup.GroupDigest(grpB), "deb", "openssl", "3.0.14-0ubuntu1", ""))
	report(t, f.st, "worker-1", t0)
	f.fingerprint(t, "worker-1", grpA)
	report(t, f.st, "worker-2", t0)
	f.fingerprint(t, "worker-2", grpB)
	f.pass(t)

	owner := func() model.Owner {
		t.Helper()
		o, ok, err := f.st.GetOwner(ctx, testNodesKey)
		require.NoError(t, err)
		require.True(t, ok)
		return o
	}
	container := func(g model.NodeGroup, exposure ...string) model.ContainerUse {
		return model.ContainerUse{Name: g.Label, Kind: model.ContainerRegular, ImageRef: g.Label, Repo: model.HostRepo,
			Digest: g.Digest, Platform: "linux/amd64", ExposurePaths: exposure}
	}
	o := owner()
	require.Equal(t, []model.ContainerUse{container(ga), container(gb)}, o.Containers)
	require.Equal(t, nodegroup.SuppressedModules(f.state(t).RuntimeRetired), o.SuppressModules)
	require.Equal(t, []string{"amd64"}, o.Arch)
	require.True(t, t0.Equal(o.UpdatedAt))
	require.Equal(t, [][]string{{testNodesKey}}, fr.changed)

	// Unchanged: neither stored nor announced again.
	f.clk.Add(time.Minute)
	f.pass(t)
	require.True(t, t0.Equal(owner().UpdatedAt), "not stored again")
	require.Len(t, fr.changed, 1)

	// Exposed nodes by label selector.
	var w1 corev1.Node
	require.NoError(t, f.cl.Get(ctx, client.ObjectKey{Name: "worker-1"}, &w1))
	w1.Labels = map[string]string{"node-role.kubernetes.io/edge": "true"}
	require.NoError(t, f.cl.Update(ctx, &w1))
	f.setConfig(func(c *config.Config) { c.NodeAgent.ExposedNodes = "node-role.kubernetes.io/edge=true" })
	f.pass(t)
	require.Equal(t, []model.ContainerUse{container(ga, "node worker-1"), container(gb)}, owner().Containers)
	require.Len(t, fr.changed, 2)
	g, _, err := f.st.NodeGroup(ctx, grpA)
	require.NoError(t, err)
	require.Equal(t, []string{"worker-1"}, g.ExposedNodes)

	// A blank selector exposes nothing (labels.Parse("") would select every node).
	f.setConfig(func(c *config.Config) { c.NodeAgent.ExposedNodes = "  " })
	f.pass(t)
	for _, c := range owner().Containers {
		require.Empty(t, c.ExposurePaths)
	}
	g, _, err = f.st.NodeGroup(ctx, grpA)
	require.NoError(t, err)
	require.Empty(t, g.ExposedNodes)

	// Images in use come from the pods on the node.
	x := hexDigest("e")
	require.NoError(t, f.st.ReplaceNodeImages(ctx, "worker-1", []model.NodeImage{{Digest: x, Complete: true, Source: "content-store"}}))
	f.pods.run("worker-1", x)
	f.pass(t)
	imgs, err := f.st.NodeImages(ctx, "worker-1")
	require.NoError(t, err)
	require.Len(t, imgs, 1)
	require.True(t, imgs[0].InUse)
}

func TestNodeEvents_TriggerOnAddDeleteLabelOrReady(t *testing.T) {
	n := 0
	h := nodeEvents(func() { n++ })
	node := testNode("worker-1", "Ubuntu 26.04 LTS")

	h.OnAdd(node, false)
	require.Equal(t, 1, n)
	h.OnDelete(node)
	require.Equal(t, 2, n)

	info := node.DeepCopy()
	info.Status.NodeInfo.KernelVersion = "7.0.0-38-generic"
	h.OnUpdate(node, info)
	require.Equal(t, 2, n, "a nodeInfo change alone does not trigger")

	labelled := node.DeepCopy()
	labelled.Labels = map[string]string{"node-role.kubernetes.io/edge": "true"}
	h.OnUpdate(node, labelled)
	require.Equal(t, 3, n)

	notReady := node.DeepCopy()
	notReady.Status.Conditions = []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionFalse,
		LastHeartbeatTime: metav1.NewTime(t0)}}
	h.OnUpdate(node, notReady)
	require.Equal(t, 4, n)
}

// TestReconciler_IdlePassWritesNothing: the grouping and the in-use marks are one transaction that writes
// only what changed, so a pass over an unchanged cluster writes no row; a pod change writes its row only.
func TestReconciler_IdlePassWritesNothing(t *testing.T) {
	ctx := context.Background()
	fr := &fakeRehomer{}
	f := newRecFixture(t, fr)
	fr.st = f.st
	seedGroup(t, f.st, grpA, hostPkg(nodegroup.GroupDigest(grpA), "deb", "openssl", "3.0.13-0ubuntu1", ""))
	img1, img2 := hexDigest("1"), hexDigest("2")
	for _, n := range []string{"worker-1", "worker-2", "cp-1"} {
		report(t, f.st, n, t0)
		f.fingerprint(t, n, grpA)
		require.NoError(t, f.st.ReplaceNodeImages(ctx, n, []model.NodeImage{{Digest: img1, Complete: true, Source: "content-store"},
			{Digest: img2, Complete: true, Source: "content-store"}}))
	}
	f.pods.run("worker-1", img1)
	f.setConfig(func(c *config.Config) { c.NodeAgent.ExposedNodes = "node-role.example.com/edge" })
	f.pass(t)
	require.True(t, f.state(t).RuntimeRetired)
	require.False(t, f.state(t).BaselineReadyAt.IsZero())
	rows, err := f.st.NodeImages(ctx, "worker-1")
	require.NoError(t, err)
	require.True(t, rows[0].InUse)
	require.False(t, rows[1].InUse)

	changes := func() int64 {
		t.Helper()
		n, err := f.st.WriteChanges(ctx)
		require.NoError(t, err)
		return n
	}
	before := changes()
	for range 3 {
		f.clk.Add(time.Minute)
		f.pass(t)
	}
	require.Equal(t, before, changes(), "an idle pass writes nothing")

	f.pods.run("worker-2", img2)
	f.clk.Add(time.Minute)
	f.pass(t)
	require.Equal(t, before+1, changes(), "a new pod writes its image's in-use mark only")
	rows, err = f.st.NodeImages(ctx, "worker-2")
	require.NoError(t, err)
	require.True(t, rows[1].InUse)
}
