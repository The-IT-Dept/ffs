package notify_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/notify"
	"github.com/the-it-dept/ffs/internal/store"
)

var (
	nodesRef = model.NodesOwner("test")
	grpA     = model.NodeGroupDigestPrefix + strings.Repeat("a", 64)
	grpB     = model.NodeGroupDigestPrefix + strings.Repeat("b", 64)
)

const (
	labelA = "ubuntu-26.04-k7.0.0-34-aaaaaa"
	labelB = "ubuntu-26.04-k7.0.0-38-bbbbbb"
)

func nodesFinding(adv string, p model.Priority, digests ...string) model.Finding {
	f := finding(nodesRef, adv, p)
	f.Fingerprint = model.FindingFingerprint("test", nodesRef, model.HostRepo, adv)
	f.ImageRepo, f.Digests = model.HostRepo, digests
	return f
}

// groups stores agent groups (digest, label, member) and their membership.
func (h *harness) groups(gs ...[3]string) {
	h.t.Helper()
	members := map[string]string{}
	for _, g := range gs {
		id := strings.TrimPrefix(g[0], model.NodeGroupDigestPrefix)
		require.NoError(h.t, h.st.PutNodeGroup(ctx, model.NodeGroup{ID: id, Kind: model.NodeGroupAgent, Name: g[1][:len(g[1])-7],
			Label: g[1], Digest: g[0]}, h.now))
		members[g[2]] = id
	}
	require.NoError(h.t, h.st.ApplyNodeGrouping(ctx, store.NodeGrouping{Members: members, Now: h.now}))
}

// nodesReady marks the node inventory ready to baseline now, as the reconciler does.
func (h *harness) nodesReady() {
	h.t.Helper()
	require.NoError(h.t, h.st.PutNodesState(ctx, store.NodesState{AgentEnabled: true, BaselineReadyAt: h.now}))
}

func (h *harness) targetState(uid string) store.NotifyTargetState {
	h.t.Helper()
	st, ok, err := h.st.NotifyTarget(ctx, uid)
	require.NoError(h.t, err)
	require.True(h.t, ok)
	return st
}

// nodesSummarised runs Review Focus 1 up to the node inventory baseline: a target baselined before
// the node agent's data is ready, Nodes findings held from its alerts and digest, then one summary
// once the reconciler marks the baseline ready. It returns the harness and the fingerprints of the
// three summarised Nodes findings (CVE-2026-0100 urgent, CVE-2026-0101 urgent, CVE-2026-0102 high).
func nodesSummarised(t *testing.T) (*harness, []string) {
	t.Helper()
	h := newHarness(t)
	h.open(dep("shop", "web"), "CVE-2026-0001", high)
	require.NoError(t, h.st.UpsertOwner(ctx, model.Owner{Ref: nodesRef}))
	h.batch(nodesFinding("CVE-2026-0100", urgent, grpA)) // partial agent data before the target's baseline
	h.target("ops")
	h.process()
	m := h.sink.only(t)
	assert.Equal(t, "ffs is watching 1 workload: 0 urgent, 1 high", m.Title) // Nodes owner not a workload; held finding left out
	assert.Equal(t, map[model.Priority]int{high: 1}, m.Summary.Counts)

	// Held: urgent Nodes findings send nothing; an urgent workload finding still alerts.
	h.batch(nodesFinding("CVE-2026-0101", urgent, grpA, grpB), nodesFinding("CVE-2026-0102", high, grpB))
	h.open(dep("shop", "api"), "CVE-2026-0002", urgent)
	h.open(dep("shop", "cron"), "CVE-2026-0003", medium) // gives the 09:00 digest something to list
	h.process()
	assert.Equal(t, []string{"CVE-2026-0002"}, advisories(h.sink.ofKind(notify.KindImmediate)))
	h.at("2026-11-19T09:00Z")
	h.process()
	require.Len(t, h.sink.ofKind(notify.KindDigest), 1)
	for _, it := range h.sink.lastOfKind(notify.KindDigest).Items {
		for _, o := range it.Owners {
			assert.NotEqual(t, model.OwnerKindNodes, o.Kind) // held Nodes findings not listed
		}
	}

	// The reconciler marks the node baseline ready: one summary of the open Nodes findings.
	h.groups([3]string{grpA, labelA, "worker-1"}, [3]string{grpB, labelB, "worker-2"})
	h.nodesReady()
	before := len(h.sink.sent)
	h.process()
	require.Len(t, h.sink.sent, before+1)
	s := h.sink.sent[before]
	assert.Equal(t, notify.KindBaseline, s.Kind)
	assert.Equal(t, "Node inventory baseline: 3 findings on 2 node groups (2 urgent, 1 high)", s.Title)
	assert.Nil(t, s.Summary)
	i := slices.IndexFunc(s.Items, func(i notify.Item) bool { return i.AdvisoryID == "CVE-2026-0101" })
	require.GreaterOrEqual(t, i, 0)
	assert.Equal(t, []string{labelA, labelB}, s.Items[i].NodeGroups)
	assert.True(t, h.targetState("uid-ops").NodesBaselineAt.Equal(h.now))
	held := []string{nodesFinding("CVE-2026-0100", urgent).Fingerprint, nodesFinding("CVE-2026-0101", urgent).Fingerprint,
		nodesFinding("CVE-2026-0102", high).Fingerprint}
	l, err := h.st.Ledger(ctx, "uid-ops", held)
	require.NoError(t, err)
	assert.Len(t, l, 3)
	return h, held
}

func TestNotify_NodesBaselineHoldsThenSummarises(t *testing.T) { // Review Focus 1
	h, held := nodesSummarised(t)
	n := len(h.sink.sent)

	// Never twice; after the summary, Nodes findings alert like any other.
	h.process()
	assert.Len(t, h.sink.sent, n)
	h.batch(nodesFinding("CVE-2026-0103", urgent, grpB))
	h.move(held[2], model.StateOpen, urgent, model.TriggerNewAdvisory) // escalation of a summarised finding
	h.process()
	imm := h.sink.ofKind(notify.KindImmediate)
	assert.Equal(t, []string{"CVE-2026-0002", "CVE-2026-0102", "CVE-2026-0103"}, slices.Sorted(slices.Values(advisories(imm))))
	m := byAdvisory(t, imm, "CVE-2026-0103")
	assert.Equal(t, "New urgent finding: CVE-2026-0103 affects 1 node group", m.Title)
	assert.Equal(t, []string{labelB}, m.Items[0].NodeGroups)
	assert.Equal(t, "Escalated to urgent: CVE-2026-0102 affects 1 node group", byAdvisory(t, imm, "CVE-2026-0102").Title)
}

func TestNotify_NodesReenableBaselinesAgain(t *testing.T) {
	h, held := nodesSummarised(t)
	imm := len(h.sink.ofKind(notify.KindImmediate))

	// The agent is disabled: the reconciler clears BaselineReadyAt and the host findings resolve.
	require.NoError(t, h.st.PutNodesState(ctx, store.NodesState{}))
	for i, p := range []model.Priority{urgent, urgent, high} {
		h.move(held[i], model.StateResolved, p, model.TriggerInventoryChange)
	}
	h.process()
	h.at("2026-11-20T09:00Z")
	h.process()
	assert.Len(t, h.sink.ofKind(notify.KindImmediate), imm, "resolutions of held Nodes findings are not sent")
	for _, d := range h.sink.ofKind(notify.KindDigest) {
		for _, it := range d.Items {
			for _, o := range it.Owners {
				assert.NotEqual(t, model.OwnerKindNodes, o.Kind)
			}
		}
	}

	// Enabled again: held until a fresh summary, not an alert per finding.
	h.at("2026-11-20T10:00Z")
	later := h.now
	h.nodesReady()
	h.batch(nodesFinding("CVE-2026-0104", urgent, grpA))
	baselines := len(h.sink.ofKind(notify.KindBaseline))
	h.process()
	assert.Len(t, h.sink.ofKind(notify.KindImmediate), imm, "no immediate alert for CVE-2026-0104")
	bs := h.sink.ofKind(notify.KindBaseline)
	require.Len(t, bs, baselines+1)
	assert.True(t, strings.HasPrefix(bs[len(bs)-1].Title, "Node inventory baseline: "), bs[len(bs)-1].Title)
	assert.Equal(t, "Node inventory baseline: 1 finding on 2 node groups (1 urgent, 0 high)", bs[len(bs)-1].Title)
	assert.True(t, h.targetState("uid-ops").NodesBaselineAt.Equal(later))

	// Nodes transitions alert again.
	h.batch(nodesFinding("CVE-2026-0105", urgent, grpA))
	h.process()
	assert.Len(t, h.sink.ofKind(notify.KindImmediate), imm+1)
	assert.Equal(t, "CVE-2026-0105", h.sink.lastOfKind(notify.KindImmediate).Items[0].AdvisoryID)
}

func TestNotify_NewTargetAfterNodesReadyBaselineIncludesNodes(t *testing.T) {
	h := newHarness(t)
	h.groups([3]string{grpA, labelA, "worker-1"})
	h.nodesReady()
	h.batch(nodesFinding("CVE-2026-0100", urgent, grpA))
	h.target("ops")
	h.process()
	m := h.sink.only(t)
	assert.Equal(t, notify.KindBaseline, m.Kind)
	assert.Equal(t, "ffs is watching 0 workloads: 1 urgent, 0 high", m.Title)
	require.Len(t, m.Items, 1)
	assert.Equal(t, []string{labelA}, m.Items[0].NodeGroups)
	assert.True(t, h.targetState("uid-ops").NodesBaselineAt.Equal(h.now))
	h.process()
	h.sink.only(t)
}

func TestNotify_NodesItemNamesThreeGroupsThenMore(t *testing.T) {
	h := newHarness(t)
	h.target("ops")
	h.process()
	var (
		gs      [][3]string
		digests []string
		labels  []string
	)
	for i, c := range "abcde" {
		d := model.NodeGroupDigestPrefix + strings.Repeat(string(c), 64)
		l := fmt.Sprintf("node-%c-%s", c, strings.Repeat(string(c), 6))
		gs, digests, labels = append(gs, [3]string{d, l, fmt.Sprintf("worker-%d", i+1)}), append(digests, d), append(labels, l)
	}
	h.groups(gs...)
	h.batch(nodesFinding("CVE-2026-0100", high, digests...))
	h.nodesReady()
	h.process()
	s := h.sink.lastOfKind(notify.KindBaseline)
	assert.Equal(t, "Node inventory baseline: 1 finding on 5 node groups (0 urgent, 1 high)", s.Title)
	require.Len(t, s.Items, 1)
	assert.Equal(t, []string{labels[0], labels[1], labels[2], "+2 more"}, s.Items[0].NodeGroups)
}

func TestNotify_NamespacedTargetEndsNodeHoldSilently(t *testing.T) {
	h := newHarness(t)
	h.target("shop", func(c *notify.TargetConfig) { c.NamespaceMatch = func(ns string) bool { return ns == "shop" } })
	h.process()
	n := len(h.sink.sent) // the target's own baseline
	h.groups([3]string{grpA, labelA, "worker-1"})
	h.batch(nodesFinding("CVE-2026-0100", urgent, grpA))
	h.nodesReady()
	h.process()
	assert.Len(t, h.sink.sent, n)
	assert.True(t, h.targetState("uid-shop").NodesBaselineAt.Equal(h.now))
}

func TestNotify_PausedTargetGetsNodeSummaryOnResume(t *testing.T) {
	h := newHarness(t)
	h.target("ops")
	h.process()
	h.target("ops", func(c *notify.TargetConfig) { c.Paused = true })
	h.groups([3]string{grpA, labelA, "worker-1"})
	h.batch(nodesFinding("CVE-2026-0100", urgent, grpA))
	h.nodesReady()
	n := len(h.sink.sent)
	h.process()
	assert.Len(t, h.sink.sent, n)
	assert.True(t, h.targetState("uid-ops").NodesBaselineAt.IsZero())

	h.target("ops")
	h.process()
	require.Len(t, h.sink.sent, n+1)
	s := h.sink.sent[n]
	assert.Equal(t, notify.KindBaseline, s.Kind)
	assert.Equal(t, "Node inventory baseline: 1 finding on 1 node group (1 urgent, 0 high)", s.Title)
}
