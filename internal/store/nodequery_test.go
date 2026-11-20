package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/nodegroup"
)

// grouped is one group of a groupNodes fixture: its members and the members it exposes.
type grouped struct {
	g                model.NodeGroup
	members, exposed []string
}

// groupNodes stores gs the way a reconcile pass would: each member of an agent group reports at now
// and is given the group's fingerprint, the agent groups are put, and one ApplyNodeGrouping call
// writes the membership, with the nodeinfo groups as Fallback.
func groupNodes(t *testing.T, s *Store, now time.Time, gs ...grouped) {
	t.Helper()
	ng := NodeGrouping{Members: map[string]string{}, Exposed: map[string][]string{}, Now: now}
	for _, x := range gs {
		for _, m := range x.members {
			ng.Members[m] = x.g.ID
		}
		if len(x.exposed) > 0 {
			ng.Exposed[x.g.ID] = x.exposed
		}
		if x.g.Kind != model.NodeGroupAgent {
			ng.Fallback = append(ng.Fallback, x.g)
			continue
		}
		for _, m := range x.members {
			_, err := s.AcceptAgentReport(ctx, fullReport(m, "boot-a", now, 1, now))
			require.NoError(t, err)
			require.NoError(t, s.SetAgentFingerprint(ctx, m, x.g.ID))
		}
		require.NoError(t, s.PutNodeGroup(ctx, x.g, now))
	}
	require.NoError(t, s.ApplyNodeGrouping(ctx, ng))
}

func TestNodeGroups_ListAndLookup(t *testing.T) {
	s := newStore(t)
	a34, a38, pending := agentGroup("aaaa01"), agentGroup("bbbb02"), agentGroup("cccc03")
	a38.Label, a38.KernelRelease = "ubuntu-26.04-k7.0.0-38-bbbb02", "7.0.0-38-generic"
	ni := nodeinfoGroup("ffff06")
	ni.Label = "talos-1.9.0-k6.12.6-ffff06"
	groupNodes(t, s, t0,
		grouped{g: a34, members: []string{"worker-1", "worker-2"}, exposed: []string{"worker-2"}},
		grouped{g: a38, members: []string{"worker-3"}},
		grouped{g: ni, members: []string{"cp-1"}})
	// A newer fingerprint awaiting its match: stored, but memberless.
	require.NoError(t, s.PutNodeGroup(ctx, pending, t0))
	require.NoError(t, s.SetAgentFingerprint(ctx, "worker-3", pending.ID))

	gs, err := s.NodeGroups(ctx)
	require.NoError(t, err)
	labels := make([]string, len(gs))
	for i, g := range gs {
		labels[i] = g.Label
	}
	require.Equal(t, []string{a34.Label, a38.Label, ni.Label}, labels, "agent first, then nodeinfo; memberless omitted")
	require.Equal(t, []string{"worker-1", "worker-2"}, gs[0].Members)
	require.Equal(t, []string{"worker-2"}, gs[0].ExposedNodes)
	require.Equal(t, "nodegroup:aaaa01", gs[0].Digest)
	g, ok, err := s.NodeGroup(ctx, pending.ID)
	require.NoError(t, err)
	require.True(t, ok, "a memberless group is still found by id")
	require.Empty(t, g.Members)
	_, ok, _ = s.NodeGroup(ctx, "nope")
	require.False(t, ok)
	g, ok, _ = s.NodeGroupOfNode(ctx, "cp-1")
	require.True(t, ok)
	require.Equal(t, ni.ID, g.ID)
	require.Equal(t, []string{"cp-1"}, g.Members)
	_, ok, _ = s.NodeGroupOfNode(ctx, "worker-9")
	require.False(t, ok)
}

func TestNodeDrift_ComparesStoredSBOMs(t *testing.T) {
	s := newStore(t)
	a34, a38, pending := agentGroup("aaaa01"), agentGroup("bbbb02"), agentGroup("cccc03")
	a38.Label, a38.KernelRelease = "ubuntu-26.04-k7.0.0-38-bbbb02", "7.0.0-38-generic"
	ni := nodeinfoGroup("ffff06")
	groupNodes(t, s, t0,
		grouped{g: a34, members: []string{"worker-1"}},
		grouped{g: a38, members: []string{"worker-2"}},
		grouped{g: ni, members: []string{"cp-1"}})
	hostDeb := func(name, version string) model.Package {
		return model.Package{Ecosystem: "deb", Name: name, Version: version, Arch: "amd64", Path: "/var/lib/dpkg/status"}
	}
	for g, pkgs := range map[string][]model.Package{
		a34.Digest: {hostDeb("libc6", "2.39-0ubuntu8"), hostDeb("linux-image-7.0.0-34-generic", "7.0.0-34.34")},
		a38.Digest: {hostDeb("libc6", "2.39-0ubuntu8.4"), hostDeb("linux-image-7.0.0-38-generic", "7.0.0-38.38")},
	} {
		require.NoError(t, s.UpsertImage(ctx, model.Image{Digest: g, Repo: model.HostRepo, Status: model.ImageCatalogued, Source: "agent"}))
		require.NoError(t, s.PutSBOM(ctx, g, nil, pkgs))
	}
	require.NoError(t, s.PutNodeGroup(ctx, pending, t0)) // no images row

	d, err := s.NodeDrift(ctx, a34.ID, a38.ID)
	require.NoError(t, err)
	require.Equal(t, a34.ID, d.From)
	require.Equal(t, a38.ID, d.To)
	require.True(t, d.PackagesCompared)
	require.Equal(t, 1, d.NewerInTo)
	require.Equal(t, "kernel 7.0.0-38 vs 7.0.0-34; 1 package newer", nodegroup.Summary(d))
	d, err = s.NodeDrift(ctx, a34.ID, pending.ID)
	require.NoError(t, err)
	require.False(t, d.PackagesCompared, "pending has no stored SBOM")
	d, err = s.NodeDrift(ctx, a34.ID, ni.ID)
	require.NoError(t, err)
	require.False(t, d.PackagesCompared)
	_, err = s.NodeDrift(ctx, a34.ID, "nope")
	require.ErrorIs(t, err, ErrNodeGroupNotFound)
}

func TestAgentStatus_States(t *testing.T) {
	s := newStore(t)
	now := t0.Add(24 * time.Hour) // 2026-11-20T00:00:00Z
	require.NoError(t, s.ReplaceNodes(ctx, []model.Node{{Name: "worker-1", Ready: true}, {Name: "worker-2", Ready: true}, {Name: "cp-1", Ready: true}}))
	blocked := model.NodeCoverageGap{Code: model.GapNodeAgentBlocked, Detail: "node agent cannot read /var/lib/rpm: permission denied"}
	r1 := fullReport("worker-1", "boot-a", t0, 1, now.Add(-5*time.Minute))
	r1.Coverage = []model.NodeCoverageGap{blocked}
	r2 := fullReport("worker-2", "boot-b", t0, 1, now.Add(-2*time.Hour))
	for _, r := range []AgentReport{r1, r2} {
		ok, err := s.AcceptAgentReport(ctx, r)
		require.NoError(t, err)
		require.True(t, ok)
	}
	require.NoError(t, s.PutNodeGroup(ctx, agentGroup("aaaa01"), now))
	require.NoError(t, s.ApplyNodeGrouping(ctx, NodeGrouping{Now: now, Fallback: []model.NodeGroup{nodeinfoGroup("ffff06")},
		Members: map[string]string{"worker-1": "aaaa01", "worker-2": "aaaa01", "cp-1": "ffff06"}}))

	st, err := s.AgentStatus(ctx, now, 30*time.Minute)
	require.NoError(t, err)
	require.Len(t, st, 3)
	for _, n := range st {
		require.Equal(t, model.AgentDisabled, n.State, "no nodes_state row: disabled")
	}
	require.NoError(t, s.PutNodesState(ctx, NodesState{AgentEnabled: true}))
	st, err = s.AgentStatus(ctx, now, 30*time.Minute)
	require.NoError(t, err)
	require.Equal(t, []string{"cp-1", "worker-1", "worker-2"}, []string{st[0].Node, st[1].Node, st[2].Node})
	require.Equal(t, model.NodeAgentStatus{Node: "cp-1", State: model.AgentNever, GroupID: "ffff06",
		Coverage: []model.NodeCoverageGap{{Code: model.GapNodeAgentMissing, Detail: "node agent has not reported"}}}, st[0])
	require.Equal(t, model.AgentReporting, st[1].State)
	require.Equal(t, []model.NodeCoverageGap{blocked}, st[1].Coverage)
	require.Equal(t, "aaaa01", st[1].GroupID)
	require.Equal(t, "v0.1.0", st[1].AgentVersion)
	require.Equal(t, "7.0.0-34-generic", st[1].KernelRelease)
	require.Equal(t, model.AgentStale, st[2].State)
	require.Equal(t, []model.NodeCoverageGap{{Code: model.GapNodeAgentMissing,
		Detail: "node agent not reporting since 2026-11-19T22:00:00Z"}}, st[2].Coverage)
	one, ok, err := s.NodeAgentStatus(ctx, "worker-1", now, 30*time.Minute)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, st[1], one)
	_, ok, _ = s.NodeAgentStatus(ctx, "worker-9", now, 30*time.Minute)
	require.False(t, ok)
	edge, _, _ := s.NodeAgentStatus(ctx, "worker-1", now.Add(25*time.Minute), 30*time.Minute) // exactly staleAfter old
	require.Equal(t, model.AgentReporting, edge.State)
}

func TestNodeImages_StatusAndGroupUnion(t *testing.T) {
	s := newStore(t)
	groupNodes(t, s, t0, grouped{g: agentGroup("aaaa01"), members: []string{"worker-1", "worker-2"}}) // worker-3 is in no group
	require.NoError(t, s.ReplaceNodeImages(ctx, "worker-1", []model.NodeImage{
		{Digest: "sha256:m1", ConfigDigest: "sha256:c1", Kind: "manifest", Names: []string{"registry.example.com/app:1"}, SizeBytes: 1000, Complete: true, Source: "content-store"},
		{Digest: "sha256:m2", ConfigDigest: "sha256:c2", Complete: true, Source: "content-store"},
		{Digest: "sha256:m3", Source: "status"},
	}))
	require.NoError(t, s.ReplaceNodeImages(ctx, "worker-2", []model.NodeImage{
		{Digest: "sha256:m1", ConfigDigest: "sha256:c1", Names: []string{"registry.example.com/app:latest"}, SizeBytes: 900, Source: "status"},
	}))
	require.NoError(t, s.ReplaceNodeImages(ctx, "worker-3", []model.NodeImage{{Digest: "sha256:m9", Source: "status"}}))
	require.NoError(t, s.SetNodeImagesInUse(ctx, "worker-2", []string{"sha256:m1"}))
	require.NoError(t, s.UpsertImage(ctx, model.Image{Digest: "sha256:m1", Repo: "registry.example.com/app", Status: model.ImageCatalogued, Source: "registry"}))
	require.NoError(t, s.UpsertImage(ctx, model.Image{Digest: "sha256:c2", Repo: "registry.example.com/side", Status: model.ImageUnresolvable,
		StatusReason: "manifest unknown"})) // a side-loaded image is keyed by its config digest

	own, err := s.NodeImages(ctx, "worker-1")
	require.NoError(t, err)
	require.Equal(t, []model.NodeImage{
		{Digest: "sha256:m1", ConfigDigest: "sha256:c1", Kind: "manifest", Names: []string{"registry.example.com/app:1"}, SizeBytes: 1000,
			Complete: true, Nodes: []string{"worker-1"}, Status: model.ImageCatalogued, Source: "content-store"},
		{Digest: "sha256:m2", ConfigDigest: "sha256:c2", Kind: "manifest", Complete: true, Nodes: []string{"worker-1"},
			Status: model.ImageUnresolvable, StatusReason: "manifest unknown", Source: "content-store"},
		{Digest: "sha256:m3", Kind: "manifest", Nodes: []string{"worker-1"}, Source: "status"},
	}, own)

	grp, err := s.NodeGroupImages(ctx, "aaaa01")
	require.NoError(t, err)
	require.Len(t, grp, 3, "worker-3's image is not the group's")
	require.Equal(t, model.NodeImage{Digest: "sha256:m1", ConfigDigest: "sha256:c1", Kind: "manifest",
		Names: []string{"registry.example.com/app:1", "registry.example.com/app:latest"}, SizeBytes: 1000, Complete: true, InUse: true,
		Nodes: []string{"worker-1", "worker-2"}, Status: model.ImageCatalogued, Source: "both"}, grp[0])
	none, err := s.NodeGroupImages(ctx, "nope")
	require.NoError(t, err)
	require.Empty(t, none)
}

// TestAgentStatus_HostNotInventoriedAndUnsupported: a reporting node without a current host inventory
// carries host_not_inventoried and counts apart from fully reporting nodes; a node the agent DaemonSet
// does not schedule on carries node_agent_unsupported instead of node_agent_missing, never or stale.
func TestAgentStatus_HostNotInventoriedAndUnsupported(t *testing.T) {
	s := newStore(t)
	now := t0.Add(24 * time.Hour) // 2026-11-20T00:00:00Z
	names := []string{"arm-1", "w-error", "w-never", "w-ok", "w-overdue", "w-pending", "w-quar", "win-1"}
	var nodes []model.Node
	for _, n := range names {
		nodes = append(nodes, model.Node{Name: n, Ready: true})
	}
	require.NoError(t, s.ReplaceNodes(ctx, nodes))
	for _, n := range []string{"w-error", "w-ok", "w-pending", "w-quar"} {
		_, err := s.AcceptAgentReport(ctx, fullReport(n, "boot-a", t0, 1, now.Add(-time.Minute)))
		require.NoError(t, err)
	}
	_, err := s.AcceptAgentReport(ctx, fullReport("w-overdue", "boot-a", t0, 1, now.Add(-8*time.Hour)))
	require.NoError(t, err)
	heartbeat := fullReport("w-overdue", "boot-a", t0, 2, now.Add(-time.Minute))
	heartbeat.Full = false
	_, err = s.AcceptAgentReport(ctx, heartbeat)
	require.NoError(t, err)
	_, err = s.AcceptAgentReport(ctx, fullReport("win-1", "boot-a", t0, 1, now.Add(-3*time.Hour)))
	require.NoError(t, err)
	require.NoError(t, s.SetAgentError(ctx, "w-error", "host inventory not stored: decoding SBOM"))
	_, err = s.RecordAgentJobFailure(ctx, "nodehost:w-quar", "w-quar", "preparing the host inventory: panic", now.Add(-time.Hour), 1,
		24*time.Hour)
	require.NoError(t, err)
	require.NoError(t, s.PutNodeGroup(ctx, agentGroup("aaaa01"), now))
	require.NoError(t, s.ApplyNodeGrouping(ctx, NodeGrouping{Now: now, Fallback: []model.NodeGroup{nodeinfoGroup("ffff06")},
		Members: map[string]string{"w-error": "aaaa01", "w-ok": "aaaa01", "w-overdue": "aaaa01", "w-quar": "aaaa01",
			"w-pending": "ffff06", "w-never": "ffff06", "arm-1": "ffff06", "win-1": "ffff06"}}))
	state := NodesState{AgentEnabled: true, FullReportOverdue: 7 * time.Hour, Unsupported: map[string]string{
		"arm-1": "architecture arm64 is not in nodeAgent.architectures", "win-1": "node labels do not match nodeAgent.nodeSelector"}}
	require.NoError(t, s.PutNodesState(ctx, state))
	got, err := s.NodesState(ctx)
	require.NoError(t, err)
	require.Equal(t, state, got)

	st, err := s.AgentStatus(ctx, now, 30*time.Minute)
	require.NoError(t, err)
	byNode := map[string]model.NodeAgentStatus{}
	for _, x := range st {
		byNode[x.Node] = x
	}
	type want struct {
		state, count model.AgentState
		gap          model.NodeCoverageGap
	}
	notInventoried := func(detail string) model.NodeCoverageGap {
		return model.NodeCoverageGap{Code: model.GapHostNotInventoried, Detail: detail}
	}
	for node, w := range map[string]want{
		"w-pending": {model.AgentReporting, model.AgentReportingWithoutInventory, notInventoried("host packages not inventoried yet")},
		"w-error": {model.AgentReporting, model.AgentReportingWithoutInventory,
			notInventoried("host inventory not stored: decoding SBOM")},
		"w-quar": {model.AgentReporting, model.AgentReportingWithoutInventory,
			notInventoried("host inventory quarantined until 2026-11-20T23:00:00Z: preparing the host inventory: panic")},
		"w-overdue": {model.AgentReporting, model.AgentReportingWithoutInventory,
			notInventoried("no full host report since 2026-11-19T16:00:00Z")},
		"arm-1": {model.AgentNever, model.AgentUnsupported, model.NodeCoverageGap{Code: model.GapNodeAgentUnsupported,
			Detail: "not scheduled by the node agent: architecture arm64 is not in nodeAgent.architectures"}},
		"win-1": {model.AgentStale, model.AgentUnsupported, model.NodeCoverageGap{Code: model.GapNodeAgentUnsupported,
			Detail: "not scheduled by the node agent: node labels do not match nodeAgent.nodeSelector"}},
		"w-never": {model.AgentNever, model.AgentNever, model.NodeCoverageGap{Code: model.GapNodeAgentMissing,
			Detail: "node agent has not reported"}},
	} {
		x := byNode[node]
		require.Equal(t, w.state, x.State, node)
		require.Equal(t, w.count, x.CountState(), node)
		require.Equal(t, []model.NodeCoverageGap{w.gap}, x.Coverage, node)
	}
	ok := byNode["w-ok"]
	require.Equal(t, model.AgentReporting, ok.CountState())
	require.Empty(t, ok.Coverage)

	one, found, err := s.NodeAgentStatus(ctx, "w-quar", now, 30*time.Minute)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, byNode["w-quar"], one, "one node's status reads its own quarantine")

	// Disabled: every node is disabled with node_agent_missing, unsupported ones included.
	state.AgentEnabled = false
	require.NoError(t, s.PutNodesState(ctx, state))
	arm, _, err := s.NodeAgentStatus(ctx, "arm-1", now, 30*time.Minute)
	require.NoError(t, err)
	require.Equal(t, model.AgentDisabled, arm.CountState())
	require.Equal(t, model.GapNodeAgentMissing, arm.Coverage[0].Code)
}
