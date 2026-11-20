package store

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

// members reads node_group_members: node → group ID.
func members(t *testing.T, s *Store) map[string]string {
	t.Helper()
	rows, err := s.rdb.QueryContext(ctx, `SELECT node, group_id FROM node_group_members`)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var node, id string
		require.NoError(t, rows.Scan(&node, &id))
		out[node] = id
	}
	require.NoError(t, rows.Err())
	return out
}

// groupIDs reads the stored node group IDs, sorted.
func groupIDs(t *testing.T, s *Store) []string {
	t.Helper()
	ids, err := queryAll(ctx, s.rdb, scanString, `SELECT id FROM node_groups ORDER BY id`)
	require.NoError(t, err)
	return ids
}

// groupRow decodes one node_groups row.
func groupRow(t *testing.T, s *Store, id string) (g model.NodeGroup, first, last time.Time) {
	t.Helper()
	var (
		data string
		f, l int64
	)
	require.NoError(t, s.rdb.QueryRowContext(ctx, `SELECT data, first_seen, last_seen FROM node_groups WHERE id = ?`, id).
		Scan(&data, &f, &l))
	require.NoError(t, json.Unmarshal([]byte(data), &g))
	return g, time.Unix(0, f).UTC(), time.Unix(0, l).UTC()
}

// groupIDOf reads nodes_agent.group_id of node.
func groupIDOf(t *testing.T, s *Store, node string) string {
	t.Helper()
	var id string
	require.NoError(t, s.rdb.QueryRowContext(ctx, `SELECT group_id FROM nodes_agent WHERE node = ?`, node).Scan(&id))
	return id
}

// nodeImageRows reads node's node_images rows: digest → in_use.
func nodeImageRows(t *testing.T, s *Store, node string) map[string]bool {
	t.Helper()
	rows, err := s.rdb.QueryContext(ctx, `SELECT digest, in_use FROM node_images WHERE node = ?`, node)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	out := map[string]bool{}
	for rows.Next() {
		var (
			digest string
			inUse  bool
		)
		require.NoError(t, rows.Scan(&digest, &inUse))
		out[digest] = inUse
	}
	require.NoError(t, rows.Err())
	return out
}

func fullReport(node, boot string, started time.Time, seq uint64, at time.Time) AgentReport {
	return AgentReport{Node: node, AgentVersion: "v0.1.0", BootID: boot, Instance: "proc-a", StartedAt: started, Seq: seq, At: at,
		Full: true, KernelRelease: "7.0.0-34-generic", Arch: "amd64", PackageDB: "dpkg"}
}

func TestAcceptAgentReport_Idempotent(t *testing.T) {
	s := newStore(t)
	accept := func(r AgentReport) bool {
		t.Helper()
		ok, err := s.AcceptAgentReport(ctx, r)
		require.NoError(t, err)
		return ok
	}
	only := func() AgentNode {
		t.Helper()
		ns, err := s.AgentNodes(ctx)
		require.NoError(t, err)
		require.Len(t, ns, 1)
		return ns[0]
	}
	r := fullReport("worker-1", "boot-a", t0, 1, t0.Add(time.Minute))
	r.RebootPending, r.RebootReason = true, "installed kernel 7.0.0-38-generic is newer than the running kernel 7.0.0-34-generic"
	r.Coverage = []model.NodeCoverageGap{{Code: model.GapContentStoreUnreadable,
		Detail: "no containerd content store on this node; side-loaded images cannot be catalogued from it"}}
	r.Problems = []string{"content_store: not found"}
	require.True(t, accept(r))
	require.NoError(t, s.SetAgentFingerprint(ctx, "worker-1", "fp-1"))
	require.NoError(t, s.SetAgentError(ctx, "worker-1", "host SBOM refused"))
	require.False(t, accept(r), "the same (boot, instance, seq) is a duplicate")
	lower := r
	lower.Seq = 0
	require.False(t, accept(lower), "a lower sequence of the same process is stale")
	stored, ok, err := s.AgentNode(ctx, "worker-1")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "proc-a", stored.Instance)
	_, ok, err = s.AgentNode(ctx, "cp-1")
	require.NoError(t, err)
	require.False(t, ok)

	img := r
	img.Seq, img.Full, img.At, img.KernelRelease = 2, false, t0.Add(2*time.Minute), "ignored"
	require.True(t, accept(img))
	n := only()
	require.Equal(t, uint64(2), n.Seq)
	require.Equal(t, t0.Add(2*time.Minute), n.LastReport)
	require.Equal(t, t0.Add(time.Minute), n.LastFullReport)
	require.Equal(t, "7.0.0-34-generic", n.KernelRelease, "an images-only report leaves the host fields")
	require.Equal(t, r.Coverage, n.Coverage, "an images-only report writes the coverage it carries")
	require.Equal(t, r.Problems, n.Problems)
	require.True(t, n.RebootPending)
	require.Equal(t, "fp-1", n.Fingerprint, "reports never touch the fingerprint")
	require.Equal(t, "host SBOM refused", n.LastError, "only a full report clears the error")

	full := fullReport("worker-1", "boot-a", t0, 3, t0.Add(3*time.Minute))
	require.True(t, accept(full))
	n = only()
	require.Empty(t, n.LastError)
	require.Nil(t, n.Coverage)
	require.False(t, n.RebootPending)
	require.Equal(t, "fp-1", n.Fingerprint)

	cleared := img
	cleared.Seq, cleared.Coverage = 4, nil
	require.True(t, accept(cleared))
	require.Nil(t, only().Coverage)

	require.True(t, accept(fullReport("worker-1", "boot-b", t0.Add(-time.Hour), 1, t0.Add(4*time.Minute))), "a new boot is always applied")
	require.Error(t, s.SetAgentFingerprint(ctx, "cp-1", "fp-x"), "cp-1 never reported")
	require.Error(t, s.SetAgentError(ctx, "cp-1", "x"))
}

// TestAcceptAgentReport_OrderedByInstanceNotClock: the wall clock steps back and the agent restarts within
// the same boot. The new process starts "earlier" and at sequence 1, and its reports are applied; only a
// replay of the same process's sequence is a duplicate.
func TestAcceptAgentReport_OrderedByInstanceNotClock(t *testing.T) {
	s := newStore(t)
	accept := func(r AgentReport) bool {
		t.Helper()
		ok, err := s.AcceptAgentReport(ctx, r)
		require.NoError(t, err)
		return ok
	}
	first := fullReport("worker-1", "boot-a", t0.Add(time.Hour), 40, t0.Add(time.Hour))
	first.Instance = "proc-a"
	require.True(t, accept(first))

	stepped := fullReport("worker-1", "boot-a", t0, 1, t0.Add(time.Hour+time.Minute)) // started "before" proc-a
	stepped.Instance = "proc-b"
	require.True(t, accept(stepped), "a new process of the same boot is applied whatever its clock says")
	next := stepped
	next.Seq, next.At = 2, next.At.Add(5*time.Minute)
	require.True(t, accept(next))
	require.False(t, accept(stepped), "a replay of proc-b's first report is a duplicate")
	rows, err := s.AgentNodes(ctx)
	require.NoError(t, err)
	require.Equal(t, "proc-b", rows[0].Instance)
	require.Equal(t, uint64(2), rows[0].Seq)
	require.Equal(t, t0, rows[0].StartedAt, "the start is stored as reported")
}

func agentGroup(id string) model.NodeGroup {
	return model.NodeGroup{ID: id, Kind: model.NodeGroupAgent, Name: "ubuntu-26.04-k7.0.0-34", Label: "ubuntu-26.04-k7.0.0-34-" + id,
		Digest: "nodegroup:" + id, OSImage: "Ubuntu 26.04 LTS", KernelRelease: "7.0.0-34-generic", PackageDB: "dpkg", PackageCount: 812}
}

func nodeinfoGroup(id string) model.NodeGroup {
	return model.NodeGroup{ID: id, Kind: model.NodeGroupNodeInfo, Name: "ubuntu-26.04-k7.0.0-34", Label: "ubuntu-26.04-k7.0.0-34-" + id}
}

func TestApplyNodeGrouping(t *testing.T) {
	s := newStore(t)
	a, pending, orphan := agentGroup("aaaa01"), agentGroup("bbbb02"), agentGroup("cccc03")
	for _, g := range []model.NodeGroup{a, pending, orphan} {
		require.NoError(t, s.PutNodeGroup(ctx, g, t0))
	}
	for node, fp := range map[string]string{"worker-1": a.ID, "worker-2": pending.ID} {
		_, err := s.AcceptAgentReport(ctx, fullReport(node, "boot-a", t0, 1, t0))
		require.NoError(t, err)
		require.NoError(t, s.SetAgentFingerprint(ctx, node, fp))
	}
	require.NoError(t, s.ApplyNodeGrouping(ctx, NodeGrouping{Now: t0, Fallback: []model.NodeGroup{nodeinfoGroup("dddd04")},
		Members: map[string]string{"worker-1": a.ID, "worker-2": a.ID, "cp-1": "dddd04"}}))
	require.Equal(t, a.ID, groupIDOf(t, s, "worker-2"))

	now := t0.Add(time.Hour)
	require.NoError(t, s.ApplyNodeGrouping(ctx, NodeGrouping{Now: now, Fallback: []model.NodeGroup{nodeinfoGroup("eeee05")},
		Members: map[string]string{"worker-1": a.ID, "worker-2": "eeee05", "cp-1": "eeee05"},
		Exposed: map[string][]string{a.ID: {"worker-1"}}}))
	require.Equal(t, map[string]string{"worker-1": a.ID, "worker-2": "eeee05", "cp-1": "eeee05"}, members(t, s))
	// dddd04: memberless nodeinfo; cccc03: memberless and named by no fingerprint; bbbb02 is worker-2's pending fingerprint
	require.Equal(t, []string{"aaaa01", "bbbb02", "eeee05"}, groupIDs(t, s))
	require.Equal(t, a.ID, groupIDOf(t, s, "worker-1"))
	require.Equal(t, "", groupIDOf(t, s, "worker-2"), "a node in a nodeinfo group has no agent group")
	g, first, last := groupRow(t, s, a.ID)
	require.Equal(t, []string{"worker-1"}, g.ExposedNodes)
	require.Equal(t, t0, first)
	require.Equal(t, now, last)
	_, _, last = groupRow(t, s, pending.ID)
	require.Equal(t, t0, last, "a memberless group is not seen")

	a.PackageCount, a.Members = 900, []string{"ignored"}
	require.NoError(t, s.PutNodeGroup(ctx, a, now.Add(time.Hour)))
	g, first, last = groupRow(t, s, a.ID)
	require.Equal(t, 900, g.PackageCount)
	require.Equal(t, []string{"worker-1"}, g.ExposedNodes, "PutNodeGroup keeps the exposure")
	require.Equal(t, t0, first)
	require.Equal(t, now, last)
	require.Equal(t, map[string]string{"worker-1": a.ID, "worker-2": "eeee05", "cp-1": "eeee05"}, members(t, s), "PutNodeGroup ignores Members")
}

func TestPruneAgentNodes(t *testing.T) {
	s := newStore(t)
	for _, n := range []string{"worker-1", "worker-2"} {
		_, err := s.AcceptAgentReport(ctx, fullReport(n, "boot-a", t0, 1, t0))
		require.NoError(t, err)
		require.NoError(t, s.ReplaceNodeImages(ctx, n, []model.NodeImage{{Digest: "sha256:m1", Source: "content-store"}}))
	}
	require.NoError(t, s.PutNodeGroup(ctx, agentGroup("aaaa01"), t0))
	require.NoError(t, s.ApplyNodeGrouping(ctx, NodeGrouping{Now: t0, Members: map[string]string{"worker-1": "aaaa01", "worker-2": "aaaa01"}}))
	for _, n := range []string{"worker-1", "worker-2"} {
		_, err := s.RecordAgentJobFailure(ctx, "nodehost:"+n, n, "the controller stopped while processing the host inventory", t0, 2, 24*time.Hour)
		require.NoError(t, err)
		_, err = s.BeginAcquire(ctx, "nodehost:"+n, t0) // left by a controller that stopped
		require.NoError(t, err)
	}
	_, err := s.BeginAcquire(ctx, "sha256:image", t0)
	require.NoError(t, err)
	require.Error(t, s.PruneAgentNodes(ctx, nil), "no live nodes: refuse rather than wipe")
	require.NoError(t, s.PruneAgentNodes(ctx, []string{"worker-1", "cp-1"}))
	ns, err := s.AgentNodes(ctx)
	require.NoError(t, err)
	require.Len(t, ns, 1)
	require.Equal(t, "worker-1", ns[0].Node)
	require.Equal(t, map[string]string{"worker-1": "aaaa01"}, members(t, s))
	require.Empty(t, nodeImageRows(t, s, "worker-2"))
	_, ok, err := s.AgentJobOf(ctx, "nodehost:worker-2")
	require.NoError(t, err)
	require.False(t, ok, "a pruned node's host poison-pill row goes too")
	_, ok, _ = s.AgentJobOf(ctx, "nodehost:worker-1")
	require.True(t, ok)
	inflight, err := queryAll(ctx, s.rdb, scanString, `SELECT digest FROM acquisitions_inflight ORDER BY digest`)
	require.NoError(t, err)
	require.Equal(t, []string{"nodehost:worker-1", "sha256:image"}, inflight, "a pruned node's host acquisition record goes too")
}

func TestNodeImages_InUseAcrossReplace(t *testing.T) {
	s := newStore(t)
	img := func(d, cfg string) model.NodeImage {
		return model.NodeImage{Digest: d, ConfigDigest: cfg, Names: []string{"registry.example.com/app:1"}, SizeBytes: 1000,
			Complete: true, Source: "both"}
	}
	require.NoError(t, s.ReplaceNodeImages(ctx, "worker-1", []model.NodeImage{img("sha256:m1", "sha256:c1"), img("sha256:m2", "sha256:c2")}))
	require.NoError(t, s.SetNodeImagesInUse(ctx, "worker-1", []string{"sha256:c2"})) // by config digest
	require.Equal(t, map[string]bool{"sha256:m1": false, "sha256:m2": true}, nodeImageRows(t, s, "worker-1"))
	require.NoError(t, s.ReplaceNodeImages(ctx, "worker-1", []model.NodeImage{img("sha256:m2", "sha256:c2"), img("sha256:m3", "sha256:c3")}))
	require.Equal(t, map[string]bool{"sha256:m2": true, "sha256:m3": false}, nodeImageRows(t, s, "worker-1"))
	require.NoError(t, s.SetNodeImagesInUse(ctx, "worker-1", []string{"sha256:m3"}))
	require.Equal(t, map[string]bool{"sha256:m2": false, "sha256:m3": true}, nodeImageRows(t, s, "worker-1"))
	var kind string
	require.NoError(t, s.rdb.QueryRowContext(ctx, `SELECT kind FROM node_images WHERE digest = 'sha256:m3'`).Scan(&kind))
	require.Equal(t, "manifest", kind)
}

func TestSetImageStatusReason_OnlyUnresolvable(t *testing.T) {
	s := newStore(t)
	require.NoError(t, s.UpsertImage(ctx, model.Image{Digest: "sha256:u", Repo: "registry.example.com/app", Status: model.ImageUnresolvable, StatusReason: "old"}))
	require.NoError(t, s.UpsertImage(ctx, model.Image{Digest: "sha256:c", Repo: "registry.example.com/app", Status: model.ImageCatalogued}))
	for digest, want := range map[string]bool{"sha256:u": true, "sha256:c": false, "sha256:missing": false} {
		ok, err := s.SetImageStatusReason(ctx, digest, "layers discarded")
		require.NoError(t, err)
		require.Equal(t, want, ok, digest)
	}
	img, _, _ := s.GetImage(ctx, "sha256:u")
	require.Equal(t, "layers discarded", img.StatusReason)
	img, _, _ = s.GetImage(ctx, "sha256:c")
	require.Empty(t, img.StatusReason)
}

func TestAgentProvenanceJobsAndNodesState(t *testing.T) {
	s := newStore(t)
	p := AgentProvenance{Digest: "sha256:side", Node: "worker-1", AgentVersion: "v0.1.0", ReceivedAt: t0}
	require.NoError(t, s.PutAgentProvenance(ctx, p))
	got, ok, err := s.AgentProvenanceOf(ctx, p.Digest)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, p, got)
	require.NoError(t, s.ClearAgentProvenance(ctx, p.Digest))
	_, ok, _ = s.AgentProvenanceOf(ctx, p.Digest)
	require.False(t, ok)

	job, err := s.RecordAgentJobFailure(ctx, "sha256:side", "worker-1", "cataloguer out of memory", t0, 2, 24*time.Hour)
	require.NoError(t, err)
	require.Equal(t, AgentJob{Digest: "sha256:side", Attempts: 1, LastError: "cataloguer out of memory", LastNode: "worker-1", LastAttempt: t0}, job)
	job, err = s.RecordAgentJobFailure(ctx, "sha256:side", "worker-2", "timed out", t0.Add(time.Hour), 2, 24*time.Hour)
	require.NoError(t, err)
	require.Equal(t, 2, job.Attempts)
	require.Equal(t, t0.Add(25*time.Hour), job.QuarantinedUntil)
	stored, ok, err := s.AgentJobOf(ctx, "sha256:side")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, job, stored)
	require.NoError(t, s.ClearAgentJob(ctx, "sha256:side"))
	_, ok, _ = s.AgentJobOf(ctx, "sha256:side")
	require.False(t, ok)

	st, err := s.NodesState(ctx)
	require.NoError(t, err)
	require.Equal(t, NodesState{}, st)
	want := NodesState{AgentEnabled: true, RuntimeRetired: true, NotFreshSince: t0, ChangedAt: t0.Add(time.Hour), BaselineReadyAt: t0.Add(2 * time.Hour)}
	require.NoError(t, s.PutNodesState(ctx, want))
	st, err = s.NodesState(ctx)
	require.NoError(t, err)
	require.Equal(t, want, st)
}

func TestPruneImages_DropsAgentRows(t *testing.T) {
	s := newStore(t)
	for _, d := range []string{"sha256:gone", "sha256:kept"} {
		require.NoError(t, s.UpsertImage(ctx, model.Image{Digest: d, Repo: "registry.example.com/app", Status: model.ImageCatalogued, Source: "agent"}))
		require.NoError(t, s.PutAgentProvenance(ctx, AgentProvenance{Digest: d, Node: "worker-1", AgentVersion: "v0.1.0", ReceivedAt: t0}))
		_, err := s.RecordAgentJobFailure(ctx, d, "worker-1", "timed out", t0, 2, 24*time.Hour)
		require.NoError(t, err)
	}
	require.NoError(t, s.UpsertOwner(ctx, model.Owner{Ref: model.OwnerRef{Kind: "Deployment", Namespace: "shop", Name: "web"},
		Containers: []model.ContainerUse{{Name: "web", Repo: "registry.example.com/app", Digest: "sha256:kept"}}}))
	week := 7 * 24 * time.Hour
	_, err := s.PruneImages(ctx, t0, week)
	require.NoError(t, err)
	n, err := s.PruneImages(ctx, t0.Add(8*24*time.Hour), week)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	for d, want := range map[string]bool{"sha256:gone": false, "sha256:kept": true} {
		_, ok, err := s.AgentProvenanceOf(ctx, d)
		require.NoError(t, err)
		require.Equal(t, want, ok, d)
		_, ok, err = s.AgentJobOf(ctx, d)
		require.NoError(t, err)
		require.Equal(t, want, ok, d)
	}
}

// TestApplyNodeGrouping_UnchangedWritesNothing: a grouping, with its in-use sets, applied again writes no
// row; a change writes only what changed.
func TestApplyNodeGrouping_UnchangedWritesNothing(t *testing.T) {
	s := newStore(t)
	a := agentGroup("aaaa01")
	require.NoError(t, s.PutNodeGroup(ctx, a, t0))
	for _, n := range []string{"worker-1", "worker-2"} {
		_, err := s.AcceptAgentReport(ctx, fullReport(n, "boot-a", t0, 1, t0))
		require.NoError(t, err)
		require.NoError(t, s.SetAgentFingerprint(ctx, n, a.ID))
		require.NoError(t, s.ReplaceNodeImages(ctx, n, []model.NodeImage{{Digest: "sha256:m1", ConfigDigest: "sha256:c1", Source: "content-store"},
			{Digest: "sha256:m2", Source: "content-store"}}))
	}
	ng := NodeGrouping{Now: t0, Fallback: []model.NodeGroup{nodeinfoGroup("ffff06")},
		Members: map[string]string{"worker-1": a.ID, "worker-2": a.ID, "cp-1": "ffff06"},
		Exposed: map[string][]string{a.ID: {"worker-2", "worker-1"}},
		InUse:   map[string][]string{"worker-1": {"sha256:c1"}, "worker-2": nil}}
	require.NoError(t, s.ApplyNodeGrouping(ctx, ng))
	require.Equal(t, map[string]bool{"sha256:m1": true, "sha256:m2": false}, nodeImageRows(t, s, "worker-1"))
	g, _, _ := groupRow(t, s, a.ID)
	require.Equal(t, []string{"worker-1", "worker-2"}, g.ExposedNodes)

	changes := func() int64 {
		t.Helper()
		n, err := s.WriteChanges(ctx)
		require.NoError(t, err)
		return n
	}
	before := changes()
	ng.Now = t0.Add(9 * time.Minute) // within lastSeenEvery
	require.NoError(t, s.ApplyNodeGrouping(ctx, ng))
	require.Equal(t, before, changes(), "an unchanged grouping writes nothing")

	ng.InUse = map[string][]string{"worker-1": {"sha256:c1", "sha256:m2"}}
	require.NoError(t, s.ApplyNodeGrouping(ctx, ng))
	require.Equal(t, before+1, changes(), "one image row changed")
	require.Equal(t, map[string]bool{"sha256:m1": true, "sha256:m2": true}, nodeImageRows(t, s, "worker-1"))

	before = changes()
	ng.Now = t0.Add(10 * time.Minute)
	require.NoError(t, s.ApplyNodeGrouping(ctx, ng))
	require.Equal(t, before+2, changes(), "the two groups with members are seen again after lastSeenEvery")
	_, _, last := groupRow(t, s, a.ID)
	require.Equal(t, t0.Add(10*time.Minute), last)

	ng.Members["worker-2"] = "ffff06"
	ng.Exposed = nil
	require.NoError(t, s.ApplyNodeGrouping(ctx, ng))
	require.Equal(t, map[string]string{"worker-1": a.ID, "worker-2": "ffff06", "cp-1": "ffff06"}, members(t, s))
	require.Equal(t, "", groupIDOf(t, s, "worker-2"))
	g, _, _ = groupRow(t, s, a.ID)
	require.Nil(t, g.ExposedNodes)
}

func TestHeldCompleteElsewhere(t *testing.T) {
	s := newStore(t)
	for _, n := range []string{"worker-1", "worker-2"} {
		_, err := s.AcceptAgentReport(ctx, fullReport(n, "boot-a", t0, 1, t0))
		require.NoError(t, err)
	}
	require.NoError(t, s.ReplaceNodeImages(ctx, "worker-1", []model.NodeImage{{Digest: "sha256:m1", Complete: true, Source: "content-store"}}))
	require.NoError(t, s.ReplaceNodeImages(ctx, "worker-2", []model.NodeImage{
		{Digest: "sha256:m2", ConfigDigest: "sha256:c2", Complete: true, Source: "content-store"},
		{Digest: "sha256:idx", Kind: "index", Complete: true, Source: "content-store"},
		{Digest: "sha256:m3", Source: "content-store"}, // incomplete
	}))
	require.NoError(t, s.ReplaceNodeImages(ctx, "gone-1", []model.NodeImage{{Digest: "sha256:m3", Complete: true, Source: "content-store"}}))
	for _, tc := range []struct {
		digest, index, except string
		want                  bool
	}{
		{"sha256:m1", "", "worker-2", true},
		{"sha256:m1", "", "worker-1", false},
		{"sha256:c2", "", "worker-1", true}, // by config digest
		{"sha256:mx", "sha256:idx", "worker-1", true},
		{"sha256:mx", "", "worker-1", false},
		{"sha256:m3", "", "worker-1", false}, // incomplete, and gone-1 has no agent report
	} {
		got, err := s.HeldCompleteElsewhere(ctx, tc.digest, tc.index, tc.except)
		require.NoError(t, err)
		require.Equal(t, tc.want, got, "%+v", tc)
	}
}
