package apiserver_test

import (
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/web/apigen"
	"github.com/the-it-dept/ffs/internal/web/webtest"
)

// f13 is Small's one host finding: openssl on the agent group, on the Nodes owner.
var f13 = model.FindingFingerprint(webtest.ClusterName, model.NodesOwner(webtest.ClusterName), model.HostRepo, "CVE-2026-0012")

func cachedDigests(imgs []apigen.NodeImage) []string {
	out := []string{}
	for _, img := range imgs {
		out = append(out, img.Digest)
	}
	return out
}

func gapCodes(gaps []apigen.NodeGap) []apigen.GapCode {
	var out []apigen.GapCode
	for _, g := range gaps {
		out = append(out, g.Code)
	}
	return out
}

func TestNodeGroups_ListsAgentThenNodeInfoWithControlPlane(t *testing.T) {
	_, h := newAPI(t)
	got := ok[apigen.NodeGroupsList](t, get(t, h, "/api/v1/nodegroups"))
	require.True(t, got.AgentEnabled)
	require.Len(t, got.Groups, 2)

	g := got.Groups[0]
	require.Equal(t, webtest.AgentGroupKey, g.Id, "a group is named by its stable name")
	require.Equal(t, apigen.NodeGroupKindAgent, g.Kind)
	require.Equal(t, "ubuntu-24.04-k6.8.0-88-3f9c1a", g.Label)
	require.Equal(t, 2, g.Members)
	require.Equal(t, 1, g.ExposedNodes)
	require.Equal(t, apigen.PriorityCounts{High: 1}, g.Counts)
	require.Equal(t, 1, g.Fixable)
	require.Equal(t, apigen.AgentCounts{Reporting: 1, Stale: 1}, g.Agents)
	require.Equal(t, &[]apigen.GapCode{apigen.GapCodeNodeAgentMissing}, g.Gaps, "worker-2 is stale")
	require.Empty(t, g.Drift, "the largest group of its architecture is the base")

	cp := got.Groups[1]
	require.Equal(t, webtest.CP1GroupKey, cp.Id)
	require.Equal(t, apigen.NodeGroupKindNodeinfo, cp.Kind)
	require.Equal(t, 1, cp.Members)
	require.Equal(t, apigen.PriorityCounts{}, cp.Counts)
	require.Equal(t, apigen.AgentCounts{Never: 1}, cp.Agents)
	require.NotEmpty(t, cp.Drift)
	require.Contains(t, cp.Drift, "kernel")

	c := got.ControlPlane
	require.Len(t, c.Kubernetes, 1)
	require.Equal(t, "1.34.2", c.Kubernetes[0].Version)
	require.Equal(t, 3, c.Kubernetes[0].Nodes)
	require.NotNil(t, c.Kubernetes[0].Eol)
	require.True(t, c.Kubernetes[0].Eol.IsEol)
	require.Len(t, c.Runtimes, 1)
	require.Equal(t, "containerd", c.Runtimes[0].Name)
	require.Equal(t, "2.2.1", c.Runtimes[0].Version)
	require.Equal(t, 3, c.Runtimes[0].Nodes)
	require.Equal(t, apigen.PriorityCounts{High: 1, Medium: 1}, c.Counts)
	require.Equal(t, 2, c.Fixable)
	require.NotNil(t, c.Suggestions)
	require.Empty(t, c.Suggestions)
}

func TestNodeGroup_MembersDriftAndCompare(t *testing.T) {
	_, h := newAPI(t)
	got := ok[apigen.NodeGroupDetail](t, get(t, h, "/api/v1/nodegroups/"+webtest.AgentGroupID+"?compare="+webtest.CP1GroupID))
	require.Equal(t, webtest.AgentGroupKey, got.Group.Id)
	require.Equal(t, "nodegroup:"+webtest.AgentGroupID, got.Group.Digest)
	require.True(t, got.AgentData)
	require.Len(t, got.Members, 2)
	w1, w2 := got.Members[0], got.Members[1]
	require.Equal(t, "worker-1", w1.Name)
	require.True(t, w1.Ready)
	require.True(t, w1.Exposed)
	require.Equal(t, apigen.AgentStateReporting, w1.Agent.State)
	require.NotNil(t, w1.Agent.LastReport)
	require.True(t, webtest.Now.Add(-5*time.Minute).Equal(*w1.Agent.LastReport))
	require.Equal(t, "worker-2", w2.Name)
	require.False(t, w2.Exposed)
	require.Equal(t, apigen.AgentStateStale, w2.Agent.State)
	require.Contains(t, gapCodes(w2.Agent.Gaps), apigen.GapCodeNodeAgentMissing)

	require.Len(t, got.Drift, 1)
	d := got.Drift[0]
	require.Equal(t, apigen.GroupRef{Id: webtest.CP1GroupKey, Kind: apigen.NodeGroupKindNodeinfo, Label: d.Other.Label}, d.Other)
	require.Contains(t, d.Fields, apigen.FieldDrift{Field: "kernel", From: "6.8.0-85-generic", To: "6.8.0-88-generic"},
		"here (to) is this group, there (from) the other")
	require.False(t, d.PackagesCompared)
	require.Contains(t, d.Summary, "kernel")

	require.NotNil(t, got.Compare)
	require.False(t, got.Compare.PackagesCompared)
	require.Equal(t, webtest.CP1GroupKey, got.Compare.From)
	require.Equal(t, webtest.AgentGroupKey, got.Compare.To)
	require.Equal(t, d.Fields, got.Compare.Fields)
	require.Contains(t, cachedDigests(got.CachedImages), webtest.DigestWeb)
	require.NotNil(t, got.Group.Kernel)
	require.Equal(t, "6.8.0-88-generic", got.Group.Kernel.Release)
	require.Equal(t, apigen.PriorityCounts{High: 1}, got.Counts)
	require.Equal(t, 1, got.Fixable)

	cp := ok[apigen.NodeGroupDetail](t, get(t, h, "/api/v1/nodegroups/"+webtest.CP1GroupID))
	require.False(t, cp.AgentData)
	require.NotNil(t, cp.CachedImages)
	require.Empty(t, cp.CachedImages)
	require.Nil(t, cp.Compare)
	require.Equal(t, apigen.AgentStateNever, cp.Members[0].Agent.State)

	p := wantProblem(t, get(t, h, "/api/v1/nodegroups/nope"), 404, apigen.ProblemCodeNotFound)
	require.NotNil(t, p.Detail)
	require.Contains(t, *p.Detail, "nope")
	p = wantProblem(t, get(t, h, "/api/v1/nodegroups/"+webtest.AgentGroupID+"?compare=nope"), 404, apigen.ProblemCodeNotFound)
	require.Contains(t, *p.Detail, "nope")
}

func TestNode_ResolvesGroupAndAgent(t *testing.T) {
	_, h := newAPI(t)
	got := ok[apigen.NodeDetail](t, get(t, h, "/api/v1/nodes/worker-2"))
	require.NotNil(t, got.Group)
	require.Equal(t, webtest.AgentGroupKey, got.Group.Id)
	require.Equal(t, apigen.NodeGroupKindAgent, got.Group.Kind)
	require.Equal(t, apigen.AgentStateStale, got.Agent.State)
	require.False(t, got.Exposed)
	require.Equal(t, apigen.PriorityCounts{High: 1}, got.Counts)
	require.Equal(t, "Ubuntu 24.04.4 LTS", got.Node.OsImage)
	require.NotNil(t, got.Node.OsEol)
	require.Equal(t, "ubuntu", got.Node.OsEol.Product)

	w1 := ok[apigen.NodeDetail](t, get(t, h, "/api/v1/nodes/worker-1"))
	require.True(t, w1.Exposed)

	cp := ok[apigen.NodeDetail](t, get(t, h, "/api/v1/nodes/cp-1"))
	require.NotNil(t, cp.Group)
	require.Equal(t, apigen.NodeGroupKindNodeinfo, cp.Group.Kind)
	require.Equal(t, apigen.AgentStateNever, cp.Agent.State)
	require.Nil(t, cp.Agent.LastReport, "report times are left out until there is one")
	require.Equal(t, apigen.PriorityCounts{}, cp.Counts)

	wantProblem(t, get(t, h, "/api/v1/nodes/missing"), 404, apigen.ProblemCodeNotFound)
}

func TestNodes_FallbackGroupsWithoutStoredGroups(t *testing.T) {
	f := webtest.Open(t)
	webtest.ExecSQL(t, f.Store, `DELETE FROM node_group_members`)
	h := handlerOf(f)
	got := ok[apigen.NodeGroupsList](t, get(t, h, "/api/v1/nodegroups"))
	require.NotEmpty(t, got.Groups)
	members := 0
	for _, g := range got.Groups {
		require.Equal(t, apigen.NodeGroupKindNodeinfo, g.Kind, g.Label)
		members += g.Members
	}
	require.Equal(t, 3, members, "cp-1, worker-1 and worker-2")
	detail := map[string][]string{}
	for _, g := range got.Groups {
		d := ok[apigen.NodeGroupDetail](t, get(t, h, "/api/v1/nodegroups/"+g.Id))
		for _, m := range d.Members {
			detail[g.Id] = append(detail[g.Id], m.Name)
		}
	}
	var all []string
	for _, ms := range detail {
		all = append(all, ms...)
	}
	require.ElementsMatch(t, []string{"cp-1", "worker-1", "worker-2"}, all)

	w1 := ok[apigen.NodeDetail](t, get(t, h, "/api/v1/nodes/worker-1"))
	require.NotNil(t, w1.Group)
	require.Equal(t, apigen.NodeGroupKindNodeinfo, w1.Group.Kind)
}

func TestNodes_FallbackMergesIntoStoredGroup(t *testing.T) {
	f := webtest.Open(t)
	nodes, err := f.Store.ListNodes(t.Context())
	require.NoError(t, err)
	i := slices.IndexFunc(nodes, func(n model.Node) bool { return n.Name == "cp-1" })
	require.GreaterOrEqual(t, i, 0)
	cp2 := nodes[i]
	cp2.Name = "cp-2" // cp-1's node status, in no stored group
	require.NoError(t, f.Store.ReplaceNodes(t.Context(), append(nodes, cp2)))

	got := ok[apigen.NodeGroupsList](t, get(t, handlerOf(f), "/api/v1/nodegroups"))
	var rows []apigen.NodeGroupRow
	for _, g := range got.Groups {
		if g.Id == webtest.CP1GroupKey {
			rows = append(rows, g)
		}
	}
	require.Len(t, rows, 1)
	require.Equal(t, 2, rows[0].Members)
	require.Len(t, got.Groups, 2)

	d := ok[apigen.NodeDetail](t, get(t, handlerOf(f), "/api/v1/nodes/cp-2"))
	require.NotNil(t, d.Group)
	require.Equal(t, webtest.CP1GroupKey, d.Group.Id)
}

func TestNodes_CachedImagesOnlyFromLiveAgents(t *testing.T) {
	f, h := newAPI(t)
	w1 := ok[apigen.NodeDetail](t, get(t, h, "/api/v1/nodes/worker-1"))
	require.Contains(t, cachedDigests(w1.CachedImages), webtest.DigestWeb)
	img := w1.CachedImages[slices.Index(cachedDigests(w1.CachedImages), webtest.DigestWeb)]
	require.Equal(t, []string{"worker-1"}, img.Nodes)
	require.NotNil(t, img.Status)
	require.Equal(t, apigen.ImageStatusCatalogued, *img.Status)

	require.NoError(t, f.Store.ReplaceNodeImages(t.Context(), "cp-1", []model.NodeImage{{Digest: webtest.DigestWeb,
		Names: []string{"docker.io/library/nginx:1.30.6"}, Kind: "manifest", Source: "status"}}))
	cp := ok[apigen.NodeDetail](t, get(t, h, "/api/v1/nodes/cp-1"))
	require.Equal(t, apigen.AgentStateNever, cp.Agent.State)
	require.NotNil(t, cp.CachedImages)
	require.Empty(t, cp.CachedImages)
	g := ok[apigen.NodeGroupDetail](t, get(t, h, "/api/v1/nodegroups/"+webtest.CP1GroupID))
	require.NotNil(t, g.CachedImages)
	require.Empty(t, g.CachedImages)
}

func TestNodeScope_FindingsResolveToGroup(t *testing.T) {
	_, h := newAPI(t)
	got := ok[apigen.FindingsPage](t, get(t, h, "/api/v1/findings?scope=node:worker-1"))
	require.Equal(t, 1, got.Total)
	require.Len(t, got.Rows, 1)
	require.Equal(t, f13, got.Rows[0].Id)
	require.Equal(t, apigen.FixKindPackage, got.Rows[0].Fix.Kind, "host findings never get a rebuild action")
	require.Equal(t, "package:deb:openssl:3.0.13-0ubuntu3:3.0.13-0ubuntu3.1", got.Rows[0].Fix.Key)

	got = ok[apigen.FindingsPage](t, get(t, h, "/api/v1/findings?scope=node:cp-1"))
	require.Zero(t, got.Total)
	require.Empty(t, got.Rows)

	p := wantProblem(t, get(t, h, "/api/v1/findings?scope=node:missing"), 404, apigen.ProblemCodeNotFound)
	require.Contains(t, *p.Detail, "missing")

	got = ok[apigen.FindingsPage](t, get(t, h, "/api/v1/findings?scope=nodegroup:"+webtest.AgentGroupID))
	require.Equal(t, 1, got.Total)
	require.Equal(t, f13, got.Rows[0].Id)
}

func TestNodeAgentFields(t *testing.T) {
	_, h := newAPI(t)
	settings := ok[apigen.Settings](t, get(t, h, "/api/v1/settings"))
	require.Equal(t, &apigen.NodeAgentSettings{Enabled: true, StaleAfter: "30m0s"}, settings.NodeAgent)

	img := ok[apigen.ImageDetail](t, get(t, h, "/api/v1/images/"+url.PathEscape("nodegroup:"+webtest.AgentGroupID)))
	require.Equal(t, "agent", img.Sbom.Source)
	require.NotNil(t, img.Sbom.Agent)
	require.Equal(t, "worker-1", img.Sbom.Agent.Node)
	require.Equal(t, "v0.1.0", img.Sbom.Agent.AgentVersion)
	require.True(t, webtest.Now.Add(-5*time.Minute).Equal(img.Sbom.Agent.ReceivedAt))
	web := ok[apigen.ImageDetail](t, get(t, h, "/api/v1/images/"+webtest.DigestWeb))
	require.Nil(t, web.Sbom.Agent, "a registry SBOM has no agent provenance")

	res := ok[apigen.SearchResult](t, get(t, h, "/api/v1/search?q=ubuntu"))
	hit := hitOf(t, res, apigen.SearchHitKindNodegroup, webtest.AgentGroupKey)
	require.Equal(t, "ubuntu-24.04-k6.8.0-88-3f9c1a", hit.Label)
	require.NotNil(t, hit.Scope)
	require.Equal(t, "nodegroup:"+webtest.AgentGroupKey, *hit.Scope)
	require.NotNil(t, hit.Detail)
	require.Equal(t, "2 nodes", *hit.Detail)
}

// Agent counts follow each member's CountState: a reporting agent whose host inventory is not stored
// counts as reportingWithoutInventory, not reporting, and a node the agent does not schedule on as
// unsupported, not never.
func TestNodeGroups_AgentCountsByCountState(t *testing.T) {
	f := webtest.Open(t)
	agentReport(t, f, "worker-1", time.Minute, string(apigen.GapCodeHostNotInventoried))
	st, err := f.Store.NodesState(t.Context())
	require.NoError(t, err)
	st.Unsupported = map[string]string{"cp-1": "architecture arm64 is not in nodeAgent.architectures"}
	require.NoError(t, f.Store.PutNodesState(t.Context(), st))

	got := ok[apigen.NodeGroupsList](t, get(t, handlerOf(f), "/api/v1/nodegroups"))
	require.Len(t, got.Groups, 2)
	require.Equal(t, webtest.AgentGroupKey, got.Groups[0].Id)
	require.Equal(t, apigen.AgentCounts{ReportingWithoutInventory: 1, Stale: 1}, got.Groups[0].Agents)
	require.Equal(t, webtest.CP1GroupKey, got.Groups[1].Id)
	require.Equal(t, apigen.AgentCounts{Unsupported: 1}, got.Groups[1].Agents)

	agentReport(t, f, "worker-2", time.Minute)
	got = ok[apigen.NodeGroupsList](t, get(t, handlerOf(f), "/api/v1/nodegroups"))
	require.Equal(t, apigen.AgentCounts{Reporting: 1, ReportingWithoutInventory: 1}, got.Groups[0].Agents)
}
