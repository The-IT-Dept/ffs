package apiserver_test

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/nodegroup"
	"github.com/the-it-dept/ffs/internal/store"
	"github.com/the-it-dept/ffs/internal/web/apigen"
	"github.com/the-it-dept/ffs/internal/web/webtest"
)

// agentReport stores a full report of node, ago before the fixture's clock, carrying gaps, from a
// new agent process (so it is never a duplicate of the fixture's).
func agentReport(t *testing.T, f *webtest.Fixture, node string, ago time.Duration, gaps ...string) {
	t.Helper()
	at := webtest.Now.Add(-ago)
	var cov []model.NodeCoverageGap
	for _, g := range gaps {
		cov = append(cov, model.NodeCoverageGap{Code: g, Detail: g + " on " + node})
	}
	applied, err := f.Store.AcceptAgentReport(t.Context(), store.AgentReport{Node: node, AgentVersion: "v0.1.0",
		BootID: "boot-" + node + "-again", StartedAt: at.Add(-time.Minute), Seq: 1, At: at, Full: true,
		KernelRelease: "6.8.0-88-generic", Arch: "amd64", PackageDB: "dpkg", Coverage: cov})
	require.NoError(t, err)
	require.True(t, applied)
}

func relatedItem(t *testing.T, c apigen.ScopeCard, section apigen.RelatedSectionId, label string) apigen.RelatedItem {
	t.Helper()
	for _, r := range c.Related {
		if r.Id != section {
			continue
		}
		for _, it := range r.Items {
			if it.Label == label {
				return it
			}
		}
	}
	require.Failf(t, "related item missing", "%s %s", section, label)
	return apigen.RelatedItem{}
}

// V1, V8: an agent group whose host SBOM is catalogued is seen into, but in full detail only while
// none of its members has a host coverage gap. A blocked agent, an image-based OS, members that all
// went stale and a host inventory that is not stored each leave the group not in full, with the
// members' gaps listed for the UI to hatch.
func TestNodeGroupCoverage_MemberGapsAreNotFull(t *testing.T) {
	const fresh, old = time.Minute, 2 * time.Hour
	notInventoried := string(apigen.GapCodeHostNotInventoried)
	for _, tc := range []struct {
		name      string
		reports   map[string][]string // node → gaps of a fresh report; nil leaves the node stale
		gaps      []apigen.GapCode
		reporting int
	}{
		{"every member reports in full", map[string][]string{"worker-1": nil, "worker-2": nil}, []apigen.GapCode{}, 2},
		{"SELinux blocks the agent", map[string][]string{"worker-1": {model.GapNodeAgentBlocked}, "worker-2": nil},
			[]apigen.GapCode{apigen.GapCodeNodeAgentBlocked}, 2},
		{"image-based OS", map[string][]string{"worker-1": {model.GapNoPackageDatabase}, "worker-2": {model.GapNoPackageDatabase}},
			[]apigen.GapCode{apigen.GapCodeNoPackageDatabase}, 2},
		{"every member stale", map[string][]string{}, []apigen.GapCode{apigen.GapCodeNodeAgentMissing}, 0},
		{"host inventory not stored", map[string][]string{"worker-1": {notInventoried}, "worker-2": nil},
			[]apigen.GapCode{apigen.GapCodeHostNotInventoried}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := webtest.Open(t)
			for _, node := range []string{"worker-1", "worker-2"} {
				gaps, ok := tc.reports[node]
				if !ok {
					agentReport(t, f, node, old)
					continue
				}
				agentReport(t, f, node, fresh, gaps...)
			}
			h := handlerOf(f)
			full := len(tc.gaps) == 0
			want := apigen.CoverageFigure{InUse: 1, SeenInto: 1}
			if full {
				want.Full = 1
			}

			list := ok[apigen.NodeGroupsList](t, get(t, h, "/api/v1/nodegroups"))
			row := list.Groups[0]
			require.Equal(t, webtest.AgentGroupKey, row.Id)
			require.NotNil(t, row.Gaps)
			require.Equal(t, tc.gaps, *row.Gaps)
			require.Equal(t, tc.reporting, row.Agents.Reporting, "a node without a stored host inventory is not reporting in full")

			ng := "nodegroup:" + webtest.AgentGroupKey
			card := scopeCard(t, h, "?scope="+url.QueryEscape(ng))
			require.Equal(t, want, card.Trust.Coverage)
			require.Equal(t, !full, viewOf(t, card, apigen.ViewIdFindings).Gap)
			require.Equal(t, !full, viewOf(t, card, apigen.ViewIdHostPackages).Gap)
			require.Equal(t, !full, viewOf(t, card, apigen.ViewIdMembers).Gap)
			require.Equal(t, want, ok[apigen.Summary](t, get(t, h, "/api/v1/summary?scope="+url.QueryEscape(ng))).Coverage)

			cluster := scopeCard(t, h, "")
			require.Equal(t, !full, relatedItem(t, cluster, apigen.RelatedSectionIdNodegroups, "ubuntu-24.04-k6.8.0-88-3f9c1a").Gap)

			byNode := ok[apigen.ExposureTable](t, get(t, h, "/api/v1/exposure?group=node"))
			require.Equal(t, want, rowByID(t, byNode.Rows, "ng:"+webtest.AgentGroupKey).Signals.Coverage)

			if len(tc.gaps) > 0 && tc.gaps[0] != apigen.GapCodeNodeAgentMissing {
				cov := ok[apigen.Coverage](t, get(t, h, "/api/v1/coverage"))
				require.True(t, slices.ContainsFunc(cov.Gaps, func(g apigen.Gap) bool { return g.Code == tc.gaps[0] }), "%v", cov.Gaps)
			}
		})
	}
}

// V9: an image stored but not matched yet is not seen into: it is pending until its first match.
func TestCoverage_UnmatchedImagesArePending(t *testing.T) {
	f := webtest.Open(t)
	require.NoError(t, f.Store.MarkUnmatched(t.Context(), webtest.DigestWeb, webtest.Now))
	agentReport(t, f, "worker-2", time.Minute)
	require.NoError(t, f.Store.MarkUnmatched(t.Context(), nodegroup.GroupDigest(webtest.AgentGroupID), webtest.Now))
	h := handlerOf(f)

	sum := ok[apigen.Summary](t, get(t, h, "/api/v1/summary"))
	require.Equal(t, apigen.CoverageFigure{InUse: 10, SeenInto: 5, Full: 3}, sum.Coverage, "web is no longer seen into")

	img := ok[apigen.ImageDetail](t, get(t, h, "/api/v1/images/"+webtest.DigestWeb))
	require.Equal(t, apigen.ImageStatusPending, img.Status)
	require.Equal(t, apigen.CoverageClassNone, img.Coverage.Class)
	require.Equal(t, []apigen.GapCode{apigen.GapCodePending}, img.Coverage.Gaps)

	page := ok[apigen.ImagesPage](t, get(t, h, "/api/v1/images?q=nginx"))
	require.Len(t, page.Rows, 1)
	require.Equal(t, apigen.ImageStatusPending, page.Rows[0].Status)
	require.Equal(t, []apigen.GapCode{apigen.GapCodePending}, page.Rows[0].Gaps)

	cov := ok[apigen.Coverage](t, get(t, h, "/api/v1/coverage"))
	require.True(t, slices.ContainsFunc(cov.Gaps, func(g apigen.Gap) bool {
		return g.Code == apigen.GapCodePending && g.What == "docker.io/library/nginx"
	}))
	require.Equal(t, cov.TotalGaps, sum.Gaps)

	ng := "nodegroup:" + webtest.AgentGroupKey
	require.Equal(t, apigen.CoverageFigure{InUse: 1}, scopeCard(t, h, "?scope="+url.QueryEscape(ng)).Trust.Coverage,
		"a host inventory not matched yet is not seen into")

	require.NoError(t, f.Store.MarkMatched(t.Context(), webtest.DigestWeb))
	require.NoError(t, f.Store.MarkMatched(t.Context(), nodegroup.GroupDigest(webtest.AgentGroupID)))
	h = handlerOf(f)
	require.Equal(t, apigen.CoverageFigure{InUse: 10, SeenInto: 6, Full: 4}, ok[apigen.Summary](t, get(t, h, "/api/v1/summary")).Coverage)
	require.Equal(t, apigen.CoverageFigure{InUse: 1, SeenInto: 1, Full: 1}, scopeCard(t, h, "?scope="+url.QueryEscape(ng)).Trust.Coverage)
}

// V6: node group scopes and pages resolve a group's stable name, which survives the fingerprint
// change package updates bring; an unknown node group, workload or node scope is 404.
func TestNodeGroups_StableNameSurvivesFingerprintChange(t *testing.T) {
	f := webtest.Open(t)
	h := handlerOf(f)
	for _, ref := range []string{webtest.AgentGroupKey, webtest.AgentGroupID, "ubuntu-24.04-k6.8.0-88-3f9c1a"} {
		d := ok[apigen.NodeGroupDetail](t, get(t, h, "/api/v1/nodegroups/"+url.PathEscape(ref)))
		require.Equal(t, webtest.AgentGroupKey, d.Group.Id, ref)
		require.Equal(t, 1, ok[apigen.FindingsPage](t, get(t, h, "/api/v1/findings?scope="+url.QueryEscape("nodegroup:"+ref))).Total, ref)
	}
	cmp := ok[apigen.NodeGroupDetail](t, get(t, h, "/api/v1/nodegroups/"+webtest.AgentGroupKey+"?compare="+webtest.CP1GroupKey))
	require.NotNil(t, cmp.Compare)
	require.Equal(t, webtest.CP1GroupKey, cmp.Compare.From)

	// unattended-upgrades on every worker: a new fingerprint, the same stable name.
	ctx := t.Context()
	groups, err := f.Store.NodeGroups(ctx)
	require.NoError(t, err)
	i := slices.IndexFunc(groups, func(g model.NodeGroup) bool { return g.ID == webtest.AgentGroupID })
	require.GreaterOrEqual(t, i, 0)
	moved := groups[i]
	newID := "9e8d7c" + strings.Repeat("1", 58)
	moved.ID, moved.Label, moved.Digest = newID, nodegroup.GroupLabel(moved.Name, newID), nodegroup.GroupDigest(newID)
	moved.Members = nil
	require.NoError(t, f.Store.PutNodeGroup(ctx, moved, webtest.Now))
	cp1 := slices.IndexFunc(groups, func(g model.NodeGroup) bool { return g.ID == webtest.CP1GroupID })
	require.GreaterOrEqual(t, cp1, 0)
	nodes, err := f.Store.ListNodes(ctx)
	require.NoError(t, err)
	var cpNodes []model.Node
	for _, n := range nodes {
		if n.Name == "cp-1" {
			cpNodes = append(cpNodes, n)
		}
	}
	require.NoError(t, f.Store.ApplyNodeGrouping(ctx, store.NodeGrouping{
		Members:  map[string]string{"worker-1": newID, "worker-2": newID, "cp-1": webtest.CP1GroupID},
		Fallback: nodegroup.FallbackGroups(cpNodes, webtest.Now), Exposed: map[string][]string{newID: {"worker-1"}}, Now: webtest.Now,
	}))
	h = handlerOf(f)
	d := ok[apigen.NodeGroupDetail](t, get(t, h, "/api/v1/nodegroups/"+webtest.AgentGroupKey))
	require.Equal(t, "nodegroup:"+newID, d.Group.Digest, "the bookmarked name opens the current group")
	require.Equal(t, webtest.AgentGroupKey, d.Group.Id)
	card := scopeCard(t, h, "?scope="+url.QueryEscape("nodegroup:"+webtest.AgentGroupKey))
	require.Equal(t, moved.Label, card.Title)
	require.Equal(t, 2, *viewOf(t, card, apigen.ViewIdMembers).Count)
	wantProblem(t, get(t, h, "/api/v1/nodegroups/"+webtest.AgentGroupID), 404, apigen.ProblemCodeNotFound)
	node := ok[apigen.NodeDetail](t, get(t, h, "/api/v1/nodes/worker-1"))
	require.Equal(t, webtest.AgentGroupKey, node.Group.Id, "the API links groups by their stable name")

	// During a rollout two current groups share the name, kind and architecture: each is linked by
	// the name anchored to its first member, never by a fingerprint, and the bare name opens one.
	require.NoError(t, f.Store.ApplyNodeGrouping(ctx, store.NodeGrouping{
		Members:  map[string]string{"worker-1": webtest.AgentGroupID, "worker-2": newID, "cp-1": webtest.CP1GroupID},
		Fallback: nodegroup.FallbackGroups(cpNodes, webtest.Now), Exposed: map[string][]string{webtest.AgentGroupID: {"worker-1"}},
		Now: webtest.Now,
	}))
	h = handlerOf(f)
	onW1, onW2 := webtest.AgentGroupKey+"@worker-1", webtest.AgentGroupKey+"@worker-2"
	require.ElementsMatch(t, []string{onW1, onW2, webtest.CP1GroupKey}, groupKeys(t, h))
	for id, key := range map[string]string{webtest.AgentGroupID: onW1, newID: onW2} {
		require.Equal(t, key, ok[apigen.NodeGroupDetail](t, get(t, h, "/api/v1/nodegroups/"+id)).Group.Id)
		require.Equal(t, "nodegroup:"+id, ok[apigen.NodeGroupDetail](t, get(t, h, "/api/v1/nodegroups/"+url.PathEscape(key))).Group.Digest)
	}
	require.Equal(t, onW1, ok[apigen.NodeDetail](t, get(t, h, "/api/v1/nodes/worker-1")).Group.Id)
	byName := ok[apigen.NodeGroupDetail](t, get(t, h, "/api/v1/nodegroups/"+webtest.AgentGroupKey))
	require.Contains(t, []string{onW1, onW2}, byName.Group.Id)

	// The rollout completes: the links built during it open the group their node is in now.
	require.NoError(t, f.Store.ApplyNodeGrouping(ctx, store.NodeGrouping{
		Members:  map[string]string{"worker-1": newID, "worker-2": newID, "cp-1": webtest.CP1GroupID},
		Fallback: nodegroup.FallbackGroups(cpNodes, webtest.Now), Exposed: map[string][]string{newID: {"worker-1"}}, Now: webtest.Now,
	}))
	h = handlerOf(f)
	require.ElementsMatch(t, []string{webtest.AgentGroupKey, webtest.CP1GroupKey}, groupKeys(t, h))
	for _, ref := range []string{onW1, onW2} {
		d := ok[apigen.NodeGroupDetail](t, get(t, h, "/api/v1/nodegroups/"+url.PathEscape(ref)))
		require.Equal(t, "nodegroup:"+newID, d.Group.Digest, ref)
		require.Equal(t, webtest.AgentGroupKey, d.Group.Id, ref)
		require.Equal(t, moved.Label, scopeCard(t, h, "?scope="+url.QueryEscape("nodegroup:"+ref)).Title, ref)
	}
}

// groupKeys are the keys /nodegroups names the groups by, after checking that none is a group's
// fingerprint.
func groupKeys(t *testing.T, h http.Handler) []string {
	t.Helper()
	list := ok[apigen.NodeGroupsList](t, get(t, h, "/api/v1/nodegroups"))
	var keys []string
	for _, g := range list.Groups {
		require.NotRegexp(t, `^[0-9a-f]{64}$`, g.Id, "a group is never linked by its fingerprint")
		keys = append(keys, g.Id)
	}
	return keys
}

// V6: on a multi-arch cluster with an agentless node whose nodeinfo group takes the agent group's
// stable name, every link the API builds names a group by what survives package updates (its
// architecture and kind), and those links open the same pools after updates re-key them and the
// agentless node's agent reports.
func TestNodeGroups_MultiArchAndAgentlessKeysSurvivePackageUpdates(t *testing.T) {
	f := webtest.Open(t)
	ctx := t.Context()
	name := webtest.AgentGroupKey
	nodes, err := f.Store.ListNodes(ctx)
	require.NoError(t, err)
	i := slices.IndexFunc(nodes, func(n model.Node) bool { return n.Name == "worker-1" })
	require.GreaterOrEqual(t, i, 0)
	arm, fresh := nodes[i], nodes[i]
	arm.Name, arm.Arch = "arm-1", "arm64"
	fresh.Name, fresh.OSImage = "worker-3", "Ubuntu 24.04 LTS"
	require.Equal(t, name, nodegroup.GroupName(nil, fresh.OSImage, fresh.KernelVersion),
		"the agentless node's nodeinfo group takes the agent group's stable name")
	var cpNodes []model.Node
	for _, n := range nodes {
		if n.Name == "cp-1" {
			cpNodes = append(cpNodes, n)
		}
	}
	require.NoError(t, f.Store.ReplaceNodes(ctx, append(nodes, arm, fresh)))

	groups, err := f.Store.NodeGroups(ctx)
	require.NoError(t, err)
	i = slices.IndexFunc(groups, func(g model.NodeGroup) bool { return g.ID == webtest.AgentGroupID })
	require.GreaterOrEqual(t, i, 0)
	rekey := func(g model.NodeGroup, id, arch string) model.NodeGroup {
		g.ID, g.Label, g.Digest, g.Arch, g.Members = id, nodegroup.GroupLabel(g.Name, id), nodegroup.GroupDigest(id), arch, nil
		require.NoError(t, f.Store.PutNodeGroup(ctx, g, webtest.Now))
		return g
	}
	armGroup := rekey(groups[i], "7a7a7a"+strings.Repeat("0", 58), "arm64")
	group := func(members map[string]string, exposed string) {
		t.Helper()
		members["cp-1"] = webtest.CP1GroupID
		require.NoError(t, f.Store.ApplyNodeGrouping(ctx, store.NodeGrouping{Members: members,
			Fallback: nodegroup.FallbackGroups(cpNodes, webtest.Now), Exposed: map[string][]string{exposed: {"worker-1"}},
			Now: webtest.Now}))
	}
	group(map[string]string{"worker-1": webtest.AgentGroupID, "worker-2": webtest.AgentGroupID, "arm-1": armGroup.ID},
		webtest.AgentGroupID)
	h := handlerOf(f)

	amdKey, armKey, freshKey := name+"-amd64", name+"-arm64", name+"-amd64-nodeinfo"
	require.ElementsMatch(t, []string{amdKey, armKey, freshKey, webtest.CP1GroupKey}, groupKeys(t, h))
	for key, members := range map[string][]string{amdKey: {"worker-1", "worker-2"}, armKey: {"arm-1"}, freshKey: {"worker-3"}} {
		d := ok[apigen.NodeGroupDetail](t, get(t, h, "/api/v1/nodegroups/"+key))
		require.Equal(t, key, d.Group.Id)
		var got []string
		for _, m := range d.Members {
			got = append(got, m.Name)
		}
		require.Equal(t, members, got, key)
		for _, other := range d.Drift {
			require.NotRegexp(t, `^[0-9a-f]{64}$`, other.Other.Id, "drift rows link groups by key")
		}
	}
	for node, key := range map[string]string{"worker-1": amdKey, "arm-1": armKey, "worker-3": freshKey} {
		require.Equal(t, key, ok[apigen.NodeDetail](t, get(t, h, "/api/v1/nodes/"+node)).Group.Id, node)
	}
	page := ok[apigen.FindingsPage](t, get(t, h, "/api/v1/findings?scope="+url.QueryEscape("nodegroup:"+amdKey)))
	require.Len(t, page.Rows, 1)
	require.NotNil(t, page.Rows[0].NodeGroups)
	require.Equal(t, amdKey, (*page.Rows[0].NodeGroups)[0].Id, "a host finding links its group by key")
	require.Equal(t, armGroup.Label, scopeCard(t, h, "?scope="+url.QueryEscape("nodegroup:"+armKey)).Title)
	crumbs := scopeCard(t, h, "?scope="+url.QueryEscape("node:arm-1")).Breadcrumbs
	require.True(t, slices.ContainsFunc(crumbs, func(c apigen.ScopeRef) bool { return c.Scope == "nodegroup:"+armKey }),
		"a node's breadcrumb links its group by key: %+v", crumbs)
	res := ok[apigen.SearchResult](t, get(t, h, "/api/v1/search?q="+url.QueryEscape(name)))
	for _, key := range []string{amdKey, armKey, freshKey} {
		require.Equal(t, "nodegroup:"+key, *hitOf(t, res, apigen.SearchHitKindNodegroup, key).Scope)
	}

	// unattended-upgrades re-keys both agent pools, and the agentless node's agent reports, moving
	// it into the amd64 pool: every link built before opens the same pool.
	amdNext := rekey(groups[i], "9e8d7c"+strings.Repeat("1", 58), "amd64")
	armNext := rekey(groups[i], "8b8b8b"+strings.Repeat("1", 58), "arm64")
	group(map[string]string{"worker-1": amdNext.ID, "worker-2": amdNext.ID, "worker-3": amdNext.ID, "arm-1": armNext.ID},
		amdNext.ID)
	h = handlerOf(f)
	require.ElementsMatch(t, []string{amdKey, armKey, webtest.CP1GroupKey}, groupKeys(t, h))
	for ref, want := range map[string]model.NodeGroup{amdKey: amdNext, armKey: armNext, freshKey: amdNext} {
		d := ok[apigen.NodeGroupDetail](t, get(t, h, "/api/v1/nodegroups/"+ref))
		require.Equal(t, want.Digest, d.Group.Digest, ref)
		require.Equal(t, want.Label, scopeCard(t, h, "?scope="+url.QueryEscape("nodegroup:"+ref)).Title, ref)
	}
	for _, id := range []string{webtest.AgentGroupID, armGroup.ID} {
		wantProblem(t, get(t, h, "/api/v1/nodegroups/"+id), http.StatusNotFound, apigen.ProblemCodeNotFound)
	}
}

func TestScopes_UnknownNodeGroupWorkloadOrNodeIsNotFound(t *testing.T) {
	_, h := newAPI(t)
	for _, target := range []string{
		"/api/v1/findings?scope=nodegroup:nope", "/api/v1/summary?scope=nodegroup:nope", "/api/v1/scope?scope=nodegroup:nope",
		"/api/v1/findings?scope=workload:Deployment/shop/missing", "/api/v1/summary?scope=workload:Deployment/shop/missing",
		"/api/v1/scope?scope=workload:Deployment/shop/missing", "/api/v1/images?scope=workload:Deployment/shop/missing",
		"/api/v1/packages?scope=workload:Deployment/shop/missing", "/api/v1/coverage?scope=workload:Deployment/shop/missing",
		"/api/v1/findings?scope=node:missing", "/api/v1/summary?scope=node:missing", "/api/v1/scope?scope=node:missing",
	} {
		p := wantProblem(t, get(t, h, target), http.StatusNotFound, apigen.ProblemCodeNotFound)
		require.NotNil(t, p.Detail, target)
		require.Contains(t, *p.Detail, "not found", target)
	}
	ok[apigen.FindingsPage](t, get(t, h, "/api/v1/findings?scope="+url.QueryEscape("workload:Cluster//test")))
}

// V14: a namespaced owner of kind Cluster (a CloudNativePG cluster) is a workload, not the control
// plane: its upgrades are not the control plane's.
func TestControlPlane_NamespacedClusterOwnerIsNotControlPlane(t *testing.T) {
	f := webtest.Open(t)
	ctx := t.Context()
	cnpg := model.OwnerRef{Kind: model.OwnerKindCluster, Namespace: "db", Name: "pg-main"}
	const repo = "ghcr.io/cloudnative-pg/postgresql"
	require.NoError(t, f.Store.UpsertOwner(ctx, model.Owner{Ref: cnpg, UpdatedAt: webtest.Now, Containers: []model.ContainerUse{{
		Name: "postgres", Kind: model.ContainerRegular, ImageRef: repo + ":16.4", Repo: repo, Digest: "sha256:" + strings.Repeat("5", 64)}}}))
	require.NoError(t, f.Store.PutSuggestion(ctx, cnpg.Key(), model.Suggestion{Repo: repo, FromTag: "16.4", ToTag: "16.6",
		Tier: model.TierPatch, Fixes: map[model.Priority]int{model.PriorityHigh: 1}, ComputedAt: webtest.Now}, nil))
	h := handlerOf(f)

	require.Empty(t, ok[apigen.NodeGroupsList](t, get(t, h, "/api/v1/nodegroups")).ControlPlane.Suggestions)
	require.Equal(t, 0, *viewOf(t, scopeCard(t, h, "?scope=controlplane"), apigen.ViewIdUpgrades).Count)
	w := ok[apigen.WorkloadDetail](t, get(t, h, "/api/v1/workloads/Cluster/db/pg-main"))
	require.Len(t, w.Upgrades, 1, "the CloudNativePG cluster's own page keeps its upgrade")
}

// V15: over the cluster, the packages explorer counts the findings on container images only; a
// host package at the same version as a container's does not add its finding.
func TestPackages_ClusterCountsContainerFindingsOnly(t *testing.T) {
	f := webtest.Open(t)
	ctx := t.Context()
	digest := nodegroup.GroupDigest(webtest.AgentGroupID)
	ubuntu := &model.Distro{ID: "ubuntu", VersionID: "24.04", Codename: "noble"}
	require.NoError(t, f.Store.PutSBOM(ctx, digest, nil, []model.Package{
		{Ecosystem: "deb", Distro: ubuntu, Name: "linux-image-6.8.0-88-generic", Version: "6.8.0-88.89", Arch: "amd64"},
		{Ecosystem: "deb", Distro: ubuntu, Name: "openssl", Version: "3.0.13-0ubuntu3", Arch: "amd64"},
		{Ecosystem: "go-module", Name: "stdlib", Version: "go1.24.1", GoStdlib: true, Path: "/usr/bin/kubelet"},
	}))
	host := model.Finding{Fingerprint: model.FindingFingerprint(webtest.ClusterName, webtest.Nodes, model.HostRepo, "GO-2026-0010"),
		Owner: webtest.Nodes, ImageRepo: model.HostRepo, AdvisoryID: "GO-2026-0010", Digests: []string{digest},
		Packages: []model.FindingPackage{{Name: "stdlib", Ecosystem: "go-module", Installed: "go1.24.1", Path: "/usr/bin/kubelet"}},
		Severity: model.SeverityHigh, Priority: model.PriorityHigh, State: model.StateOpen, Observed: webtest.Now, Matched: webtest.Now,
		LastSeen: webtest.Now}
	require.NoError(t, f.Store.ApplyFindings(ctx, []model.Finding{host}, nil))
	h := handlerOf(f)

	page := ok[apigen.PackagesPage](t, get(t, h, "/api/v1/packages?q=stdlib&ecosystem=go-module"))
	i := slices.IndexFunc(page.Rows, func(r apigen.PackageRow) bool { return r.Version == "go1.24.1" })
	require.GreaterOrEqual(t, i, 0)
	require.Equal(t, apigen.PriorityCounts{Urgent: 1}, page.Rows[i].Counts, "the node-exporter image's finding, not the host's")
	require.Equal(t, 1, page.Rows[i].Images)
}

// V24: a host finding names the node groups it affects, with their member counts and the installed
// versions of its packages there; the advisory page lists them too.
func TestHostFindings_NameTheirNodeGroups(t *testing.T) {
	_, h := newAPI(t)
	want := []apigen.FindingNodeGroup{{Id: webtest.AgentGroupKey, Label: "ubuntu-24.04-k6.8.0-88-3f9c1a", Nodes: 2,
		Versions: []struct {
			Package string `json:"package"`
			Version string `json:"version"`
		}{{Package: "openssl", Version: "3.0.13-0ubuntu3"}}}}

	page := ok[apigen.FindingsPage](t, get(t, h, "/api/v1/findings?scope="+url.QueryEscape("nodegroup:"+webtest.AgentGroupKey)))
	require.Len(t, page.Rows, 1)
	require.NotNil(t, page.Rows[0].NodeGroups)
	require.Equal(t, want, *page.Rows[0].NodeGroups)

	web := ok[apigen.FindingsPage](t, get(t, h, "/api/v1/findings?scope="+url.QueryEscape("workload:Deployment/shop/web")))
	require.NotEmpty(t, web.Rows)
	for _, r := range web.Rows {
		require.Nil(t, r.NodeGroups, "a container finding has no node groups")
	}

	adv := ok[apigen.AdvisoryDetail](t, get(t, h, "/api/v1/advisories/CVE-2026-0012"))
	require.NotNil(t, adv.NodeGroups)
	require.Equal(t, want, *adv.NodeGroups)
	other := ok[apigen.AdvisoryDetail](t, get(t, h, "/api/v1/advisories/CVE-2026-0001"))
	require.NotNil(t, other.NodeGroups)
	require.Empty(t, *other.NodeGroups)
}

// V51: an image in full detail that holds classifier-found packages the upstream map does not
// cover is still listed as a cpe_only_classifier gap.
func TestCoverage_ListsCPEOnlyPackagesOfFullImages(t *testing.T) {
	f := webtest.Open(t)
	require.NoError(t, f.Store.PutSBOM(t.Context(), webtest.DigestCoreDNS, nil, []model.Package{
		{Ecosystem: "go-module", Name: "stdlib", Version: "go1.25.3", GoStdlib: true, Path: "/coredns"},
		{Ecosystem: "binary", Name: "redis-server", Version: "7.4.1", Classifier: "redis-binary", Path: "/usr/local/bin/redis-server"},
	}))
	h := handlerOf(f)
	cov := ok[apigen.Coverage](t, get(t, h, "/api/v1/coverage"))
	i := slices.IndexFunc(cov.Gaps, func(g apigen.Gap) bool {
		return g.Code == apigen.GapCodeCpeOnlyClassifier && g.What == "registry.k8s.io/coredns/coredns"
	})
	require.GreaterOrEqual(t, i, 0, "%v", cov.Gaps)
	require.Equal(t, "redis-server", cov.Gaps[i].Detail)
	require.Equal(t, cov.TotalGaps, ok[apigen.Summary](t, get(t, h, "/api/v1/summary")).Gaps)
	img := ok[apigen.ImageDetail](t, get(t, h, "/api/v1/images/"+webtest.DigestCoreDNS))
	require.Equal(t, apigen.CoverageClassFull, img.Coverage.Class)
	ns := ok[apigen.Coverage](t, get(t, h, "/api/v1/coverage?scope=namespace:kube-system"))
	require.True(t, slices.ContainsFunc(ns.Gaps, func(g apigen.Gap) bool { return g.Code == apigen.GapCodeCpeOnlyClassifier }))
}

// V52, V53: a second workload running web's image: web's container counts web's own findings, and
// the hostname both are exposed through counts the shared image once.
func TestSharedImages_CountOwnFindingsAndImagesOnce(t *testing.T) {
	f := webtest.Open(t)
	ctx := t.Context()
	canary := model.OwnerRef{Kind: "Deployment", Namespace: "shop", Name: "web-canary"}
	edge := model.ExposureEdge{Entry: model.EntryGateway, EntryName: "gateway/public", Listener: "https", Hostname: "shop.example.com",
		Route: "HTTPRoute shop/web-canary", Service: "shop/web-canary:8080", Path: "HTTPRoute shop/web-canary on Gateway gateway/public"}
	require.NoError(t, f.Store.UpsertOwner(ctx, model.Owner{Ref: canary, UpdatedAt: webtest.Now,
		Context: model.WorkloadContext{Exposed: true, ExposurePaths: []string{edge.Path}, Exposure: []model.ExposureEdge{edge}},
		Containers: []model.ContainerUse{{Name: "app", Kind: model.ContainerRegular, ImageRef: "docker.io/library/nginx:1.30.6",
			Repo: "docker.io/library/nginx", Digest: webtest.DigestWeb, Platform: "linux/amd64"}}}))
	canaryFinding := model.Finding{Fingerprint: model.FindingFingerprint(webtest.ClusterName, canary, "docker.io/library/nginx", "CVE-2026-0006"),
		Owner: canary, ImageRepo: "docker.io/library/nginx", AdvisoryID: "CVE-2026-0006", Digests: []string{webtest.DigestWeb},
		Packages: []model.FindingPackage{{Name: "zlib1g", Ecosystem: "deb", Installed: "1.2.13.dfsg-1"}}, Severity: model.SeverityMedium,
		Priority: model.PriorityMedium, State: model.StateOpen, Observed: webtest.Now, Matched: webtest.Now, LastSeen: webtest.Now}
	require.NoError(t, f.Store.ApplyFindings(ctx, []model.Finding{canaryFinding}, nil))
	h := handlerOf(f)

	card := scopeCard(t, h, "?scope="+url.QueryEscape("workload:"+webtest.Web.Key()))
	app := relatedItem(t, card, apigen.RelatedSectionIdContainers, "app")
	require.NotNil(t, app.Count)
	require.Equal(t, 3, *app.Count, "web's own three findings on the image, not the canary's")
	require.Equal(t, 4, ok[apigen.Summary](t, get(t, h, "/api/v1/summary?scope="+url.QueryEscape("image:"+webtest.DigestWeb))).Open)

	table := ok[apigen.ExposureTable](t, get(t, h, "/api/v1/exposure"))
	host := rowByID(t, table.Rows, "gw:gateway/public/shop.example.com")
	require.Equal(t, apigen.CoverageFigure{InUse: 2, SeenInto: 1, Full: 1}, host.Signals.Coverage,
		"nginx (shared) and the proxy image, each once")
}

// The cluster rail's node-group item is hatched as the group's own card is: by the group's coverage
// figure, which also needs its host SBOM catalogued and matched, not only its members' gaps.
func TestClusterRail_NodeGroupGapFollowsItsCoverage(t *testing.T) {
	f := webtest.Open(t)
	for _, node := range []string{"worker-1", "worker-2"} {
		agentReport(t, f, node, time.Minute)
	}
	label := "ubuntu-24.04-k6.8.0-88-3f9c1a"
	ng := "?scope=" + url.QueryEscape("nodegroup:"+webtest.AgentGroupKey)
	h := handlerOf(f)
	require.Equal(t, apigen.CoverageFigure{InUse: 1, SeenInto: 1, Full: 1}, scopeCard(t, h, ng).Trust.Coverage)
	require.False(t, relatedItem(t, scopeCard(t, h, ""), apigen.RelatedSectionIdNodegroups, label).Gap, "every member in full")

	require.NoError(t, f.Store.MarkUnmatched(t.Context(), nodegroup.GroupDigest(webtest.AgentGroupID), webtest.Now))
	h = handlerOf(f)
	require.Equal(t, apigen.CoverageFigure{InUse: 1}, scopeCard(t, h, ng).Trust.Coverage, "the host SBOM is not matched yet")
	require.True(t, relatedItem(t, scopeCard(t, h, ""), apigen.RelatedSectionIdNodegroups, label).Gap,
		"the rail agrees with the group's card")
}
