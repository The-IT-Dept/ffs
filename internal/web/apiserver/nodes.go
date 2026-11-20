package apiserver

import (
	"cmp"
	"context"
	"maps"
	"slices"
	"strings"

	"github.com/the-it-dept/ffs/internal/eol"
	"github.com/the-it-dept/ffs/internal/inventory"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/nodegroup"
	"github.com/the-it-dept/ffs/internal/store"
	"github.com/the-it-dept/ffs/internal/web/apigen"
)

// readNodeGroups reads the node groups the API shows: the stored groups that have members, plus a
// nodeinfo fallback group (nodegroup.FallbackGroups) for the nodes no stored group lists. A fallback
// group whose ID is a stored group's (FallbackID is deterministic) adds its members to that group
// instead of a second row. Agent groups come first, then nodeinfo groups, each by Label and then ID.
func (s *Server) readNodeGroups(ctx context.Context) ([]model.NodeGroup, error) {
	stored, err := s.o.Store.NodeGroups(ctx)
	if err != nil {
		return nil, err
	}
	nodes, err := s.o.Store.ListNodes(ctx)
	if err != nil {
		return nil, err
	}
	groups := make([]model.NodeGroup, 0, len(stored))
	listed := map[string]bool{}
	for _, g := range stored {
		if len(g.Members) == 0 {
			continue
		}
		groups = append(groups, g)
		for _, m := range g.Members {
			listed[m] = true
		}
	}
	var rest []model.Node
	for _, n := range nodes {
		if !listed[n.Name] {
			rest = append(rest, n)
		}
	}
	for _, fb := range nodegroup.FallbackGroups(rest, s.o.Now()) {
		if i := slices.IndexFunc(groups, func(g model.NodeGroup) bool { return g.ID == fb.ID }); i >= 0 {
			members := append(slices.Clone(groups[i].Members), fb.Members...)
			slices.Sort(members)
			groups[i].Members = slices.Compact(members)
			continue
		}
		groups = append(groups, fb)
	}
	slices.SortFunc(groups, func(a, b model.NodeGroup) int {
		return cmp.Or(cmp.Compare(groupKindRank(a.Kind), groupKindRank(b.Kind)), strings.Compare(a.Label, b.Label),
			strings.Compare(a.ID, b.ID))
	})
	return groups, nil
}

// groupKindRank orders agent groups before nodeinfo groups.
func groupKindRank(k model.NodeGroupKind) int {
	if k == model.NodeGroupAgent {
		return 0
	}
	return 1
}

// groupSet is the node groups the API shows, with the key each is linked by. The key is the
// group's stable name (nodegroup.GroupName), which survives the fingerprint changes package updates
// bring. When several current groups share the name, each key adds what tells them apart and also
// survives package updates: "-<arch>" when they span architectures, and "-nodeinfo" on a nodeinfo
// group when an agent group shares the name. Groups that still share a key (a rollout of package
// updates, or two pools with the same OS, kernel and architecture) are each anchored to their first
// member node, "<key>@<node>", which find follows into whichever group with that key holds the node
// next. A key that is another group's ID, label or key falls back to the group's ID.
type groupSet struct {
	groups []model.NodeGroup
	keys   map[string]string // group ID → key
	forms  map[string][]int  // stable form (stableForms) → indexes into groups, in group order
}

const (
	// nodeInfoSuffix marks a nodeinfo group's key when an agent group shares its stable name.
	nodeInfoSuffix = "-nodeinfo"
	// anchorSep joins a key that several groups share to a member node's name. Neither stable
	// names nor node names (DNS subdomains) contain it.
	anchorSep = "@"
)

// stableKey is g's stable name, with its architecture and, for a nodeinfo group, nodeInfoSuffix
// when asked for.
func stableKey(g model.NodeGroup, withArch, withKind bool) string {
	k := g.Name
	if withArch && g.Arch != "" {
		k += "-" + g.Arch
	}
	if withKind && g.Kind == model.NodeGroupNodeInfo {
		k += nodeInfoSuffix
	}
	return k
}

// stableForms are the stable keys g may have been linked by, whichever groups shared its name.
func stableForms(g model.NodeGroup) []string {
	if g.Name == "" {
		return nil
	}
	forms := []string{stableKey(g, false, false), stableKey(g, true, false)}
	if g.Kind == model.NodeGroupNodeInfo {
		forms = append(forms, stableKey(g, false, true), stableKey(g, true, true))
	}
	slices.Sort(forms)
	return slices.Compact(forms)
}

// spans reports whether the groups at idx differ in attr.
func spans(groups []model.NodeGroup, idx []int, attr func(model.NodeGroup) string) bool {
	return slices.ContainsFunc(idx, func(i int) bool { return attr(groups[i]) != attr(groups[idx[0]]) })
}

func newGroupSet(groups []model.NodeGroup) *groupSet {
	keys := make([]string, len(groups))
	byName := map[string][]int{}
	for i, g := range groups {
		keys[i] = g.ID
		if g.Name != "" {
			byName[g.Name] = append(byName[g.Name], i)
		}
	}
	for _, idx := range byName {
		withArch := spans(groups, idx, func(g model.NodeGroup) string { return g.Arch })
		withKind := spans(groups, idx, func(g model.NodeGroup) string { return string(g.Kind) })
		shared := map[string]int{}
		for _, i := range idx {
			keys[i] = stableKey(groups[i], withArch, withKind)
			shared[keys[i]]++
		}
		for _, i := range idx {
			switch g := groups[i]; {
			case shared[keys[i]] == 1:
			case len(g.Members) > 0:
				keys[i] += anchorSep + g.Members[0]
			default:
				keys[i] = g.ID
			}
		}
	}
	// How many groups each exact reference names: their key, ID and label, each once per group. (A
	// key that is another group's stable name wins over it in find, as a current key should.)
	refs := map[string]int{}
	for i, g := range groups {
		own := []string{keys[i], g.ID, g.Label}
		for j, r := range own {
			if r != "" && !slices.Contains(own[:j], r) {
				refs[r]++
			}
		}
	}
	gs := &groupSet{groups: groups, keys: make(map[string]string, len(groups)), forms: map[string][]int{}}
	for i, g := range groups {
		if refs[keys[i]] > 1 {
			keys[i] = g.ID
		}
		gs.keys[g.ID] = keys[i]
		for _, f := range stableForms(g) {
			gs.forms[f] = append(gs.forms[f], i)
		}
	}
	return gs
}

// key is the reference API links use for g.
func (gs *groupSet) key(g model.NodeGroup) string {
	if k, ok := gs.keys[g.ID]; ok {
		return k
	}
	return g.ID
}

// find resolves a group reference: a group ID, a current key or label, or a key built while other
// groups shared the name (or none did). A stable form names the current groups it is a stable form
// of (stableForms); "<form>-nodeinfo" with none of those names the groups of <form>, which the
// nodeinfo group's nodes moved to once their agent reported. An anchored reference, "<form>@<node>",
// is the one of those groups that holds the node; else, and for a bare form, it is the preferred one
// (preferGroup).
func (gs *groupSet) find(ref string) (model.NodeGroup, bool) {
	if ref == "" {
		return model.NodeGroup{}, false
	}
	for _, match := range []func(model.NodeGroup) bool{
		func(g model.NodeGroup) bool { return g.ID == ref },
		func(g model.NodeGroup) bool { return gs.keys[g.ID] == ref || g.Label == ref },
	} {
		if i := slices.IndexFunc(gs.groups, match); i >= 0 {
			return gs.groups[i], true
		}
	}
	form, node, anchored := ref, "", false
	if i := strings.LastIndex(ref, anchorSep); i >= 0 {
		form, node, anchored = ref[:i], ref[i+len(anchorSep):], true
	}
	tiers := [][]int{gs.forms[form]}
	if base, ok := strings.CutSuffix(form, nodeInfoSuffix); ok {
		tiers = append(tiers, gs.forms[base])
	}
	if anchored {
		for _, idx := range tiers {
			if i := slices.IndexFunc(idx, func(j int) bool { return slices.Contains(gs.groups[j].Members, node) }); i >= 0 {
				return gs.groups[idx[i]], true
			}
		}
	}
	for _, idx := range tiers {
		if len(idx) > 0 {
			return gs.groups[slices.MaxFunc(idx, func(a, b int) int { return preferGroup(gs.groups[a], gs.groups[b]) })], true
		}
	}
	return model.NodeGroup{}, false
}

// preferGroup is positive when a reference that names both a and b should resolve to a: an agent
// group first, then the one with the most members, then the most recently seen, then the lowest ID.
func preferGroup(a, b model.NodeGroup) int {
	return cmp.Or(cmp.Compare(groupKindRank(b.Kind), groupKindRank(a.Kind)), cmp.Compare(len(a.Members), len(b.Members)),
		a.LastSeen.Compare(b.LastSeen), strings.Compare(b.ID, a.ID))
}

// byID is the group with exactly this ID.
func (gs *groupSet) byID(id string) (model.NodeGroup, bool) {
	i := slices.IndexFunc(gs.groups, func(g model.NodeGroup) bool { return g.ID == id })
	if i < 0 {
		return model.NodeGroup{}, false
	}
	return gs.groups[i], true
}

// of is the group a node belongs to: the stored group that lists it (the answer
// Store.NodeGroupOfNode gives), else the fallback group holding it. It searches the shown groups
// rather than calling Store.NodeGroupOfNode, so a node merged into a stored group from a fallback
// group with the same ID resolves too.
func (gs *groupSet) of(node string) (model.NodeGroup, bool) {
	i := slices.IndexFunc(gs.groups, func(g model.NodeGroup) bool { return slices.Contains(g.Members, node) })
	if i < 0 {
		return model.NodeGroup{}, false
	}
	return gs.groups[i], true
}

// nodeGroups are the node groups the API shows (readNodeGroups), read once per request.
func (s *Server) nodeGroups(ctx context.Context) ([]model.NodeGroup, error) {
	gs, err := s.groupSet(ctx)
	if err != nil {
		return nil, err
	}
	return gs.groups, nil
}

// groupOf is the group a node belongs to (groupSet.of).
func (s *Server) groupOf(ctx context.Context, node string) (model.NodeGroup, bool, error) {
	gs, err := s.groupSet(ctx)
	if err != nil {
		return model.NodeGroup{}, false, err
	}
	g, ok := gs.of(node)
	return g, ok, nil
}

// findGroup is the group a reference resolves to (groupSet.find): its ID, key, label or a stable form.
func (s *Server) findGroup(ctx context.Context, ref string) (model.NodeGroup, bool, error) {
	gs, err := s.groupSet(ctx)
	if err != nil {
		return model.NodeGroup{}, false, err
	}
	g, ok := gs.find(ref)
	return g, ok, nil
}

// groupScope is the scope API links name a group by: its key.
func (gs *groupSet) scope(g model.NodeGroup) model.Scope {
	return model.Scope{Kind: model.ScopeNodeGroup, Value: gs.key(g)}
}

// groupStats are a group's open host findings (node-level findings only, by its digest); a nodeinfo
// group has none.
func (s *Server) groupStats(ctx context.Context, g model.NodeGroup) (store.OwnerStats, error) {
	if g.Kind != model.NodeGroupAgent {
		return store.OwnerStats{}, nil
	}
	return s.o.Store.ScopeStats(ctx, model.Scope{Kind: model.ScopeNodeGroup, Value: g.ID})
}

// hostGapCodes are the node gaps after which ffs does not see a node's host packages in full: its
// agent is blocked, not reporting or not scheduled on it, it has no package database, or its host
// inventory is not stored. A content store the agent cannot read concerns side-loaded images only.
var hostGapCodes = []string{model.GapNodeAgentBlocked, model.GapNoPackageDatabase, model.GapNodeAgentMissing,
	string(apigen.GapCodeHostNotInventoried), string(apigen.GapCodeNodeAgentUnsupported)}

// hasGap reports whether a node's agent status carries one of codes.
func hasGap(a model.NodeAgentStatus, codes ...string) bool {
	return slices.ContainsFunc(a.Coverage, func(g model.NodeCoverageGap) bool { return slices.Contains(codes, g.Code) })
}

// hostGap reports whether ffs does not see a node's host packages in full (hostGapCodes).
func hostGap(a model.NodeAgentStatus) bool { return hasGap(a, hostGapCodes...) }

// memberGaps are the gap codes of a group's members, each once, sorted.
func memberGaps(g model.NodeGroup, agents *agentView) []apigen.GapCode {
	out := []apigen.GapCode{}
	for _, m := range g.Members {
		for _, gap := range agents.of(m).Coverage {
			if c := apigen.GapCode(gap.Code); !slices.Contains(out, c) {
				out = append(out, c)
			}
		}
	}
	slices.Sort(out)
	return out
}

// missingAgent is the status of a node the store has no status for: disabled when the node agent
// is, else never reported, with the node_agent_missing gap.
func missingAgent(node string, enabled bool) model.NodeAgentStatus {
	st := model.NodeAgentStatus{Node: node, State: model.AgentNever,
		Coverage: []model.NodeCoverageGap{{Code: model.GapNodeAgentMissing, Detail: "node agent has not reported"}}}
	if !enabled {
		st.State = model.AgentDisabled
	}
	return st
}

// liveAgent reports whether an agent's cached-image data is current enough to show.
func liveAgent(st model.AgentState) bool {
	return st == model.AgentReporting || st == model.AgentStale
}

// ListNodeGroups lists the control plane and every node group with its members' agent states and
// coverage gaps and field drift against the largest group of the same architecture. Members are
// counted by their CountState: one whose agent reports but whose host inventory is not stored counts
// as reportingWithoutInventory, and one the agent does not schedule on as unsupported.
func (s *Server) ListNodeGroups(ctx context.Context, _ apigen.ListNodeGroupsRequestObject) (apigen.ListNodeGroupsResponseObject, error) {
	agents, err := s.agentView(ctx)
	if err != nil {
		return nil, err
	}
	cp, err := s.controlPlane(ctx)
	if err != nil {
		return nil, err
	}
	gs, err := s.groupSet(ctx)
	if err != nil {
		return nil, err
	}
	// The base of each architecture: the group with the most members, ties by Label.
	base := map[string]model.NodeGroup{}
	for _, g := range gs.groups {
		b, ok := base[g.Arch]
		if !ok || len(g.Members) > len(b.Members) || (len(g.Members) == len(b.Members) && g.Label < b.Label) {
			base[g.Arch] = g
		}
	}
	rows := make([]apigen.NodeGroupRow, 0, len(gs.groups))
	for _, g := range gs.groups {
		st, err := s.groupStats(ctx, g)
		if err != nil {
			return nil, err
		}
		gaps := memberGaps(g, agents)
		row := apigen.NodeGroupRow{
			Id: gs.key(g), Kind: apigen.NodeGroupKind(g.Kind), Name: g.Name, Label: g.Label, OsImage: g.OSImage,
			KernelRelease: g.KernelRelease, ContainerRuntimeVersion: g.ContainerRuntimeVersion, KubeletVersion: g.KubeletVersion,
			Arch: g.Arch, Members: len(g.Members), ExposedNodes: len(g.ExposedNodes), Counts: priorityCounts(st.Counts),
			Fixable: st.Fixable, Gaps: &gaps,
		}
		for _, m := range g.Members {
			a := agents.of(m)
			switch a.CountState() {
			case model.AgentReporting:
				row.Agents.Reporting++
			case model.AgentReportingWithoutInventory:
				row.Agents.ReportingWithoutInventory++
			case model.AgentUnsupported:
				row.Agents.Unsupported++
			case model.AgentStale:
				row.Agents.Stale++
			case model.AgentNever:
				row.Agents.Never++
			case model.AgentDisabled:
				row.Agents.Disabled++
			}
			if a.RebootPending {
				row.RebootPending++
			}
		}
		if b := base[g.Arch]; b.ID != g.ID {
			row.Drift = nodegroup.Summary(nodegroup.Drift(b, g, nil, nil))
		}
		rows = append(rows, row)
	}
	cluster, at := s.stamp()
	return apigen.ListNodeGroups200JSONResponse{Cluster: cluster, GeneratedAt: at, AgentEnabled: agents.enabled,
		ControlPlane: cp, Groups: rows}, nil
}

// GetNodeGroup is one node group, found by its key, a stable form of it, its label or its ID
// (groupSet.find): its description, members, drift against every other group (with the package
// comparison when both are agent groups), an optional detailed comparison, its host findings and
// the images cached on its members.
func (s *Server) GetNodeGroup(ctx context.Context, req apigen.GetNodeGroupRequestObject) (apigen.GetNodeGroupResponseObject, error) {
	gs, err := s.groupSet(ctx)
	if err != nil {
		return nil, err
	}
	g, ok := gs.find(req.Id)
	if !ok {
		return nil, notFound("node group " + req.Id + " not found")
	}
	var compare *model.NodeGroup
	if req.Params.Compare != nil && *req.Params.Compare != "" {
		other, ok := gs.find(*req.Params.Compare)
		if !ok {
			return nil, notFound("node group " + *req.Params.Compare + " not found")
		}
		compare = &other
	}
	agents, err := s.agentView(ctx)
	if err != nil {
		return nil, err
	}
	members, err := s.nodeRows(ctx, g, agents)
	if err != nil {
		return nil, err
	}
	drift := make([]apigen.DriftRow, 0, len(gs.groups))
	for _, other := range gs.groups {
		if other.ID == g.ID {
			continue
		}
		d, err := s.drift(ctx, other, g)
		if err != nil {
			return nil, err
		}
		drift = append(drift, apigen.DriftRow{
			Other: gs.ref(other), Summary: nodegroup.Summary(d), Fields: fieldDrift(d.Fields), PackagesCompared: d.PackagesCompared,
			NewerHere: d.NewerInTo, NewerThere: d.NewerInFrom, OnlyHere: len(d.OnlyTo), OnlyThere: len(d.OnlyFrom),
		})
	}
	st, err := s.groupStats(ctx, g)
	if err != nil {
		return nil, err
	}
	cached := []apigen.NodeImage{}
	if g.Kind == model.NodeGroupAgent {
		imgs, err := s.o.Store.NodeGroupImages(ctx, g.ID)
		if err != nil {
			return nil, err
		}
		cached = liveImages(imgs, agents.byNode)
	}
	cluster, at := s.stamp()
	out := apigen.GetNodeGroup200JSONResponse{
		Cluster: cluster, GeneratedAt: at, Group: nodeGroupOf(g, gs.key(g)), AgentData: g.Kind == model.NodeGroupAgent, Members: members,
		Drift: drift, Counts: priorityCounts(st.Counts), Fixable: st.Fixable, CachedImages: cached,
	}
	if compare != nil {
		d, err := s.drift(ctx, *compare, g)
		if err != nil {
			return nil, err
		}
		out.Compare = driftDetail(d, gs.key(*compare), gs.key(g))
	}
	return out, nil
}

// drift compares group to with group from: over their stored host SBOMs when both are agent groups,
// else on the node fields alone.
func (s *Server) drift(ctx context.Context, from, to model.NodeGroup) (model.NodeDrift, error) {
	if from.Kind == model.NodeGroupAgent && to.Kind == model.NodeGroupAgent {
		return s.o.Store.NodeDrift(ctx, from.ID, to.ID)
	}
	return nodegroup.Drift(from, to, nil, nil), nil
}

// nodeRows are a group's members: readiness from the inventory, exposure from the group, and the
// agent status.
func (s *Server) nodeRows(ctx context.Context, g model.NodeGroup, agents *agentView) ([]apigen.NodeRow, error) {
	nodes, err := s.o.Store.ListNodes(ctx)
	if err != nil {
		return nil, err
	}
	ready := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		ready[n.Name] = n.Ready
	}
	out := make([]apigen.NodeRow, 0, len(g.Members))
	for _, m := range g.Members {
		out = append(out, apigen.NodeRow{Name: m, Ready: ready[m], Exposed: slices.Contains(g.ExposedNodes, m),
			Agent: agentStatusOf(agents.of(m))})
	}
	return out, nil
}

// liveImages keeps the cached images held by a node whose agent is reporting or stale, listing
// only those holders: the agent never clears what it reported once it stops.
func liveImages(imgs []model.NodeImage, agents map[string]model.NodeAgentStatus) []apigen.NodeImage {
	out := []apigen.NodeImage{}
	for _, img := range imgs {
		img.Nodes = slices.DeleteFunc(slices.Clone(img.Nodes), func(n string) bool { return !liveAgent(agents[n].State) })
		if len(img.Nodes) > 0 {
			out = append(out, nodeImageOf(img))
		}
	}
	return out
}

// GetNode is one node: its node status, group, agent status, exposure, its group's host findings
// and, while its agent reports, the images cached on it.
func (s *Server) GetNode(ctx context.Context, req apigen.GetNodeRequestObject) (apigen.GetNodeResponseObject, error) {
	nodes, err := s.o.Store.ListNodes(ctx)
	if err != nil {
		return nil, err
	}
	i := slices.IndexFunc(nodes, func(n model.Node) bool { return n.Name == req.Name })
	if i < 0 {
		return nil, notFound("node " + req.Name + " not found")
	}
	n := nodes[i]
	info := apigen.NodeInfo{Name: n.Name, Os: n.OS, Arch: n.Arch, OsImage: n.OSImage, KernelVersion: n.KernelVersion,
		KubeletVersion: n.KubeletVersion, ContainerRuntimeVersion: n.ContainerRuntimeVersion, Ready: n.Ready}
	if pv, ok := eol.NodeOSProduct(n.OSImage); ok {
		info.OsEol = s.eolFor(pv)
	}
	gs, err := s.groupSet(ctx)
	if err != nil {
		return nil, err
	}
	g, inGroup := gs.of(n.Name)
	agent, ok, err := s.o.Store.NodeAgentStatus(ctx, n.Name, s.o.Now(), s.o.Config.NodeAgent.StaleAfter)
	if err != nil {
		return nil, err
	}
	if !ok {
		state, err := s.o.Store.NodesState(ctx)
		if err != nil {
			return nil, err
		}
		agent = missingAgent(n.Name, state.AgentEnabled)
	}
	var (
		ref *apigen.GroupRef
		st  store.OwnerStats
	)
	if inGroup {
		r := gs.ref(g)
		ref = &r
		if st, err = s.groupStats(ctx, g); err != nil {
			return nil, err
		}
	}
	cached := []apigen.NodeImage{}
	if liveAgent(agent.State) {
		imgs, err := s.o.Store.NodeImages(ctx, n.Name)
		if err != nil {
			return nil, err
		}
		for _, img := range imgs {
			cached = append(cached, nodeImageOf(img))
		}
	}
	cluster, at := s.stamp()
	return apigen.GetNode200JSONResponse{
		Cluster: cluster, GeneratedAt: at, Node: info, Group: ref, Agent: agentStatusOf(agent),
		Exposed: inGroup && slices.Contains(g.ExposedNodes, n.Name), Counts: priorityCounts(st.Counts), Fixable: st.Fixable,
		CachedImages: cached,
	}, nil
}

// controlPlane summarises the Kubernetes versions and container runtimes in use, with their
// lifecycle, the open findings of the Cluster and ContainerRuntime owners, and their upgrades.
func (s *Server) controlPlane(ctx context.Context) (apigen.ControlPlane, error) {
	ci, _, err := s.o.Store.GetClusterInfo(ctx)
	if err != nil {
		return apigen.ControlPlane{}, err
	}
	nodes, err := s.o.Store.ListNodes(ctx)
	if err != nil {
		return apigen.ControlPlane{}, err
	}
	owner, _, err := s.o.Store.GetOwner(ctx, model.OwnerRef{Kind: model.OwnerKindCluster, Name: s.o.Config.ClusterName}.Key())
	if err != nil {
		return apigen.ControlPlane{}, err
	}
	stats, err := s.o.Store.ScopeStats(ctx, model.Scope{Kind: model.ScopeControlPlane})
	if err != nil {
		return apigen.ControlPlane{}, err
	}
	keys, err := s.controlPlaneKeys(ctx)
	if err != nil {
		return apigen.ControlPlane{}, err
	}
	suggestions, err := s.suggestions(ctx, func(owner string, _ model.Suggestion) bool { return slices.Contains(keys, owner) })
	if err != nil {
		return apigen.ControlPlane{}, err
	}

	kubelets := map[string]int{}
	type runtime struct{ name, version string }
	runtimes := map[runtime]int{}
	for _, n := range nodes {
		if v, _, _, err := inventory.NormalizeK8sVersion(n.KubeletVersion); err == nil {
			kubelets[v]++
		}
		if name, v, ok := inventory.ParseRuntimeVersion(n.ContainerRuntimeVersion); ok {
			runtimes[runtime{name, v}]++
		}
	}
	var versions []string
	for _, c := range owner.Containers {
		if v, ok := strings.CutPrefix(c.Digest, "k8s:"); ok && !slices.Contains(versions, v) {
			versions = append(versions, v)
		}
	}
	slices.Sort(versions)
	out := apigen.ControlPlane{Kubernetes: []apigen.KubernetesVersion{}, Runtimes: []apigen.RuntimeVersion{},
		Counts: priorityCounts(stats.Counts), Fixable: stats.Fixable, Suggestions: suggestions}
	for _, v := range versions {
		out.Kubernetes = append(out.Kubernetes, apigen.KubernetesVersion{Version: v, Nodes: kubelets[v],
			Eol: s.eolFor(eol.ClusterProduct(ci.Distribution, v))})
	}
	byName := func(a, b runtime) int { return cmp.Or(cmp.Compare(a.name, b.name), cmp.Compare(a.version, b.version)) }
	for _, k := range slices.SortedFunc(maps.Keys(runtimes), byName) {
		rv := apigen.RuntimeVersion{Name: k.name, Version: k.version, Nodes: runtimes[k]}
		if pv, ok := eol.ContainerRuntimeProduct(k.name, k.version); ok {
			rv.Eol = s.eolFor(pv)
		}
		out.Runtimes = append(out.Runtimes, rv)
	}
	return out, nil
}

// eolFor is the lifecycle status of a product version; nil without lifecycle data or a known cycle.
func (s *Server) eolFor(pv eol.ProductVersion) *apigen.EOL {
	if s.o.EOL == nil {
		return nil
	}
	st, ok := s.o.EOL.Evaluate(pv.Product, pv.Version)
	if !ok {
		return nil
	}
	e := eolOf(st, s.o.Now())
	return &e
}

// ref is a reference to g by its key.
func (gs *groupSet) ref(g model.NodeGroup) apigen.GroupRef {
	return apigen.GroupRef{Id: gs.key(g), Label: g.Label, Kind: apigen.NodeGroupKind(g.Kind)}
}

// nodeGroupOf shapes g, identified by key.
func nodeGroupOf(g model.NodeGroup, key string) apigen.NodeGroup {
	out := apigen.NodeGroup{
		Id: key, Kind: apigen.NodeGroupKind(g.Kind), Name: g.Name, Label: g.Label, Digest: g.Digest, OsImage: g.OSImage,
		KernelRelease: g.KernelRelease, ContainerRuntimeVersion: g.ContainerRuntimeVersion, KubeletVersion: g.KubeletVersion,
		Arch: g.Arch, Binaries: []apigen.NodeBinary{}, PackageDb: g.PackageDB, PackageCount: g.PackageCount,
		FirstSeen: optTime(g.FirstSeen), LastSeen: optTime(g.LastSeen),
	}
	if d := g.Distro; d != nil {
		out.Distro = &apigen.Distro{Id: d.ID, VersionId: d.VersionID, Codename: d.Codename}
	}
	if k := g.Kernel; k != nil {
		out.Kernel = &apigen.NodeKernel{Release: k.Release, Package: k.Package, Version: k.Version, SourceName: k.SourceName}
	}
	for _, b := range g.Binaries {
		out.Binaries = append(out.Binaries, apigen.NodeBinary{Name: b.Name, Path: b.Path, Module: b.Module, Version: b.Version})
	}
	return out
}

// agentStatusOf shapes a node's agent status; report times are left out until there is one.
func agentStatusOf(st model.NodeAgentStatus) apigen.AgentStatus {
	out := apigen.AgentStatus{
		State: apigen.AgentState(st.State), AgentVersion: optString(st.AgentVersion), LastReport: optTime(st.LastReport),
		LastFullReport: optTime(st.LastFullReport), LastError: optString(st.LastError), KernelRelease: optString(st.KernelRelease),
		RebootPending: st.RebootPending, RebootReason: optString(st.RebootReason), Gaps: []apigen.NodeGap{}, Problems: nz(st.Problems),
	}
	for _, g := range st.Coverage {
		out.Gaps = append(out.Gaps, apigen.NodeGap{Code: apigen.GapCode(g.Code), Detail: g.Detail})
	}
	return out
}

func nodeImageOf(img model.NodeImage) apigen.NodeImage {
	out := apigen.NodeImage{
		Digest: img.Digest, ConfigDigest: img.ConfigDigest, Kind: img.Kind, Names: nz(img.Names), SizeBytes: img.SizeBytes,
		Complete: img.Complete, InUse: img.InUse, Nodes: nz(img.Nodes), Source: apigen.NodeImageSource(img.Source),
		StatusReason: optString(img.StatusReason),
	}
	if img.Status != "" {
		st := apigen.ImageStatus(img.Status)
		out.Status = &st
	}
	return out
}

func fieldDrift(fs []model.FieldDrift) []apigen.FieldDrift {
	out := make([]apigen.FieldDrift, 0, len(fs))
	for _, f := range fs {
		out = append(out, apigen.FieldDrift{Field: f.Field, From: f.From, To: f.To})
	}
	return out
}

func driftPackages(ps []model.DriftPackage) []apigen.DriftPackage {
	out := make([]apigen.DriftPackage, 0, len(ps))
	for _, p := range ps {
		out = append(out, apigen.DriftPackage{Ecosystem: p.Ecosystem, Name: p.Name, Version: p.Version, Arch: p.Arch})
	}
	return out
}

// driftDetail shapes a comparison: from is the other group and to is this one, by their keys.
func driftDetail(d model.NodeDrift, from, to string) *apigen.NodeDriftDetail {
	out := &apigen.NodeDriftDetail{From: from, To: to, Fields: fieldDrift(d.Fields), PackagesCompared: d.PackagesCompared,
		OnlyFrom: driftPackages(d.OnlyFrom), OnlyTo: driftPackages(d.OnlyTo), Changed: []apigen.VersionDrift{}}
	for _, c := range d.Changed {
		out.Changed = append(out.Changed, apigen.VersionDrift{Ecosystem: c.Ecosystem, Name: c.Name, Arch: c.Arch, From: c.From,
			To: c.To, Newer: apigen.VersionDriftNewer(c.Newer)})
	}
	return out
}
