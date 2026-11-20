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

// nodeGroups are the node groups the API shows: the stored groups that have members, plus a
// nodeinfo fallback group (nodegroup.FallbackGroups) for the nodes no stored group lists. A fallback
// group whose ID is a stored group's (FallbackID is deterministic) adds its members to that group
// instead of a second row. Agent groups come first, then nodeinfo groups, each by Label and then ID.
func (s *Server) nodeGroups(ctx context.Context) ([]model.NodeGroup, error) {
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

// groupOf is the group a node belongs to: the stored group that lists it (Store.NodeGroupOfNode),
// else the fallback group holding it, as nodeGroups shows them (members merged).
func (s *Server) groupOf(ctx context.Context, node string) (model.NodeGroup, bool, error) {
	groups, err := s.nodeGroups(ctx)
	if err != nil {
		return model.NodeGroup{}, false, err
	}
	for _, g := range groups {
		if slices.Contains(g.Members, node) {
			return g, true, nil
		}
	}
	return model.NodeGroup{}, false, nil
}

// groupStats are a group's open host findings (node-level findings only, by its digest); a nodeinfo
// group has none.
func (s *Server) groupStats(ctx context.Context, g model.NodeGroup) (store.OwnerStats, error) {
	if g.Kind != model.NodeGroupAgent {
		return store.OwnerStats{}, nil
	}
	return s.o.Store.ScopeStats(ctx, model.Scope{Kind: model.ScopeNodeGroup, Value: g.ID})
}

// agentStatuses is the agent status of every stored node, by node name.
func (s *Server) agentStatuses(ctx context.Context) (map[string]model.NodeAgentStatus, error) {
	list, err := s.o.Store.AgentStatus(ctx, s.o.Now(), s.o.Config.NodeAgent.StaleAfter)
	if err != nil {
		return nil, err
	}
	out := make(map[string]model.NodeAgentStatus, len(list))
	for _, st := range list {
		out[st.Node] = st
	}
	return out, nil
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
// field drift against the largest group of the same architecture.
func (s *Server) ListNodeGroups(ctx context.Context, _ apigen.ListNodeGroupsRequestObject) (apigen.ListNodeGroupsResponseObject, error) {
	state, err := s.o.Store.NodesState(ctx)
	if err != nil {
		return nil, err
	}
	cp, err := s.controlPlane(ctx)
	if err != nil {
		return nil, err
	}
	groups, err := s.nodeGroups(ctx)
	if err != nil {
		return nil, err
	}
	agents, err := s.agentStatuses(ctx)
	if err != nil {
		return nil, err
	}
	// The base of each architecture: the group with the most members, ties by Label.
	base := map[string]model.NodeGroup{}
	for _, g := range groups {
		b, ok := base[g.Arch]
		if !ok || len(g.Members) > len(b.Members) || (len(g.Members) == len(b.Members) && g.Label < b.Label) {
			base[g.Arch] = g
		}
	}
	rows := make([]apigen.NodeGroupRow, 0, len(groups))
	for _, g := range groups {
		st, err := s.groupStats(ctx, g)
		if err != nil {
			return nil, err
		}
		row := apigen.NodeGroupRow{
			Id: g.ID, Kind: apigen.NodeGroupKind(g.Kind), Name: g.Name, Label: g.Label, OsImage: g.OSImage,
			KernelRelease: g.KernelRelease, ContainerRuntimeVersion: g.ContainerRuntimeVersion, KubeletVersion: g.KubeletVersion,
			Arch: g.Arch, Members: len(g.Members), ExposedNodes: len(g.ExposedNodes), Counts: priorityCounts(st.Counts),
			Fixable: st.Fixable,
		}
		for _, m := range g.Members {
			a, ok := agents[m]
			if !ok {
				a = missingAgent(m, state.AgentEnabled)
			}
			switch a.State {
			case model.AgentReporting:
				row.Agents.Reporting++
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
	return apigen.ListNodeGroups200JSONResponse{Cluster: cluster, GeneratedAt: at, AgentEnabled: state.AgentEnabled,
		ControlPlane: cp, Groups: rows}, nil
}

// GetNodeGroup is one node group: its description, members, drift against every other group (with
// the package comparison when both are agent groups), an optional detailed comparison, its host
// findings and the images cached on its members.
func (s *Server) GetNodeGroup(ctx context.Context, req apigen.GetNodeGroupRequestObject) (apigen.GetNodeGroupResponseObject, error) {
	groups, err := s.nodeGroups(ctx)
	if err != nil {
		return nil, err
	}
	find := func(id string) (model.NodeGroup, bool) {
		i := slices.IndexFunc(groups, func(g model.NodeGroup) bool { return g.ID == id })
		if i < 0 {
			return model.NodeGroup{}, false
		}
		return groups[i], true
	}
	g, ok := find(req.Id)
	if !ok {
		return nil, notFound("node group " + req.Id + " not found")
	}
	var compare *model.NodeGroup
	if req.Params.Compare != nil && *req.Params.Compare != "" {
		other, ok := find(*req.Params.Compare)
		if !ok {
			return nil, notFound("node group " + *req.Params.Compare + " not found")
		}
		compare = &other
	}
	state, err := s.o.Store.NodesState(ctx)
	if err != nil {
		return nil, err
	}
	agents, err := s.agentStatuses(ctx)
	if err != nil {
		return nil, err
	}
	members, err := s.nodeRows(ctx, g, agents, state.AgentEnabled)
	if err != nil {
		return nil, err
	}
	drift := make([]apigen.DriftRow, 0, len(groups))
	for _, other := range groups {
		if other.ID == g.ID {
			continue
		}
		d, err := s.drift(ctx, other, g)
		if err != nil {
			return nil, err
		}
		drift = append(drift, apigen.DriftRow{
			Other: groupRef(other), Summary: nodegroup.Summary(d), Fields: fieldDrift(d.Fields), PackagesCompared: d.PackagesCompared,
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
		cached = liveImages(imgs, agents)
	}
	cluster, at := s.stamp()
	out := apigen.GetNodeGroup200JSONResponse{
		Cluster: cluster, GeneratedAt: at, Group: nodeGroupOf(g), AgentData: g.Kind == model.NodeGroupAgent, Members: members,
		Drift: drift, Counts: priorityCounts(st.Counts), Fixable: st.Fixable, CachedImages: cached,
	}
	if compare != nil {
		d, err := s.drift(ctx, *compare, g)
		if err != nil {
			return nil, err
		}
		out.Compare = driftDetail(d)
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
func (s *Server) nodeRows(ctx context.Context, g model.NodeGroup, agents map[string]model.NodeAgentStatus, enabled bool) ([]apigen.NodeRow, error) {
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
		a, ok := agents[m]
		if !ok {
			a = missingAgent(m, enabled)
		}
		out = append(out, apigen.NodeRow{Name: m, Ready: ready[m], Exposed: slices.Contains(g.ExposedNodes, m), Agent: agentStatusOf(a)})
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
	g, inGroup, err := s.groupOf(ctx, n.Name)
	if err != nil {
		return nil, err
	}
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
		r := groupRef(g)
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
	suggestions, err := s.suggestions(ctx, func(owner string, _ model.Suggestion) bool { return isControlPlaneKey(owner) })
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

// isControlPlaneKey reports whether an owner key is the Cluster's or a ContainerRuntime's.
func isControlPlaneKey(key string) bool {
	return strings.HasPrefix(key, model.OwnerKindCluster+"/") || strings.HasPrefix(key, model.OwnerKindContainerRuntime+"/")
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

func groupRef(g model.NodeGroup) apigen.GroupRef {
	return apigen.GroupRef{Id: g.ID, Label: g.Label, Kind: apigen.NodeGroupKind(g.Kind)}
}

func nodeGroupOf(g model.NodeGroup) apigen.NodeGroup {
	out := apigen.NodeGroup{
		Id: g.ID, Kind: apigen.NodeGroupKind(g.Kind), Name: g.Name, Label: g.Label, Digest: g.Digest, OsImage: g.OSImage,
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

// driftDetail shapes a comparison: from is the other group and to is this one.
func driftDetail(d model.NodeDrift) *apigen.NodeDriftDetail {
	out := &apigen.NodeDriftDetail{From: d.From, To: d.To, Fields: fieldDrift(d.Fields), PackagesCompared: d.PackagesCompared,
		OnlyFrom: driftPackages(d.OnlyFrom), OnlyTo: driftPackages(d.OnlyTo), Changed: []apigen.VersionDrift{}}
	for _, c := range d.Changed {
		out.Changed = append(out.Changed, apigen.VersionDrift{Ecosystem: c.Ecosystem, Name: c.Name, Arch: c.Arch, From: c.From,
			To: c.To, Newer: apigen.VersionDriftNewer(c.Newer)})
	}
	return out
}
