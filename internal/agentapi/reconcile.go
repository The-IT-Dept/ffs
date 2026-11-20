package agentapi

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/conversion"
	"k8s.io/apimachinery/pkg/labels"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/engine"
	"github.com/the-it-dept/ffs/internal/inventory"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/nodegroup"
	"github.com/the-it-dept/ffs/internal/store"
)

const (
	defaultReconcileInterval = time.Minute
	// triggerGap keeps triggered passes apart, so a burst of reports costs one pass.
	triggerGap = 5 * time.Second
	// baselineSettleMax bounds the node baseline's settle window: the baseline is ready once every
	// scheduled Ready node is in a matched agent group, or min(staleAfter, baselineSettleMax) after the
	// first fresh agent report, whichever comes first.
	baselineSettleMax = 10 * time.Minute
)

// Rehomer is the engine as the reconciler uses it; *engine.Engine implements it.
type Rehomer interface {
	Rehome(ctx context.Context, r engine.Rehome) error
	OnOwnersChanged(ctx context.Context, keys []string) error
	Recompute(ctx context.Context, keys []string, trig model.Trigger) error
}

// ClusterMarker queues the cluster-level owners for an inventory flush; *inventory.Inventory implements it.
type ClusterMarker interface{ MarkCluster() }

var (
	_ Rehomer       = (*engine.Engine)(nil)
	_ ClusterMarker = (*inventory.Inventory)(nil)
)

// ReconcilerOptions configures a Reconciler.
type ReconcilerOptions struct {
	Store     *store.Store
	Engine    Rehomer
	Inventory ClusterMarker // nil: the cluster owners are not re-flushed after a cutover
	Nodes     client.Reader // cache-backed: the cluster's Nodes
	Pods      PodIndex
	Config    config.Config
	Interval  time.Duration // 0: 1m
	Now       func() time.Time
	Log       logr.Logger
}

// Reconciler maintains the node groups, the Nodes owner (one container per agent group with members), the
// ContainerRuntime cutover and the node baseline. It is the only writer of node_group_members, the Nodes
// owner and nodes_state, and it runs on the leader only.
type Reconciler struct {
	o       ReconcilerOptions
	trigger chan struct{}
}

// NewReconciler returns a Reconciler.
func NewReconciler(o ReconcilerOptions) *Reconciler {
	if o.Interval <= 0 {
		o.Interval = defaultReconcileInterval
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Reconciler{o: o, trigger: make(chan struct{}, 1)}
}

// Trigger asks for a pass soon. Triggers coalesce: it never blocks.
func (r *Reconciler) Trigger() {
	select {
	case r.trigger <- struct{}{}:
	default:
	}
}

// NeedLeaderElection makes the reconciler leader-only: it writes the store.
func (r *Reconciler) NeedLeaderElection() bool { return true }

// Start runs a pass at once, then every Interval and on every trigger, triggered passes at least triggerGap
// apart. A failed pass is logged; the next one resumes, as every write is idempotent.
func (r *Reconciler) Start(ctx context.Context) error {
	tick := time.NewTicker(r.o.Interval)
	defer tick.Stop()
	var last time.Time
	run := func() {
		last = time.Now()
		if err := r.ReconcileOnce(ctx); err != nil && ctx.Err() == nil {
			r.o.Log.Error(err, "reconciling node groups failed; retrying at the next pass")
		}
	}
	run()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			run()
		case <-r.trigger:
			if wait := triggerGap - time.Since(last); wait > 0 {
				t := time.NewTimer(wait)
				select {
				case <-ctx.Done():
					t.Stop()
					return nil
				case <-t.C:
				}
			}
			// This pass covers every trigger that arrived while waiting.
			select {
			case <-r.trigger:
			default:
			}
			run()
		}
	}
}

// nodeEvents triggers a pass when a Node is added or deleted, or its labels or Ready condition change.
func nodeEvents(trigger func()) toolscache.ResourceEventHandlerFuncs {
	return toolscache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { trigger() },
		DeleteFunc: func(any) { trigger() },
		UpdateFunc: func(oldObj, newObj any) {
			o, ok1 := oldObj.(*corev1.Node)
			n, ok2 := newObj.(*corev1.Node)
			if !ok1 || !ok2 || !maps.Equal(o.Labels, n.Labels) || readyStatus(o) != readyStatus(n) {
				trigger()
			}
		},
	}
}

func readyStatus(n *corev1.Node) corev1.ConditionStatus {
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady {
			return c.Status
		}
	}
	return ""
}

// nodeInfo is the cluster inventory's model of a Node: what its nodeinfo fallback group is built from.
func nodeInfo(n *corev1.Node, now time.Time) model.Node {
	i := n.Status.NodeInfo
	return model.Node{Name: n.Name, OS: i.OperatingSystem, Arch: i.Architecture, OSImage: i.OSImage,
		KernelVersion: i.KernelVersion, KubeletVersion: i.KubeletVersion, ContainerRuntimeVersion: i.ContainerRuntimeVersion,
		Ready: readyStatus(n) == corev1.ConditionTrue, UpdatedAt: now}
}

// pass is one ReconcileOnce: its reads, memoised by group ID.
type pass struct {
	ctx       context.Context
	st        *store.Store
	unmatched map[string]bool
	groups    map[string]groupRow
	matchedOf map[string]bool
}

type groupRow struct {
	g  model.NodeGroup
	ok bool
}

// group reads a stored group, memberless included (NodeGroups lists only groups with members, and a newly
// ingested group has none until a node joins it).
func (p *pass) group(id string) (model.NodeGroup, bool, error) {
	if row, ok := p.groups[id]; ok {
		return row.g, row.ok, nil
	}
	g, ok, err := p.st.NodeGroup(p.ctx, id)
	if err != nil {
		return model.NodeGroup{}, false, fmt.Errorf("node group %s: %w", id, err)
	}
	p.groups[id] = groupRow{g: g, ok: ok}
	return g, ok, nil
}

func (p *pass) isAgent(id string) (bool, error) {
	if id == "" {
		return false, nil
	}
	g, ok, err := p.group(id)
	return ok && g.Kind == model.NodeGroupAgent, err
}

// matched reports whether id is an agent group whose host SBOM is catalogued and matched.
func (p *pass) matched(id string) (bool, error) {
	if m, ok := p.matchedOf[id]; ok {
		return m, nil
	}
	agent, err := p.isAgent(id)
	if err != nil || !agent {
		return false, err
	}
	digest := nodegroup.GroupDigest(id)
	img, ok, err := p.st.GetImage(p.ctx, digest)
	if err != nil {
		return false, fmt.Errorf("group image %s: %w", digest, err)
	}
	m := ok && img.Status == model.ImageCatalogued && !p.unmatched[digest]
	p.matchedOf[id] = m
	return m, nil
}

// ReconcileOnce runs one pass (Contract › Data flows › Reconcile). Any error aborts the pass; every write
// is idempotent, so the next pass resumes.
func (r *Reconciler) ReconcileOnce(ctx context.Context) error {
	cfg, st := r.o.Config, r.o.Store
	enabled, now := cfg.NodeAgent.Enabled, r.o.Now()
	nodesRef := model.NodesOwner(cfg.ClusterName)
	nodesKey := nodesRef.Key()

	state, err := st.NodesState(ctx)
	if err != nil {
		return fmt.Errorf("nodes state: %w", err)
	}
	written := state
	if !enabled && (state.AgentEnabled || !state.BaselineReadyAt.IsZero() || !state.FirstReportAt.IsZero()) {
		// Cleared before this pass moves or deletes any host finding, so a notify pass in between holds
		// their transitions rather than sending them (spec §9.9).
		state.AgentEnabled, state.BaselineReadyAt, state.FirstReportAt = false, time.Time{}, time.Time{}
		if err := st.PutNodesState(ctx, state); err != nil {
			return err
		}
		written = state
	}
	sel, err := cfg.NodeAgent.ExposedSelector()
	if err != nil {
		return fmt.Errorf("nodeAgent.exposedNodes: %w", err)
	}
	var list corev1.NodeList
	if err := r.o.Nodes.List(ctx, &list); err != nil {
		return fmt.Errorf("listing nodes: %w", err)
	}
	nodes := list.Items
	slices.SortFunc(nodes, func(a, b corev1.Node) int { return cmp.Compare(a.Name, b.Name) })
	names := make([]string, len(nodes))
	for i := range nodes {
		names[i] = nodes[i].Name
	}
	if err := st.PruneAgentNodes(ctx, names); err != nil {
		return err
	}
	agentRows, err := st.AgentNodes(ctx)
	if err != nil {
		return err
	}
	agents := make(map[string]store.AgentNode, len(agentRows))
	for _, a := range agentRows {
		agents[a.Node] = a
	}
	state.Unsupported, state.FullReportOverdue = nil, 0
	if enabled {
		state.Unsupported = unsupportedNodes(cfg.NodeAgent, nodes)
		state.FullReportOverdue = fullReportOverdue(cfg.NodeAgent)
		if state.FirstReportAt.IsZero() && slices.ContainsFunc(agentRows, func(a store.AgentNode) bool {
			return !a.LastReport.Before(now.Add(-cfg.NodeAgent.StaleAfter))
		}) {
			state.FirstReportAt = now
		}
	}
	unmatched, err := st.UnmatchedImages(ctx)
	if err != nil {
		return err
	}
	p := &pass{ctx: ctx, st: st, unmatched: map[string]bool{}, groups: map[string]groupRow{}, matchedOf: map[string]bool{}}
	for _, u := range unmatched {
		p.unmatched[u.Digest] = true
	}

	members, fallback, err := r.membership(p, nodes, agents, enabled, now)
	if err != nil {
		return err
	}
	var agentIDs []string
	exposed := map[string][]string{}
	for i := range nodes {
		n := &nodes[i]
		id := members[n.Name]
		if agent, err := p.isAgent(id); err != nil {
			return err
		} else if agent && !slices.Contains(agentIDs, id) {
			agentIDs = append(agentIDs, id)
		}
		if sel.Matches(labels.Set(n.Labels)) {
			exposed[id] = append(exposed[id], n.Name) // nodes are sorted by name
		}
	}
	slices.SortFunc(agentIDs, func(a, b string) int {
		return cmp.Or(cmp.Compare(p.groups[a].g.Label, p.groups[b].g.Label), cmp.Compare(a, b))
	})
	inUse := make(map[string][]string, len(agentRows))
	for _, a := range agentRows {
		digests, err := r.o.Pods.DigestsOnNode(ctx, a.Node)
		if err != nil {
			return fmt.Errorf("pods on %s: %w", a.Node, err)
		}
		inUse[a.Node] = slices.Sorted(maps.Keys(digests))
	}
	// One transaction that writes only what changed: an idle pass writes nothing.
	if err := st.ApplyNodeGrouping(ctx, store.NodeGrouping{Members: members, Fallback: nodegroup.FallbackGroups(fallback, now),
		Exposed: exposed, InUse: inUse, Now: now}); err != nil {
		return err
	}

	fresh, err := r.fresh(p, nodes, agents, members, state.Unsupported, now)
	if err != nil {
		return err
	}
	owner := func(retired bool) model.Owner {
		o := model.Owner{Ref: nodesRef, UpdatedAt: now, SuppressModules: nodegroup.SuppressedModules(retired)}
		for _, id := range agentIDs {
			g := p.groups[id].g
			c := model.ContainerUse{Name: g.Label, Kind: model.ContainerRegular, ImageRef: g.Label, Repo: model.HostRepo,
				Digest: nodegroup.GroupDigest(id), Platform: "linux/" + g.Arch}
			for _, m := range exposed[id] {
				c.ExposurePaths = append(c.ExposurePaths, fmt.Sprintf(model.NodeExposurePathFmt, m))
			}
			o.Containers = append(o.Containers, c)
			if g.Arch != "" && !slices.Contains(o.Arch, g.Arch) {
				o.Arch = append(o.Arch, g.Arch)
			}
		}
		slices.Sort(o.Arch)
		return o
	}

	cutover := func(r2 engine.Rehome, retired bool) error {
		next := state
		next.RuntimeRetired, next.NotFreshSince, next.ChangedAt = retired, time.Time{}, now
		// Written with the moves, in one transaction, and before MarkCluster: inventory reads RuntimeRetired
		// from the store when it flushes the cluster, and a crash cannot leave one without the other.
		r2.State = &next
		if err := r.o.Engine.Rehome(ctx, r2); err != nil {
			return err
		}
		state, written = next, next
		if r.o.Inventory != nil {
			r.o.Inventory.MarkCluster()
		}
		return nil
	}
	switch {
	case !state.RuntimeRetired && enabled && fresh:
		moves, drop, err := r.runtimeFindings(ctx, nodesRef)
		if err != nil {
			return err
		}
		o := owner(true)
		r.o.Log.Info("every node agent is reporting; container runtime findings move to the Nodes owner", "findings", len(moves))
		if err := cutover(engine.Rehome{Upsert: &o, Moves: moves, Drop: drop}, true); err != nil {
			return err
		}
	case state.RuntimeRetired && (!enabled || (!fresh && !state.NotFreshSince.IsZero() &&
		now.Sub(state.NotFreshSince) >= cfg.NodeAgent.RuntimeGrace)):
		moves, err := r.nodesRuntimeFindings(ctx, nodesKey)
		if err != nil {
			return err
		}
		o := owner(false)
		r.o.Log.Info("node agents are disabled or not reporting; container runtime findings return to the ContainerRuntime owner",
			"findings", len(moves), "enabled", enabled)
		if err := cutover(engine.Rehome{Upsert: &o, Moves: moves}, false); err != nil {
			return err
		}
	case state.RuntimeRetired && !fresh && state.NotFreshSince.IsZero():
		state.NotFreshSince = now
	case fresh:
		state.NotFreshSince = time.Time{}
	}
	if state.RuntimeRetired {
		if err := r.healRetiredRuntime(ctx, nodesRef); err != nil {
			return err
		}
	}

	want := owner(state.RuntimeRetired)
	stored, ok, err := st.GetOwner(ctx, nodesKey)
	if err != nil {
		return err
	}
	switch {
	case len(agentIDs) == 0:
		if ok {
			if err := st.DeleteOwner(ctx, nodesKey); err != nil {
				return err
			}
			if err := r.o.Engine.OnOwnersChanged(ctx, []string{nodesKey}); err != nil {
				return err
			}
		}
	case !ok || !sameOwner(stored, want):
		if err := st.UpsertOwner(ctx, want); err != nil {
			return err
		}
		if err := r.o.Engine.OnOwnersChanged(ctx, []string{nodesKey}); err != nil {
			return err
		}
	}

	// The node baseline waits until every scheduled Ready node is in a matched agent group (fresh), or for
	// the settle window after the first fresh report, so groups that match later are in it too rather than
	// alerting finding by finding (spec §9.9).
	settle := min(cfg.NodeAgent.StaleAfter, baselineSettleMax)
	settled := fresh || (!state.FirstReportAt.IsZero() && now.Sub(state.FirstReportAt) >= settle)
	if state.BaselineReadyAt.IsZero() && enabled && len(agentIDs) > 0 && settled {
		all := true
		for _, id := range agentIDs {
			m, err := p.matched(id)
			if err != nil {
				return err
			}
			all = all && m
		}
		if all {
			// Synchronous, so the first node findings exist before notify sees the baseline as ready.
			if err := r.o.Engine.Recompute(ctx, []string{nodesKey}, model.TriggerInventoryChange); err != nil {
				return err
			}
			state.BaselineReadyAt = now
		}
	}
	if !enabled {
		state.BaselineReadyAt, state.FirstReportAt = time.Time{}, time.Time{} // re-enabling baselines again
	}
	state.AgentEnabled = enabled
	if !sameState(state, written) {
		return st.PutNodesState(ctx, state)
	}
	return nil
}

// membership assigns every node a group: its latest fingerprint once that group is catalogued and matched,
// else its current agent group (a stale node keeps its group), else its nodeinfo fallback group, which it
// also returns. With the agent disabled every node falls back.
func (r *Reconciler) membership(p *pass, nodes []corev1.Node, agents map[string]store.AgentNode, enabled bool,
	now time.Time) (map[string]string, []model.Node, error) {
	members := make(map[string]string, len(nodes))
	var fallback []model.Node
	for i := range nodes {
		n := &nodes[i]
		a, ok := agents[n.Name]
		if enabled && ok && a.Fingerprint != "" {
			m, err := p.matched(a.Fingerprint)
			if err != nil {
				return nil, nil, err
			}
			if m {
				members[n.Name] = a.Fingerprint
				continue
			}
		}
		if enabled && ok {
			agent, err := p.isAgent(a.GroupID)
			if err != nil {
				return nil, nil, err
			}
			if agent {
				members[n.Name] = a.GroupID
				continue
			}
		}
		fb := nodeInfo(n, now)
		members[n.Name] = nodegroup.FallbackID(fb)
		fallback = append(fallback, fb)
	}
	return members, fallback, nil
}

// fresh reports whether at least one scheduled node is Ready and every scheduled Ready node is in an agent
// group with a report no older than StaleAfter. Nodes the agent DaemonSet does not schedule on (unsupported)
// are left out, so they never hold back the runtime cutover or the node baseline.
func (r *Reconciler) fresh(p *pass, nodes []corev1.Node, agents map[string]store.AgentNode, members map[string]string,
	unsupported map[string]string, now time.Time) (bool, error) {
	ready := 0
	since := now.Add(-r.o.Config.NodeAgent.StaleAfter)
	for i := range nodes {
		n := &nodes[i]
		if _, skip := unsupported[n.Name]; skip || readyStatus(n) != corev1.ConditionTrue {
			continue
		}
		ready++
		a, ok := agents[n.Name]
		if !ok || a.LastReport.Before(since) {
			return false, nil
		}
		if agent, err := p.isAgent(members[n.Name]); err != nil || !agent {
			return false, err
		}
	}
	return ready > 0, nil
}

// unsupportedNodes returns the nodes the agent DaemonSet does not schedule on, as far as the configuration
// tells (NodeAgentConfig.ScheduledOn), each with why; nil when there are none.
func unsupportedNodes(na config.NodeAgentConfig, nodes []corev1.Node) map[string]string {
	var out map[string]string
	for i := range nodes {
		if ok, why := na.ScheduledOn(nodes[i].Labels, nodes[i].Status.NodeInfo.Architecture); !ok {
			if out == nil {
				out = map[string]string{}
			}
			out[nodes[i].Name] = why
		}
	}
	return out
}

// fullReportOverdue is how old a reporting node's last full report may be before its host inventory counts
// as not current: the report interval with its jitter, plus staleAfter.
func fullReportOverdue(na config.NodeAgentConfig) time.Duration {
	return na.ReportInterval + na.ReportInterval*jitterPercent/100 + na.StaleAfter
}

// healRetiredRuntime re-homes the findings of any ContainerRuntime owner stored while the runtime is retired
// onto the Nodes owner and drops it. Such an owner is left by an inventory flush that raced a cutover, or by
// an older version; without this it would duplicate the Nodes owner's findings until the next cutover.
func (r *Reconciler) healRetiredRuntime(ctx context.Context, nodesRef model.OwnerRef) error {
	keys, err := r.o.Store.RuntimeOwnerKeys(ctx)
	if err != nil || len(keys) == 0 {
		return err
	}
	moves, drop, err := r.runtimeFindings(ctx, nodesRef)
	if err != nil || len(drop) == 0 {
		return err
	}
	r.o.Log.Info("container runtime owner found while the node agent has retired it; moving its findings to the Nodes owner",
		"owners", drop, "findings", len(moves))
	return r.o.Engine.Rehome(ctx, engine.Rehome{Moves: moves, Drop: drop})
}

// runtimeFindings returns the moves of every non-resolved finding of the stored ContainerRuntime owners onto
// the Nodes owner, and those owners' keys.
func (r *Reconciler) runtimeFindings(ctx context.Context, nodesRef model.OwnerRef) ([]engine.FindingMove, []string, error) {
	owners, err := r.o.Store.ListOwners(ctx)
	if err != nil {
		return nil, nil, err
	}
	var (
		moves []engine.FindingMove
		drop  []string
	)
	for _, o := range owners {
		if o.Ref.Kind != model.OwnerKindContainerRuntime || o.Ref.Namespace != "" {
			continue
		}
		key := o.Ref.Key()
		drop = append(drop, key)
		fs, err := r.o.Store.FindingsForOwner(ctx, key)
		if err != nil {
			return nil, nil, err
		}
		for _, f := range fs {
			if f.State != model.StateResolved {
				moves = append(moves, engine.FindingMove{Fingerprint: f.Fingerprint, To: nodesRef, ToRepo: model.HostRepo})
			}
		}
	}
	return moves, drop, nil
}

// nodesRuntimeFindings returns the moves of the Nodes owner's non-resolved container runtime findings back
// to their ContainerRuntime owner. A finding only on runc stays: the ContainerRuntime owner never reports it.
func (r *Reconciler) nodesRuntimeFindings(ctx context.Context, nodesKey string) ([]engine.FindingMove, error) {
	fs, err := r.o.Store.FindingsForOwner(ctx, nodesKey)
	if err != nil {
		return nil, err
	}
	var moves []engine.FindingMove
	for _, f := range fs {
		if f.State == model.StateResolved {
			continue
		}
		if name, ok := nodegroup.RuntimeOwnerName(f.Packages); ok {
			moves = append(moves, engine.FindingMove{Fingerprint: f.Fingerprint,
				To: model.OwnerRef{Kind: model.OwnerKindContainerRuntime, Name: name}, ToRepo: name})
		}
	}
	return moves, nil
}

// ownerEquality is equality.Semantic (nil and empty slices are equal) that also compares times, whose
// unexported fields Semantic refuses.
var ownerEquality = func() conversion.Equalities {
	e := equality.Semantic.Copy()
	if err := e.AddFunc(func(a, b time.Time) bool { return a.Equal(b) }); err != nil {
		panic(err)
	}
	return e
}()

// sameOwner compares two Nodes owners, ignoring when each was built.
func sameOwner(a, b model.Owner) bool {
	a.UpdatedAt, b.UpdatedAt = time.Time{}, time.Time{}
	return ownerEquality.DeepEqual(a, b)
}

func sameState(a, b store.NodesState) bool {
	return a.AgentEnabled == b.AgentEnabled && a.RuntimeRetired == b.RuntimeRetired && a.NotFreshSince.Equal(b.NotFreshSince) &&
		a.ChangedAt.Equal(b.ChangedAt) && a.BaselineReadyAt.Equal(b.BaselineReadyAt) && a.FirstReportAt.Equal(b.FirstReportAt) &&
		a.FullReportOverdue == b.FullReportOverdue && maps.Equal(a.Unsupported, b.Unsupported)
}
