package apiserver

import (
	"cmp"
	"context"
	"slices"
	"strings"

	"golang.org/x/sync/errgroup"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
	"github.com/the-it-dept/ffs/internal/web/apigen"
)

// exposureFold is how many children a group shows before the rest fold into one tail row; children
// with urgent findings are always shown.
const exposureFold = 8

// Row ids of the exposure table's fixed groups.
const (
	rowHost         = "host"
	rowNodes        = "nodes"
	rowInternal     = "internal"
	rowNotExposed   = "not-exposed"
	rowControlPlane = "controlplane"
	// tailSuffix ends a tail row's id. "~" is in no hostname, node name or owner key, so no child
	// id, and no child of another group, can end with it.
	tailSuffix = "/~tail"
)

// exposureData holds what the exposure table sums per owner.
type exposureData struct {
	owners map[string]store.OwnerEntity
	stats  map[string]store.OwnerStats
	images map[string][]store.DigestCoverage
	best   map[string]store.FixSummary
}

// signals sums the signal columns over owners: their open urgent, high, fixable and exploited
// findings, how many are privileged or hold a powerful service account, the coverage of the
// distinct images they run (an image several of them run counts once), and the best fix of any
// of them.
func (d *exposureData) signals(keys []string) apigen.RowSignals {
	var (
		sig       apigen.RowSignals
		priv, sa  int
		best      store.FixSummary
		hasBest   bool
		betterFix = func(a, b store.FixSummary) bool {
			return cmp.Or(cmp.Compare(b.Clears.Urgent, a.Clears.Urgent), cmp.Compare(b.Clears.High, a.Clears.High),
				cmp.Compare(b.Findings, a.Findings), strings.Compare(a.Key, b.Key)) < 0
		}
	)
	images := map[string]store.DigestCoverage{}
	for _, k := range keys {
		st := d.stats[k]
		sig.Urgent += st.Counts.Urgent
		sig.High += st.Counts.High
		sig.Fixable += st.Fixable
		sig.Exploited += st.Exploited
		if o := d.owners[k]; o.Privileged {
			priv++
		}
		if d.owners[k].PowerfulSA {
			sa++
		}
		for _, c := range d.images[k] {
			images[c.Digest] = c
		}
		if fs, ok := d.best[k]; ok && (!hasBest || betterFix(fs, best)) {
			best, hasBest = fs, true
		}
	}
	for _, c := range images {
		sig.Coverage.InUse++
		if c.SeenInto {
			sig.Coverage.SeenInto++
		}
		if c.Full {
			sig.Coverage.Full++
		}
	}
	sig.Privileged, sig.SaPower = intp(priv), intp(sa)
	if hasBest {
		fa := fixActionOf(best.Sample)
		sig.BestFix = &fa
	}
	return sig
}

// worst is the worst open priority of any of owners.
func (d *exposureData) worst(keys []string) model.Priority {
	w := model.PriorityNone
	for _, k := range keys {
		w = max(w, d.stats[k].Counts.Worst())
	}
	return w
}

// sortByRisk orders owners worst first: urgent, high and fixable findings, then name.
func (d *exposureData) sortByRisk(keys []string) {
	slices.SortFunc(keys, func(a, b string) int {
		sa, sb := d.stats[a], d.stats[b]
		return cmp.Or(cmp.Compare(sb.Counts.Urgent, sa.Counts.Urgent), cmp.Compare(sb.Counts.High, sa.Counts.High),
			cmp.Compare(sb.Fixable, sa.Fixable), strings.Compare(d.owners[a].Name, d.owners[b].Name), strings.Compare(a, b))
	})
}

func (d *exposureData) ref(key string) apigen.WorkloadRef {
	o := d.owners[key]
	return workloadRef(model.OwnerRef{Kind: o.Kind, Namespace: o.Namespace, Name: o.Name})
}

// xrow is an exposure row while the table is built: its distinct owners, or the node groups whose
// signals it carries, and its children.
type xrow struct {
	row      apigen.ExposureRow
	owners   []string
	groups   []string
	children []*xrow
	noun     string // what one child is, for the tail label: hostname, workload or node
}

// addOwner adds key to the row's distinct owners.
func (x *xrow) addOwner(key string) {
	if !slices.Contains(x.owners, key) {
		x.owners = append(x.owners, key)
	}
}

// exposureTable builds the rows of one table.
type exposureTable struct {
	s      *Server
	d      exposureData
	expand map[string]bool
	groups map[string]groupSignals // node group ID → its signals, every group's once loaded (loadGroups)
	rows   []apigen.ExposureRow
}

// groupSignals are a node group's signal columns and worst open priority.
type groupSignals struct {
	sig   apigen.RowSignals
	worst model.Priority
}

// GetExposure answers the home table: what can be reached from outside, grouped by entry point
// (default), namespace or node, with internal entry points and the workloads that are not exposed
// listed separately.
func (s *Server) GetExposure(ctx context.Context, req apigen.GetExposureRequestObject) (apigen.GetExposureResponseObject, error) {
	p := req.Params
	sc, err := scopeParam(p.Scope, model.ScopeCluster, model.ScopeNamespace)
	if err != nil {
		return nil, err
	}
	group, err := enumValue("group", p.Group)
	if err != nil {
		return nil, err
	}
	group = cmp.Or(group, apigen.ExposureGroupEntry)
	if group == apigen.ExposureGroupNode && sc.Kind != model.ScopeCluster {
		return nil, badParam("group", "node grouping needs the cluster scope")
	}
	title, err := s.scopeTitle(ctx, sc)
	if err != nil {
		return nil, err
	}
	t := &exposureTable{s: s, expand: map[string]bool{}, groups: map[string]groupSignals{}}
	for _, id := range stringsParam(p.Expand) {
		t.expand[strings.TrimSuffix(id, tailSuffix)] = true
	}
	switch group {
	case apigen.ExposureGroupNode:
		err = t.byNode(ctx)
	case apigen.ExposureGroupNamespace:
		err = t.byNamespace(ctx, sc)
	default:
		err = t.byEntry(ctx, sc)
	}
	if err != nil {
		return nil, err
	}
	maxUrgent := 0
	for _, r := range t.rows {
		maxUrgent = max(maxUrgent, r.Signals.Urgent)
	}
	cluster, at := s.stamp()
	return apigen.GetExposure200JSONResponse{Cluster: cluster, GeneratedAt: at, Scope: scopeRef(sc, title), Group: group,
		MaxUrgent: maxUrgent, Rows: nz(t.rows)}, nil
}

// load reads the owners of a scope and, in parallel, their stats, coverage and best fixes.
func (t *exposureTable) load(ctx context.Context, sc model.Scope) ([]store.OwnerEntity, error) {
	owners, err := t.s.o.Store.OwnerEntities(ctx, sc)
	if err != nil {
		return nil, err
	}
	t.d.owners = make(map[string]store.OwnerEntity, len(owners))
	keys := make([]string, len(owners))
	for i, o := range owners {
		t.d.owners[o.Key], keys[i] = o, o.Key
	}
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() (err error) { t.d.stats, err = t.s.o.Store.OwnerStatsOf(gctx, keys); return err })
	g.Go(func() (err error) { t.d.images, err = t.s.o.Store.OwnerImageCoverage(gctx, keys); return err })
	g.Go(func() (err error) { t.d.best, err = t.s.o.Store.BestFixes(gctx, keys); return err })
	return owners, g.Wait()
}

// entryGroupOf is the group a public edge belongs to: its id, label and whether its children are
// hostnames.
func entryGroupOf(e model.ExposureEdge) (id, label string, hostnames bool) {
	switch e.Entry {
	case model.EntryGateway:
		return "gw:" + e.EntryName, "Internet → Gateway " + e.EntryName, true
	case model.EntryIngress:
		if e.EntryName == "" {
			return "ing:", "Ingress (no class)", true
		}
		return "ing:" + e.EntryName, "Ingress class " + e.EntryName, true
	case model.EntryLoadBalancer:
		return "lb:" + e.EntryName, "LoadBalancer Service " + e.EntryName, false
	case model.EntryNodePort:
		return "np:" + e.EntryName, "NodePort Service " + e.EntryName, false
	case model.EntryExternalIP:
		return "eip:" + e.EntryName, "External IPs " + e.EntryName, false
	case model.EntryHostNetwork, model.EntryHostPort:
	}
	return rowHost, "Node network (hostNetwork / hostPort)", false
}

func hostLabel(h string) string { return cmp.Or(h, "*") }

func (t *exposureTable) byEntry(ctx context.Context, sc model.Scope) error {
	owners, err := t.load(ctx, sc)
	if err != nil {
		return err
	}
	edges, err := t.s.o.Store.ExposureEdges(ctx, sc)
	if err != nil {
		return err
	}
	var (
		public   []*xrow
		byID     = map[string]*xrow{}
		internal = &xrow{row: apigen.ExposureRow{Id: rowInternal, Kind: apigen.ExposureRowKindInternal, Label: "Internal entry points",
			Internal: true}, noun: "hostname"}
		childOf = func(parent *xrow, id string, mk func() *xrow) *xrow {
			i := slices.IndexFunc(parent.children, func(c *xrow) bool { return c.row.Id == id })
			if i >= 0 {
				return parent.children[i]
			}
			c := mk()
			parent.children = append(parent.children, c)
			return c
		}
	)
	for _, er := range edges {
		if _, ok := t.d.owners[er.OwnerKey]; !ok {
			continue
		}
		e := er.Edge
		entry := apigen.EntryKind(e.Entry)
		if e.Internal {
			id := rowInternal + "/" + string(e.Entry) + ":" + e.EntryName + "/" + hostLabel(e.Hostname)
			_, label, _ := entryGroupOf(e)
			c := childOf(internal, id, func() *xrow {
				return &xrow{row: apigen.ExposureRow{Id: id, Kind: apigen.ExposureRowKindHostname, Label: cmp.Or(e.Hostname, label),
					Entry: &entry, Internal: true}}
			})
			c.addOwner(er.OwnerKey)
			internal.addOwner(er.OwnerKey)
			continue
		}
		gid, label, hostnames := entryGroupOf(e)
		g := byID[gid]
		if g == nil {
			g = &xrow{row: apigen.ExposureRow{Id: gid, Kind: apigen.ExposureRowKindEntry, Label: label, Entry: &entry}, noun: "workload"}
			if hostnames {
				g.noun = "hostname"
			}
			byID[gid] = g
			public = append(public, g)
		}
		if gid == rowHost && e.Entry == model.EntryHostNetwork {
			g.row.Entry = &entry // the group reads as host network when any workload uses it
		}
		g.addOwner(er.OwnerKey)
		if hostnames {
			id := gid + "/" + hostLabel(e.Hostname)
			c := childOf(g, id, func() *xrow {
				return &xrow{row: apigen.ExposureRow{Id: id, Kind: apigen.ExposureRowKindHostname, Label: hostLabel(e.Hostname), Entry: &entry}}
			})
			c.addOwner(er.OwnerKey)
			continue
		}
		id := gid + "/" + er.OwnerKey
		c := childOf(g, id, func() *xrow { return t.workloadRow(id, er.OwnerKey) })
		if e.Entry == model.EntryHostNetwork {
			c.row.Entry = &entry
		} else if c.row.Entry == nil {
			c.row.Entry = &entry
		}
	}

	for _, g := range public {
		for _, c := range g.children {
			if c.row.Kind == apigen.ExposureRowKindHostname {
				t.hostnameRow(c)
			}
		}
		g.row.Signals = t.d.signals(g.owners)
		if g.noun == "hostname" {
			g.row.Hostnames = intp(len(g.children))
			if strings.HasPrefix(g.row.Id, "gw:") {
				g.row.Detail = optString(plural(len(g.children), "hostname") + " · public")
			}
		}
	}
	sortRows(public)
	for _, g := range public {
		t.emit(g, t.ownerTail)
	}
	if sc.Kind == model.ScopeCluster {
		if err := t.exposedNodes(ctx); err != nil {
			return err
		}
	}
	if len(internal.children) > 0 {
		for _, c := range internal.children {
			t.hostnameRow(c)
		}
		internal.row.Signals = t.d.signals(internal.owners)
		t.emit(internal, t.ownerTail)
	}

	notExposed := &xrow{row: apigen.ExposureRow{Id: rowNotExposed, Kind: apigen.ExposureRowKindNotexposed, Label: "Not exposed",
		Expandable: true}, noun: "workload"}
	for _, o := range owners {
		if !o.Exposed {
			notExposed.addOwner(o.Key)
			id := rowNotExposed + "/" + o.Key
			notExposed.children = append(notExposed.children, t.workloadRow(id, o.Key))
		}
	}
	if len(notExposed.owners) > 0 {
		notExposed.row.Signals = t.d.signals(notExposed.owners)
		notExposed.row.Collapsed = !t.expand[rowNotExposed]
		t.emit(notExposed, t.ownerTail)
	}
	return nil
}

// workloadRow is a child row for one owner: its name, namespace and scope.
func (t *exposureTable) workloadRow(id, key string) *xrow {
	o := t.d.owners[key]
	target := scopeRef(model.Scope{Kind: model.ScopeWorkload, Value: key}, o.Name)
	return &xrow{row: apigen.ExposureRow{Id: id, Kind: apigen.ExposureRowKindWorkload, Label: o.Name, Detail: optString(o.Namespace),
		Workloads: []apigen.WorkloadRef{t.d.ref(key)}, Signals: t.d.signals([]string{key}), Target: &target}, owners: []string{key}}
}

// hostnameRow fills a hostname row from its owners: the first two worst first, the namespace (or
// how many namespaces), the workload as the target when there is one, and the summed signals.
func (t *exposureTable) hostnameRow(c *xrow) {
	t.d.sortByRisk(c.owners)
	refs := make([]apigen.WorkloadRef, 0, min(len(c.owners), 2))
	namespaces := map[string]bool{}
	for i, k := range c.owners {
		if i < 2 {
			refs = append(refs, t.d.ref(k))
		}
		namespaces[t.d.owners[k].Namespace] = true
	}
	c.row.Workloads, c.row.MoreWorkloads = refs, max(len(c.owners)-2, 0)
	if len(namespaces) == 1 {
		c.row.Detail = optString(t.d.owners[c.owners[0]].Namespace)
	} else {
		c.row.Detail = optString(plural(len(namespaces), "namespace"))
	}
	if len(c.owners) == 1 {
		target := scopeRef(model.Scope{Kind: model.ScopeWorkload, Value: c.owners[0]}, t.d.owners[c.owners[0]].Name)
		c.row.Target = &target
	}
	c.row.Signals = t.d.signals(c.owners)
}

// exposedNodes adds the "Exposed nodes" group: every node an exposed-node selector matched, with
// its group's host findings.
func (t *exposureTable) exposedNodes(ctx context.Context) error {
	set, err := t.s.groupSet(ctx)
	if err != nil {
		return err
	}
	if err := t.loadGroups(ctx, set); err != nil {
		return err
	}
	nodes := &xrow{row: apigen.ExposureRow{Id: rowNodes, Kind: apigen.ExposureRowKindEntry, Label: "Exposed nodes"}, noun: "node"}
	for _, g := range set.groups {
		if len(g.ExposedNodes) == 0 {
			continue
		}
		gs := t.groups[g.ID]
		nodes.groups = append(nodes.groups, g.ID)
		for _, n := range g.ExposedNodes {
			nodes.children = append(nodes.children, t.nodeRow(rowNodes+"/"+n, n, g, gs))
		}
	}
	if len(nodes.children) == 0 {
		return nil
	}
	nodes.row.Signals, _ = t.sumGroups(nodes.groups)
	t.emit(nodes, t.nodeTail)
	return nil
}

// loadGroups reads, once, the signal columns of every node group in set: its host findings and
// coverage, with no privilege or service account columns. The counts and the coverage figures of all
// groups are each read in one pass (groupStatsOf, groupCoverage), not per group.
func (t *exposureTable) loadGroups(ctx context.Context, set *groupSet) error {
	if len(t.groups) > 0 || len(set.groups) == 0 {
		return nil
	}
	stats, err := t.s.groupStatsOf(ctx, set.groups)
	if err != nil {
		return err
	}
	covs, err := t.s.groupCoverage(ctx, set)
	if err != nil {
		return err
	}
	for i, g := range set.groups {
		st := stats[g.ID]
		t.groups[g.ID] = groupSignals{sig: apigen.RowSignals{Urgent: st.Counts.Urgent, High: st.Counts.High, Fixable: st.Fixable,
			Exploited: st.Exploited, Coverage: coverageFigure(covs[i])}, worst: st.Counts.Worst()}
	}
	return nil
}

// sumGroups sums the signals of node groups, and their worst open priority.
func (t *exposureTable) sumGroups(ids []string) (apigen.RowSignals, model.Priority) {
	var (
		sig   apigen.RowSignals
		worst = model.PriorityNone
	)
	for _, id := range ids {
		gs := t.groups[id]
		sig.Urgent += gs.sig.Urgent
		sig.High += gs.sig.High
		sig.Fixable += gs.sig.Fixable
		sig.Exploited += gs.sig.Exploited
		sig.Coverage.InUse += gs.sig.Coverage.InUse
		sig.Coverage.SeenInto += gs.sig.Coverage.SeenInto
		sig.Coverage.Full += gs.sig.Coverage.Full
		worst = max(worst, gs.worst)
	}
	return sig, worst
}

// nodeRow is a child row for one node, carrying its group's signals.
func (t *exposureTable) nodeRow(id, node string, g model.NodeGroup, gs groupSignals) *xrow {
	target := scopeRef(model.Scope{Kind: model.ScopeNode, Value: node}, node)
	return &xrow{row: apigen.ExposureRow{Id: id, Kind: apigen.ExposureRowKindNode, Label: node, Detail: optString(g.Label),
		Signals: gs.sig, Target: &target}, groups: []string{g.ID}}
}

func (t *exposureTable) byNamespace(ctx context.Context, sc model.Scope) error {
	owners, err := t.load(ctx, sc)
	if err != nil {
		return err
	}
	stats, err := t.s.o.Store.NamespaceStats(ctx)
	if err != nil {
		return err
	}
	var groups []*xrow
	for _, n := range stats {
		if sc.Kind == model.ScopeNamespace && n.Namespace != sc.Value {
			continue
		}
		id := "ns:" + n.Namespace
		target := scopeRef(model.Scope{Kind: model.ScopeNamespace, Value: n.Namespace}, n.Namespace)
		g := &xrow{row: apigen.ExposureRow{Id: id, Kind: apigen.ExposureRowKindNamespace, Label: n.Namespace, Target: &target},
			noun: "workload"}
		for _, o := range owners {
			if o.Namespace == n.Namespace {
				g.addOwner(o.Key)
				g.children = append(g.children, t.workloadRow(id+"/"+o.Key, o.Key))
			}
		}
		g.row.Signals = t.d.signals(g.owners)
		groups = append(groups, g)
	}
	sortRows(groups)
	for _, g := range groups {
		t.emit(g, t.ownerTail)
	}
	return nil
}

func (t *exposureTable) byNode(ctx context.Context) error {
	s := t.s
	cp := model.Scope{Kind: model.ScopeControlPlane}
	stats, err := s.o.Store.ScopeStats(ctx, cp)
	if err != nil {
		return err
	}
	cov, err := s.scopeCoverage(ctx, cp)
	if err != nil {
		return err
	}
	keys, err := s.controlPlaneKeys(ctx)
	if err != nil {
		return err
	}
	best, err := s.o.Store.BestFixes(ctx, keys)
	if err != nil {
		return err
	}
	t.d.best = best
	target := scopeRef(cp, controlPlaneLabel)
	sig := apigen.RowSignals{Urgent: stats.Counts.Urgent, High: stats.Counts.High, Fixable: stats.Fixable, Exploited: stats.Exploited,
		Coverage: coverageFigure(cov), BestFix: t.d.signals(keys).BestFix}
	t.rows = append(t.rows, apigen.ExposureRow{Id: rowControlPlane, Kind: apigen.ExposureRowKindControlplane, Label: controlPlaneLabel,
		Workloads: []apigen.WorkloadRef{}, Signals: sig, Target: &target})

	set, err := s.groupSet(ctx)
	if err != nil {
		return err
	}
	if err := t.loadGroups(ctx, set); err != nil {
		return err
	}
	groups := set.groups
	var rows []*xrow
	for _, g := range groups {
		gs := t.groups[g.ID]
		id := "ng:" + set.key(g)
		target := scopeRef(set.scope(g), g.Label)
		x := &xrow{row: apigen.ExposureRow{Id: id, Kind: apigen.ExposureRowKindNodegroup, Label: g.Label, Signals: gs.sig,
			Target: &target}, groups: []string{g.ID}, noun: "node"}
		for _, n := range g.Members {
			x.children = append(x.children, t.nodeRow(id+"/"+n, n, g, gs))
		}
		rows = append(rows, x)
	}
	// Agent groups first, then nodeinfo groups, each worst first.
	slices.SortStableFunc(rows, func(a, b *xrow) int {
		return cmp.Or(cmp.Compare(groupKindRankOf(groups, a.groups[0]), groupKindRankOf(groups, b.groups[0])), compareRows(a, b))
	})
	for _, x := range rows {
		t.emit(x, t.nodeTail)
	}
	return nil
}

func groupKindRankOf(groups []model.NodeGroup, id string) int {
	i := slices.IndexFunc(groups, func(g model.NodeGroup) bool { return g.ID == id })
	return groupKindRank(groups[i].Kind)
}

// compareRows orders rows worst first: urgent, high and fixable findings, then label.
func compareRows(a, b *xrow) int {
	sa, sb := a.row.Signals, b.row.Signals
	return cmp.Or(cmp.Compare(sb.Urgent, sa.Urgent), cmp.Compare(sb.High, sa.High), cmp.Compare(sb.Fixable, sa.Fixable),
		strings.Compare(a.row.Label, b.row.Label))
}

func sortRows(rows []*xrow) { slices.SortStableFunc(rows, compareRows) }

// ownerTail sums folded owner rows: the signals of their distinct owners and their worst priority.
func (t *exposureTable) ownerTail(folded []*xrow) (apigen.RowSignals, model.Priority) {
	var keys []string
	for _, c := range folded {
		for _, k := range c.owners {
			if !slices.Contains(keys, k) {
				keys = append(keys, k)
			}
		}
	}
	return t.d.signals(keys), t.d.worst(keys)
}

// nodeTail sums folded node rows: the signals of their distinct groups.
func (t *exposureTable) nodeTail(folded []*xrow) (apigen.RowSignals, model.Priority) {
	var ids []string
	for _, c := range folded {
		for _, id := range c.groups {
			if !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
		}
	}
	return t.sumGroups(ids)
}

// emit appends a group row and its children, worst first. Unless the group is expanded, it keeps
// the first exposureFold children and every child with urgent findings, and folds the rest into
// one tail row. A collapsed group shows no children.
func (t *exposureTable) emit(g *xrow, tail func([]*xrow) (apigen.RowSignals, model.Priority)) {
	sortRows(g.children)
	shown, folded := g.children, []*xrow(nil)
	if !t.expand[g.row.Id] && len(g.children) > exposureFold {
		shown = nil
		for i, c := range g.children {
			if i < exposureFold || c.row.Signals.Urgent > 0 {
				shown = append(shown, c)
			} else {
				folded = append(folded, c)
			}
		}
	}
	g.row.Expandable = g.row.Expandable || len(folded) > 0 || (t.expand[g.row.Id] && len(g.children) > exposureFold)
	g.row.Workloads = nz(g.row.Workloads)
	t.rows = append(t.rows, g.row)
	if g.row.Collapsed {
		return
	}
	for _, c := range shown {
		c.row.Parent, c.row.Depth = &g.row.Id, apigen.ExposureRowDepthN1
		c.row.Workloads = nz(c.row.Workloads)
		t.rows = append(t.rows, c.row)
	}
	if len(folded) == 0 {
		return
	}
	sig, worst := tail(folded)
	above := model.PriorityLow
	if worst > model.PriorityLow {
		above = worst
	}
	t.rows = append(t.rows, apigen.ExposureRow{Id: g.row.Id + tailSuffix, Parent: &g.row.Id, Depth: apigen.ExposureRowDepthN1,
		Kind: apigen.ExposureRowKindTail, Label: strings.Replace(plural(len(folded), g.noun), " ", " more ", 1),
		Detail: optString("nothing above " + above.String()), Workloads: []apigen.WorkloadRef{}, Signals: sig, Expandable: true})
}
