package apiserver

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/the-it-dept/ffs/internal/inventory"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/nodegroup"
	"github.com/the-it-dept/ffs/internal/store"
	"github.com/the-it-dept/ffs/internal/web/apigen"
)

const (
	// relatedMax is how many items a rail section lists; the rest are counted in more.
	relatedMax = 8
	// historyWindow is how far back the rail's History count reaches.
	historyWindow = 30 * 24 * time.Hour

	controlPlaneLabel = "Control plane"
)

// scopeTitle names a scope as the rail and the page header show it: the cluster name, a namespace,
// a workload's name, an image's repository (its digest when it has none), a node group's label, a
// node's name, or "Control plane".
func (s *Server) scopeTitle(ctx context.Context, sc model.Scope) (string, error) {
	switch sc.Kind {
	case model.ScopeCluster:
		return s.o.Config.ClusterName, nil
	case model.ScopeWorkload:
		return ownerOfKey(sc.Value).Name, nil
	case model.ScopeImage:
		img, _, _, err := s.imageOf(ctx, sc.Value)
		if err != nil {
			return "", err
		}
		return cmp.Or(img.Repo, img.Digest), nil
	case model.ScopeNodeGroup:
		g, ok, err := s.findGroup(ctx, sc.Value)
		if err != nil || !ok {
			return sc.Value, err
		}
		return g.Label, nil
	case model.ScopeControlPlane:
		return controlPlaneLabel, nil
	case model.ScopeNamespace, model.ScopeNode:
	}
	return sc.Value, nil
}

// rail builds one scope card.
type rail struct {
	s     *Server
	sc    model.Scope
	card  apigen.GetScope200JSONResponse
	cov   store.CoverageFigure
	feeds apigen.FeedFreshness
}

// GetScope is the contextual rail of a scope: its title and one-line summary, breadcrumbs, the
// views it offers with their counts, related objects, and how far the counts can be trusted. from
// is the workload an image was opened from, its breadcrumb parent.
func (s *Server) GetScope(ctx context.Context, req apigen.GetScopeRequestObject) (apigen.GetScopeResponseObject, error) {
	sc, err := scopeParam(req.Params.Scope)
	if err != nil {
		return nil, err
	}
	var from *model.Scope
	if req.Params.From != nil && *req.Params.From != "" {
		f, err := scopeParam(req.Params.From, model.ScopeWorkload)
		if err != nil {
			return nil, err
		}
		from = &f
	}
	if _, err := s.resolveScope(ctx, sc); err != nil {
		return nil, err
	}
	title, err := s.scopeTitle(ctx, sc)
	if err != nil {
		return nil, err
	}
	r := &rail{s: s, sc: sc}
	if r.cov, err = s.scopeCoverage(ctx, sc); err != nil {
		return nil, err
	}
	if r.feeds, err = s.freshness(ctx); err != nil {
		return nil, err
	}
	cluster, at := s.stamp()
	r.card = apigen.GetScope200JSONResponse{
		Cluster: cluster, GeneratedAt: at, Scope: scopeRef(sc, title), Clusters: []string{s.o.Config.ClusterName}, Title: title,
		Breadcrumbs: []apigen.ScopeRef{}, Views: []apigen.ViewCount{}, Related: []apigen.RelatedSection{},
		Trust: apigen.Trust{Feeds: r.feeds, Coverage: coverageFigure(r.cov), Settings: sc.Kind == model.ScopeCluster},
	}
	if sc.Kind != model.ScopeCluster {
		r.card.Breadcrumbs = append(r.card.Breadcrumbs, scopeRef(model.Scope{Kind: model.ScopeCluster}, s.o.Config.ClusterName))
	}
	switch sc.Kind {
	case model.ScopeCluster:
		err = r.cluster(ctx)
	case model.ScopeNamespace:
		err = r.namespace(ctx)
	case model.ScopeWorkload:
		err = r.workload(ctx)
	case model.ScopeImage:
		err = r.image(ctx, from)
	case model.ScopeNodeGroup:
		err = r.nodeGroup(ctx)
	case model.ScopeNode:
		err = r.node(ctx)
	case model.ScopeControlPlane:
		err = r.controlPlane(ctx)
	}
	if err != nil {
		return nil, err
	}
	return r.card, nil
}

// covGap reports whether ffs does not see into every image of the scope in full detail.
func (r *rail) covGap() bool { return r.cov.Full < r.cov.InUse }

func (r *rail) view(id apigen.ViewId, count *int, gap bool) {
	r.card.Views = append(r.card.Views, apigen.ViewCount{Id: id, Count: count, Gap: gap})
}

func (r *rail) related(id apigen.RelatedSectionId, items []relItem) {
	r.card.Related = append(r.card.Related, relatedSection(id, items))
}

func intp(n int) *int { return &n }

func (r *rail) cluster(ctx context.Context) error {
	s, sc := r.s, r.sc
	var (
		ci                       model.ClusterInfo
		nodes                    []model.Node
		nss                      []store.NamespaceStat
		stats                    store.OwnerStats
		reach, wl, im, pk, ngaps int
		agents                   *agentView
	)
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() (err error) { ci, _, err = s.o.Store.GetClusterInfo(gctx); return err })
	g.Go(func() (err error) { nodes, err = s.o.Store.ListNodes(gctx); return err })
	g.Go(func() (err error) { nss, err = s.o.Store.NamespaceStats(gctx); return err })
	g.Go(func() (err error) { stats, err = s.o.Store.ScopeStats(gctx, sc); return err })
	g.Go(func() (err error) { reach, _, err = s.reachable(gctx, sc); return err })
	g.Go(func() error {
		p, err := s.o.Store.WorkloadsPage(gctx, store.WorkloadQuery{Scope: sc, Limit: 1})
		wl = p.Total
		return err
	})
	g.Go(func() error {
		p, err := s.o.Store.ImagesPage(gctx, store.ImageQuery{Scope: sc, Limit: 1})
		im = p.Total
		return err
	})
	g.Go(func() error {
		p, err := s.o.Store.PackagesPage(gctx, store.PackageEntityQuery{Scope: sc, Limit: 1})
		pk = p.Total
		return err
	})
	g.Go(func() error {
		gaps, err := s.scopeGaps(gctx, sc)
		ngaps = len(gaps)
		return err
	})
	g.Go(func() (err error) { agents, err = s.agentView(gctx); return err })
	if err := g.Wait(); err != nil {
		return err
	}
	var parts []string
	if ci.Version != "" {
		parts = append(parts, "Kubernetes "+ci.Version)
	}
	r.card.Summary = strings.Join(append(parts, plural(len(nodes), "node"), plural(len(nss), "namespace")), " · ")

	nodesGap := false
	for _, n := range nodes {
		nodesGap = nodesGap || len(agents.of(n.Name).Coverage) > 0
	}
	r.view(apigen.ViewIdExposure, intp(reach), false)
	r.view(apigen.ViewIdVulnerabilities, intp(stats.Open), r.covGap())
	r.view(apigen.ViewIdWorkloads, intp(wl), false)
	r.view(apigen.ViewIdImages, intp(im), r.covGap())
	r.view(apigen.ViewIdPackages, intp(pk), r.covGap())
	r.view(apigen.ViewIdNodes, intp(len(nodes)), nodesGap)
	r.view(apigen.ViewIdCoverage, intp(ngaps), ngaps > 0)

	items := make([]relItem, 0, len(nss))
	for _, n := range nss {
		items = append(items, countsItem(model.Scope{Kind: model.ScopeNamespace, Value: n.Namespace}, "namespace", n.Namespace,
			plural(n.Workloads, "workload"), n.Stats, n.Coverage.Full < n.Coverage.InUse))
	}
	r.related(apigen.RelatedSectionIdNamespaces, items)

	gs, err := s.groupSet(ctx)
	if err != nil {
		return err
	}
	items = make([]relItem, 0, len(gs.groups))
	for _, g := range gs.groups {
		st, err := s.groupStats(ctx, g)
		if err != nil {
			return err
		}
		gap := g.Kind != model.NodeGroupAgent
		for _, m := range g.Members {
			gap = gap || hostGap(agents.of(m))
		}
		items = append(items, countsItem(gs.scope(g), "nodegroup", g.Label, plural(len(g.Members), "node"), st, gap))
	}
	r.related(apigen.RelatedSectionIdNodegroups, items)

	cp := model.Scope{Kind: model.ScopeControlPlane}
	cpStats, err := s.o.Store.ScopeStats(ctx, cp)
	if err != nil {
		return err
	}
	cpCov, err := s.scopeCoverage(ctx, cp)
	if err != nil {
		return err
	}
	r.related(apigen.RelatedSectionIdControlplane, []relItem{countsItem(cp, "controlplane", controlPlaneLabel, "", cpStats,
		cpCov.Full < cpCov.InUse)})
	return nil
}

func (r *rail) namespace(ctx context.Context) error {
	s, sc := r.s, r.sc
	var (
		nss           []store.NamespaceStat
		stats         store.OwnerStats
		reach, im, pk int
		owners        []store.OwnerEntity
	)
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() (err error) { nss, err = s.o.Store.NamespaceStats(gctx); return err })
	g.Go(func() (err error) { stats, err = s.o.Store.ScopeStats(gctx, sc); return err })
	g.Go(func() (err error) { reach, _, err = s.reachable(gctx, sc); return err })
	g.Go(func() error {
		p, err := s.o.Store.ImagesPage(gctx, store.ImageQuery{Scope: sc, Limit: 1})
		im = p.Total
		return err
	})
	g.Go(func() error {
		p, err := s.o.Store.PackagesPage(gctx, store.PackageEntityQuery{Scope: sc, Limit: 1})
		pk = p.Total
		return err
	})
	g.Go(func() (err error) { owners, err = s.o.Store.OwnerEntities(gctx, sc); return err })
	if err := g.Wait(); err != nil {
		return err
	}
	var ns store.NamespaceStat
	if i := slices.IndexFunc(nss, func(n store.NamespaceStat) bool { return n.Namespace == sc.Value }); i >= 0 {
		ns = nss[i]
	}
	r.card.Summary = strings.Join([]string{plural(ns.Workloads, "workload"), fmt.Sprintf("%d urgent", ns.Stats.Counts.Urgent),
		fmt.Sprintf("%d exposed", ns.Exposed)}, " · ")
	r.view(apigen.ViewIdExposure, intp(reach), false)
	r.view(apigen.ViewIdVulnerabilities, intp(stats.Open), r.covGap())
	r.view(apigen.ViewIdImages, intp(im), r.covGap())
	r.view(apigen.ViewIdPackages, intp(pk), r.covGap())
	items, err := s.workloadItems(ctx, owners, "")
	if err != nil {
		return err
	}
	r.related(apigen.RelatedSectionIdWorkloads, items)
	return nil
}

// workloadItems are rail items for owners, except skip: worst and open counts from owner_stats,
// a gap when ffs does not see into all their images in full detail.
func (s *Server) workloadItems(ctx context.Context, owners []store.OwnerEntity, skip string) ([]relItem, error) {
	keys := make([]string, 0, len(owners))
	for _, o := range owners {
		keys = append(keys, o.Key)
	}
	stats, err := s.o.Store.OwnerStatsOf(ctx, keys)
	if err != nil {
		return nil, err
	}
	cov, err := s.o.Store.OwnerCoverage(ctx, keys)
	if err != nil {
		return nil, err
	}
	items := make([]relItem, 0, len(owners))
	for _, o := range owners {
		if o.Key == skip {
			continue
		}
		c := cov[o.Key]
		items = append(items, countsItem(model.Scope{Kind: model.ScopeWorkload, Value: o.Key}, o.Kind, o.Name, o.Namespace,
			stats[o.Key], c.SeenInto == 0 || c.Full < c.InUse))
	}
	return items, nil
}

func (r *rail) workload(ctx context.Context) error {
	s, sc := r.s, r.sc
	o, ok, err := s.o.Store.GetOwner(ctx, sc.Value)
	if err != nil {
		return err
	}
	if !ok {
		return notFound("workload " + sc.Value + " not found")
	}
	var parts []string
	if pods := podsOf(s.pods(), sc.Value); pods != nil {
		parts = append(parts, plural(*pods, "replica"))
	}
	if m := managedText(o.ManagedBy); m != "" {
		parts = append(parts, m)
	}
	if o.Context.Exposed {
		parts = append(parts, "exposed")
	} else {
		parts = append(parts, "not exposed")
	}
	r.card.Summary = strings.Join(append(parts, "SA "+cmp.Or(o.ServiceAccount, "default")), " · ")
	if ns := o.Ref.Namespace; ns != "" {
		r.card.Breadcrumbs = append(r.card.Breadcrumbs, scopeRef(model.Scope{Kind: model.ScopeNamespace, Value: ns}, ns))
	}

	stats, err := s.o.Store.ScopeStats(ctx, sc)
	if err != nil {
		return err
	}
	upgrades, err := s.suggestions(ctx, func(owner string, _ model.Suggestion) bool { return owner == sc.Value })
	if err != nil {
		return err
	}
	history, err := s.o.Store.TransitionCount(ctx, sc, s.o.Now().Add(-historyWindow))
	if err != nil {
		return err
	}
	public := 0
	for _, e := range o.Context.Exposure {
		if !e.Internal {
			public++
		}
	}
	r.view(apigen.ViewIdFindings, intp(stats.Open), r.covGap())
	r.view(apigen.ViewIdUpgrades, intp(len(upgrades)), false)
	r.view(apigen.ViewIdExposure, intp(public), false)
	r.view(apigen.ViewIdRbac, nil, false)
	r.view(apigen.ViewIdHistory, intp(history), false)

	// Each container counts this workload's own findings on its image, not every workload's.
	byDigest, err := s.o.Store.OwnerDigestStats(ctx, sc.Value)
	if err != nil {
		return err
	}
	items := make([]relItem, 0, len(o.Containers))
	for _, c := range o.Containers {
		it := relItem{RelatedItem: apigen.RelatedItem{Kind: "container", Label: c.Name, Detail: optString(c.Repo),
			Worst: apigen.PriorityNone, Gap: true}}
		if c.Digest != "" {
			img, hasRow, err := s.imageRow(ctx, c.Digest)
			if err != nil {
				return err
			}
			it = countsItem(model.Scope{Kind: model.ScopeImage, Value: c.Digest}, "container", c.Name, c.Repo, byDigest[c.Digest],
				!hasRow || store.CoverageClassOf(img) != model.CoverageFull)
		}
		items = append(items, it)
	}
	r.related(apigen.RelatedSectionIdContainers, items)

	var siblings []store.OwnerEntity
	if ns := o.Ref.Namespace; ns != "" {
		if siblings, err = s.o.Store.OwnerEntities(ctx, model.Scope{Kind: model.ScopeNamespace, Value: ns}); err != nil {
			return err
		}
	}
	sib, err := s.workloadItems(ctx, siblings, sc.Value)
	if err != nil {
		return err
	}
	r.related(apigen.RelatedSectionIdSiblings, sib)
	return nil
}

func (r *rail) image(ctx context.Context, from *model.Scope) error {
	s, sc := r.s, r.sc
	img, hasRow, owners, err := s.imageOf(ctx, sc.Value)
	if err != nil {
		return err
	}
	parts := []string{cmp.Or(img.Repo, img.Digest), shortDigest(img.Digest)}
	if _, arch, ok := strings.Cut(img.Platform, "/"); ok && arch != "" {
		parts = append(parts, arch)
	}
	r.card.Summary = strings.Join(parts, " · ")
	if from != nil {
		ref := ownerOfKey(from.Value)
		if ref.Namespace != "" {
			r.card.Breadcrumbs = append(r.card.Breadcrumbs, scopeRef(model.Scope{Kind: model.ScopeNamespace, Value: ref.Namespace}, ref.Namespace))
		}
		r.card.Breadcrumbs = append(r.card.Breadcrumbs, scopeRef(*from, ref.Name))
	}
	full := hasRow && store.CoverageClassOf(img) == model.CoverageFull
	stats, err := s.o.Store.ScopeStats(ctx, sc)
	if err != nil {
		return err
	}
	pkgs, err := s.o.Store.ImagePackages(ctx, sc.Value, "", nil, "", 1)
	if err != nil {
		return err
	}
	upgrades, err := s.suggestions(ctx, func(owner string, sg model.Suggestion) bool {
		return sg.Repo == img.Repo && slices.Contains(owners, owner)
	})
	if err != nil {
		return err
	}
	r.view(apigen.ViewIdFindings, intp(stats.Open), !full)
	r.view(apigen.ViewIdPackages, intp(pkgs.Total), false)
	r.view(apigen.ViewIdUpgrades, intp(len(upgrades)), false)
	r.view(apigen.ViewIdSbom, nil, !full)

	entities := make([]store.OwnerEntity, 0, len(owners))
	for _, k := range owners {
		e, ok, err := s.o.Store.OwnerEntityOf(ctx, k)
		if err != nil {
			return err
		}
		if ok {
			entities = append(entities, e)
		}
	}
	usedBy, err := s.workloadItems(ctx, entities, "")
	if err != nil {
		return err
	}
	r.related(apigen.RelatedSectionIdUsedBy, usedBy)
	notable, err := s.notablePackages(ctx, sc.Value)
	if err != nil {
		return err
	}
	items := make([]relItem, 0, len(notable))
	for _, p := range notable {
		items = append(items, relItem{RelatedItem: apigen.RelatedItem{Kind: "package", Label: p.Name, Detail: optString(p.Version),
			Worst: p.Worst, Count: intp(p.Findings)}})
	}
	r.card.Related = append(r.card.Related, apigen.RelatedSection{Id: apigen.RelatedSectionIdNotablePackages, Items: itemsOf(items),
		More: 0}) // already the notable few, in their own order

	r.card.Trust.SbomSource = optString(img.Source)
	if name, version, ok, err := s.o.Store.SBOMDescriptor(ctx, sc.Value); err != nil {
		return err
	} else if ok {
		r.card.Trust.SbomTool = optString(strings.TrimSpace(name + " " + version))
	}
	if hasRow {
		r.card.Trust.Unattributed = intp(img.Coverage.UnattributedELF)
	}
	return nil
}

func (r *rail) nodeGroup(ctx context.Context) error {
	s := r.s
	g, ok, err := s.findGroup(ctx, r.sc.Value)
	if err != nil {
		return err
	}
	if !ok {
		return notFound("node group " + r.sc.Value + " not found")
	}
	r.card.Summary = groupSummary(g)
	agents, err := s.agentView(ctx)
	if err != nil {
		return err
	}
	st, err := s.groupStats(ctx, g)
	if err != nil {
		return err
	}
	membersGap := false
	for _, m := range g.Members {
		membersGap = membersGap || hostGap(agents.of(m))
	}
	agent := g.Kind == model.NodeGroupAgent
	r.view(apigen.ViewIdFindings, intp(st.Open), r.covGap())
	if agent {
		pkgs, err := s.o.Store.ImagePackages(ctx, g.Digest, "", nil, "", 1)
		if err != nil {
			return err
		}
		imgs, err := s.o.Store.NodeGroupImages(ctx, g.ID)
		if err != nil {
			return err
		}
		r.view(apigen.ViewIdHostPackages, intp(pkgs.Total), membersGap)
		r.view(apigen.ViewIdKernel, nil, membersGap)
		r.view(apigen.ViewIdCachedImages, intp(len(liveImages(imgs, agents.byNode))), false)
	} else {
		r.view(apigen.ViewIdHostPackages, nil, true)
		r.view(apigen.ViewIdKernel, nil, true)
		r.view(apigen.ViewIdCachedImages, nil, true)
	}
	r.view(apigen.ViewIdMembers, intp(len(g.Members)), membersGap)
	r.related(apigen.RelatedSectionIdMembers, memberItems(g, "", agents, st))
	return nil
}

func (r *rail) node(ctx context.Context) error {
	s, name := r.s, r.sc.Value
	nodes, err := s.o.Store.ListNodes(ctx)
	if err != nil {
		return err
	}
	i := slices.IndexFunc(nodes, func(n model.Node) bool { return n.Name == name })
	if i < 0 {
		return notFound("node " + name + " not found")
	}
	gs, err := s.groupSet(ctx)
	if err != nil {
		return err
	}
	g, _ := gs.of(name)
	agents, err := s.agentView(ctx)
	if err != nil {
		return err
	}
	agent := agents.of(name)
	ready := "Not ready"
	if nodes[i].Ready {
		ready = "Ready"
	}
	r.card.Summary = strings.Join([]string{g.Label, ready, "agent " + string(agent.State)}, " · ")
	r.card.Breadcrumbs = append(r.card.Breadcrumbs, scopeRef(gs.scope(g), g.Label))
	st, err := s.groupStats(ctx, g)
	if err != nil {
		return err
	}
	r.view(apigen.ViewIdFindings, intp(st.Open), r.covGap())
	cached := 0
	if liveAgent(agent.State) {
		imgs, err := s.o.Store.NodeImages(ctx, name)
		if err != nil {
			return err
		}
		cached = len(imgs)
	}
	r.view(apigen.ViewIdCachedImages, intp(cached), !liveAgent(agent.State))
	r.related(apigen.RelatedSectionIdMembers, memberItems(g, name, agents, st))
	return nil
}

func (r *rail) controlPlane(ctx context.Context) error {
	s, sc := r.s, r.sc
	ci, _, err := s.o.Store.GetClusterInfo(ctx)
	if err != nil {
		return err
	}
	cp, err := s.controlPlane(ctx)
	if err != nil {
		return err
	}
	var parts, runtimes []string
	if ci.Version != "" {
		parts = append(parts, "Kubernetes "+ci.Version)
	}
	for _, rt := range cp.Runtimes {
		runtimes = append(runtimes, rt.Name+" "+rt.Version)
	}
	if len(runtimes) > 0 {
		parts = append(parts, strings.Join(runtimes, ", "))
	}
	r.card.Summary = strings.Join(parts, " · ")
	stats, err := s.o.Store.ScopeStats(ctx, sc)
	if err != nil {
		return err
	}
	r.view(apigen.ViewIdFindings, intp(stats.Open), r.covGap())
	r.view(apigen.ViewIdUpgrades, intp(len(cp.Suggestions)), false)
	return nil
}

// groupSummary is a node group's rail line: members, short kernel and runtime.
func groupSummary(g model.NodeGroup) string {
	parts := []string{plural(len(g.Members), "node")}
	if g.KernelRelease != "" {
		parts = append(parts, "kernel "+nodegroup.ShortKernel(g.KernelRelease))
	}
	if name, version, ok := inventory.ParseRuntimeVersion(g.ContainerRuntimeVersion); ok {
		parts = append(parts, name+" "+version)
	} else if g.ContainerRuntimeVersion != "" {
		parts = append(parts, g.ContainerRuntimeVersion)
	}
	return strings.Join(parts, " · ")
}

// memberItems are rail items for a group's members other than skip: each node's agent state, its
// group's worst priority, no count, and a gap while ffs does not see its host packages in full
// (hostGap: its agent is not reporting, blocked or without a package database, or its host
// inventory is not stored).
func memberItems(g model.NodeGroup, skip string, agents *agentView, st store.OwnerStats) []relItem {
	items := make([]relItem, 0, len(g.Members))
	for _, m := range g.Members {
		if m == skip {
			continue
		}
		a := agents.of(m)
		items = append(items, relItem{RelatedItem: apigen.RelatedItem{
			Scope: optString(model.Scope{Kind: model.ScopeNode, Value: m}.String()), Kind: "node", Label: m,
			Detail: optString("agent " + string(a.State)), Worst: priorityOf(st.Counts.Worst()), Gap: hostGap(a),
		}, urgent: st.Counts.Urgent, high: st.Counts.High})
	}
	return items
}

// relItem is a rail item with the counts it is ordered by.
type relItem struct {
	apigen.RelatedItem
	urgent, high int
}

// countsItem is a rail item for a scope with open findings stats.
func countsItem(sc model.Scope, kind, label, detail string, st store.OwnerStats, gap bool) relItem {
	return relItem{RelatedItem: apigen.RelatedItem{Scope: optString(sc.String()), Kind: kind, Label: label, Detail: optString(detail),
		Worst: priorityOf(st.Counts.Worst()), Count: intp(st.Open), Gap: gap}, urgent: st.Counts.Urgent, high: st.Counts.High}
}

// relatedSection orders items worst first (urgent, then high, then count, then label) and keeps
// the first relatedMax, counting the rest in More.
func relatedSection(id apigen.RelatedSectionId, items []relItem) apigen.RelatedSection {
	count := func(it relItem) int {
		if it.Count == nil {
			return 0
		}
		return *it.Count
	}
	slices.SortStableFunc(items, func(a, b relItem) int {
		return cmp.Or(cmp.Compare(b.urgent, a.urgent), cmp.Compare(b.high, a.high), cmp.Compare(count(b), count(a)),
			strings.Compare(a.Label, b.Label))
	})
	more := max(len(items)-relatedMax, 0)
	return apigen.RelatedSection{Id: id, Items: itemsOf(items[:len(items)-more]), More: more}
}

func itemsOf(items []relItem) []apigen.RelatedItem {
	out := make([]apigen.RelatedItem, len(items))
	for i, it := range items {
		out[i] = it.RelatedItem
	}
	return out
}

// managedText names the tool that manages an owner, as the rail shows it; "" when unknown.
func managedText(m *model.ManagedBy) string {
	if m == nil {
		return ""
	}
	switch {
	case m.Tool == "helm":
		return "Helm " + m.Name
	case strings.HasPrefix(m.Tool, "flux-"):
		return "Flux " + m.Name
	case m.Tool == "argocd":
		return "Argo CD " + m.Name
	}
	return ""
}

// shortDigest is the first 12 hex characters of a sha256 digest; other image IDs are whole.
func shortDigest(digest string) string {
	if hex, ok := strings.CutPrefix(digest, "sha256:"); ok {
		return hex[:min(len(hex), 12)]
	}
	return digest
}

// plural is "1 node" or "n nodes".
func plural(n int, one string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %ss", n, one)
}
