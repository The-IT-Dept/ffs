package apiserver

import (
	"context"
	"slices"
	"strings"

	"github.com/the-it-dept/ffs/internal/inventory"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
	"github.com/the-it-dept/ffs/internal/web/apigen"
)

// scopeCoverage is how far ffs sees into a scope: its in-use container images for a cluster,
// namespace or workload scope, and the image itself for an image scope. A node group is one host
// image, seen into when it is an agent group whose host SBOM is catalogued and matched, and in full
// detail only while none of its members has a host coverage gap (hostGap: an agent blocked, stale or
// missing, no package database, a host inventory not stored). A node is its group's host image,
// in full detail while the node itself has no such gap. The control plane is its Kubernetes and
// runtime images, in full detail when they carry no coverage note.
func (s *Server) scopeCoverage(ctx context.Context, sc model.Scope) (store.CoverageFigure, error) {
	switch sc.Kind {
	case model.ScopeNodeGroup, model.ScopeNode:
		gs, err := s.groupSet(ctx)
		if err != nil {
			return store.CoverageFigure{}, err
		}
		var (
			g       model.NodeGroup
			ok      bool
			members []string
		)
		if sc.Kind == model.ScopeNode {
			g, ok = gs.of(sc.Value)
			members = []string{sc.Value}
		} else {
			g, ok = gs.find(sc.Value)
			members = g.Members
		}
		if !ok || !hasHostImage(g) {
			return hostCoverage(false, nil, nil), nil
		}
		img, found, err := s.imageRow(ctx, g.Digest)
		if err != nil {
			return store.CoverageFigure{}, err
		}
		if !found || img.Status != model.ImageCatalogued {
			return hostCoverage(false, nil, nil), nil
		}
		agents, err := s.agentView(ctx)
		if err != nil {
			return store.CoverageFigure{}, err
		}
		return hostCoverage(true, members, agents), nil
	case model.ScopeControlPlane:
		digests, err := s.controlPlaneDigests(ctx)
		if err != nil {
			return store.CoverageFigure{}, err
		}
		var c store.CoverageFigure
		for _, d := range digests {
			c.InUse++
			img, ok, err := s.imageRow(ctx, d)
			if err != nil {
				return store.CoverageFigure{}, err
			}
			if ok && img.Status == model.ImageCatalogued {
				c.SeenInto++
				if len(img.Coverage.Notes) == 0 {
					c.Full++
				}
			}
		}
		return c, nil
	case model.ScopeCluster, model.ScopeNamespace, model.ScopeWorkload, model.ScopeImage:
	}
	return s.o.Store.CoverageOf(ctx, sc)
}

// hasHostImage reports whether ffs may see into g's host image: g is an agent group with a host
// image digest.
func hasHostImage(g model.NodeGroup) bool { return g.Kind == model.NodeGroupAgent && g.Digest != "" }

// hostCoverage is the coverage figure of one host image: in use; seen into when the image is (seen);
// in full detail while none of members, the nodes it stands for, has a host coverage gap (hostGap).
// agents may be nil when the image is not seen into.
func hostCoverage(seen bool, members []string, agents *agentView) store.CoverageFigure {
	switch {
	case !seen:
		return store.CoverageFigure{InUse: 1}
	case slices.ContainsFunc(members, func(m string) bool { return hostGap(agents.of(m)) }):
		return store.CoverageFigure{InUse: 1, SeenInto: 1}
	}
	return store.CoverageFigure{InUse: 1, SeenInto: 1, Full: 1}
}

// groupCoverage is the coverage figure of every group in gs, in gs.groups order, as scopeCoverage
// gives it for each group's scope, read in one pass: one query for which agent groups' host images
// are seen into, and the agent statuses once, rather than an image lookup per group.
func (s *Server) groupCoverage(ctx context.Context, gs *groupSet) ([]store.CoverageFigure, error) {
	var digests []string
	for _, g := range gs.groups {
		if hasHostImage(g) {
			digests = append(digests, g.Digest)
		}
	}
	seen, err := s.o.Store.DigestsSeenInto(ctx, digests)
	if err != nil {
		return nil, err
	}
	var agents *agentView
	if len(seen) > 0 {
		if agents, err = s.agentView(ctx); err != nil {
			return nil, err
		}
	}
	out := make([]store.CoverageFigure, len(gs.groups))
	for i, g := range gs.groups {
		out[i] = hostCoverage(hasHostImage(g) && seen[g.Digest], g.Members, agents)
	}
	return out, nil
}

// imageRow is digest's images row, if any, as the API reads it: a catalogued image whose first
// match has not run yet is pending, since its findings are not known.
func (s *Server) imageRow(ctx context.Context, digest string) (model.Image, bool, error) {
	img, ok, err := s.o.Store.GetImage(ctx, digest)
	if err != nil || !ok || img.Status != model.ImageCatalogued {
		return img, ok, err
	}
	unmatched, err := s.o.Store.UnmatchedDigests(ctx, []string{digest})
	if err != nil {
		return model.Image{}, false, err
	}
	if len(unmatched) > 0 {
		img.Status, img.StatusReason = model.ImagePending, ""
	}
	return img, true, nil
}

// controlPlaneKeys are the owner keys of the control plane: the cluster, and the container runtime
// of each runtime the nodes report.
func (s *Server) controlPlaneKeys(ctx context.Context) ([]string, error) {
	nodes, err := s.o.Store.ListNodes(ctx)
	if err != nil {
		return nil, err
	}
	keys := []string{model.OwnerRef{Kind: model.OwnerKindCluster, Name: s.o.Config.ClusterName}.Key()}
	for _, n := range nodes {
		if name, _, ok := inventory.ParseRuntimeVersion(n.ContainerRuntimeVersion); ok {
			if k := (model.OwnerRef{Kind: model.OwnerKindContainerRuntime, Name: name}).Key(); !slices.Contains(keys, k) {
				keys = append(keys, k)
			}
		}
	}
	return keys, nil
}

// controlPlaneDigests are the Kubernetes and runtime images the control plane owners run.
func (s *Server) controlPlaneDigests(ctx context.Context) ([]string, error) {
	keys, err := s.controlPlaneKeys(ctx)
	if err != nil {
		return nil, err
	}
	byOwner, err := s.o.Store.DigestsOfOwners(ctx, keys)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, k := range keys {
		for _, d := range byOwner[k] {
			if (strings.HasPrefix(d, "k8s:") || strings.HasPrefix(d, "runtime:")) && !slices.Contains(out, d) {
				out = append(out, d)
			}
		}
	}
	return out, nil
}

// GetCoverage is what ffs sees in a cluster, namespace or workload scope: the funnel from pods to
// images seen into in full detail and fresh feeds, and every gap with what to do about it.
func (s *Server) GetCoverage(ctx context.Context, req apigen.GetCoverageRequestObject) (apigen.GetCoverageResponseObject, error) {
	sc, err := scopeParam(req.Params.Scope, model.ScopeCluster, model.ScopeNamespace, model.ScopeWorkload)
	if err != nil {
		return nil, err
	}
	if _, err := s.resolveScope(ctx, sc); err != nil {
		return nil, err
	}
	label, err := s.scopeTitle(ctx, sc)
	if err != nil {
		return nil, err
	}
	cov, err := s.o.Store.CoverageOf(ctx, sc)
	if err != nil {
		return nil, err
	}
	gaps, err := s.scopeGaps(ctx, sc)
	if err != nil {
		return nil, err
	}
	states, err := s.feedStates(ctx)
	if err != nil {
		return nil, err
	}
	funnel := apigen.CoverageFunnel{Images: cov.InUse, Catalogued: cov.SeenInto, FullDetail: cov.Full, FeedsTotal: len(s.o.Feeds)}
	now := s.o.Now()
	for i, st := range states {
		if !stale(st, s.o.Feeds[i], now) {
			funnel.FeedsFresh++
		}
	}
	if pods := s.pods(); pods != nil {
		keys := []string{sc.Value}
		if sc.Kind != model.ScopeWorkload {
			owners, err := s.o.Store.OwnerEntities(ctx, sc)
			if err != nil {
				return nil, err
			}
			keys = keys[:0]
			for _, o := range owners {
				keys = append(keys, o.Key)
			}
		}
		n := 0
		for _, k := range keys {
			n += pods[k]
		}
		funnel.Pods = &n
	}
	cluster, at := s.stamp()
	return apigen.GetCoverage200JSONResponse{Cluster: cluster, GeneratedAt: at, Scope: scopeRef(sc, label), Funnel: funnel, Gaps: gaps,
		TotalGaps: len(gaps)}, nil
}
