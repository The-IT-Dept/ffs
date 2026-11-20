package apiserver

import (
	"context"
	"slices"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/web/apigen"
)

// reachable counts what in a scope can be reached from outside, and how many of those carry
// urgent findings: the exposed workloads of a cluster, namespace, workload or image scope (internal
// entry points never expose a workload), the exposed nodes of a node group or a node, and nothing
// for the control plane.
func (s *Server) reachable(ctx context.Context, sc model.Scope) (n, urgent int, err error) {
	var keys []string
	switch sc.Kind {
	case model.ScopeCluster, model.ScopeNamespace:
		owners, err := s.o.Store.OwnerEntities(ctx, sc)
		if err != nil {
			return 0, 0, err
		}
		for _, o := range owners {
			if o.Exposed {
				keys = append(keys, o.Key)
			}
		}
	case model.ScopeWorkload, model.ScopeImage:
		candidates := []string{sc.Value}
		if sc.Kind == model.ScopeImage {
			if candidates, err = s.o.Store.OwnersForDigests(ctx, []string{sc.Value}); err != nil {
				return 0, 0, err
			}
		}
		for _, k := range candidates {
			o, ok, err := s.o.Store.OwnerEntityOf(ctx, k)
			if err != nil {
				return 0, 0, err
			}
			if ok && o.Exposed {
				keys = append(keys, k)
			}
		}
	case model.ScopeNodeGroup, model.ScopeNode:
		return s.reachableNodes(ctx, sc)
	case model.ScopeControlPlane:
		return 0, 0, nil
	}
	stats, err := s.o.Store.OwnerStatsOf(ctx, keys)
	if err != nil {
		return 0, 0, err
	}
	for _, k := range keys {
		if stats[k].Counts.Urgent > 0 {
			urgent++
		}
	}
	return len(keys), urgent, nil
}

// reachableNodes counts the exposed nodes of a node group, or the node itself when it is exposed,
// and those of them whose group carries urgent host findings.
func (s *Server) reachableNodes(ctx context.Context, sc model.Scope) (n, urgent int, err error) {
	var (
		g  model.NodeGroup
		ok bool
	)
	if sc.Kind == model.ScopeNode {
		g, ok, err = s.groupOf(ctx, sc.Value)
	} else {
		g, ok, err = s.findGroup(ctx, sc.Value)
	}
	if err != nil || !ok {
		return 0, 0, err
	}
	n = len(g.ExposedNodes)
	if sc.Kind == model.ScopeNode {
		n = 0
		if slices.Contains(g.ExposedNodes, sc.Value) {
			n = 1
		}
	}
	st, err := s.groupStats(ctx, g)
	if err != nil {
		return 0, 0, err
	}
	if st.Counts.Urgent > 0 {
		urgent = n
	}
	return n, urgent, nil
}

// GetSummary is a scope's headline: what is reachable from outside, the open findings, what can be
// fixed, what is exploited, how far ffs sees into it, how fresh the feeds are and how many gaps it
// has.
func (s *Server) GetSummary(ctx context.Context, req apigen.GetSummaryRequestObject) (apigen.GetSummaryResponseObject, error) {
	sc, err := scopeParam(req.Params.Scope)
	if err != nil {
		return nil, err
	}
	resolved, err := s.resolveScope(ctx, sc)
	if err != nil {
		return nil, err
	}
	label, err := s.scopeTitle(ctx, sc)
	if err != nil {
		return nil, err
	}
	n, urgent, err := s.reachable(ctx, sc)
	if err != nil {
		return nil, err
	}
	stats, err := s.o.Store.ScopeStats(ctx, resolved)
	if err != nil {
		return nil, err
	}
	cov, err := s.scopeCoverage(ctx, sc)
	if err != nil {
		return nil, err
	}
	feeds, err := s.freshness(ctx)
	if err != nil {
		return nil, err
	}
	gaps, err := s.scopeGapCount(ctx, sc)
	if err != nil {
		return nil, err
	}
	cluster, at := s.stamp()
	return apigen.GetSummary200JSONResponse{
		Cluster: cluster, GeneratedAt: at, Scope: scopeRef(sc, label), Reachable: n, ReachableUrgent: urgent,
		Findings: priorityCounts(stats.Counts), Open: stats.Open, Fixable: stats.Fixable, Exploited: stats.Exploited,
		Coverage: coverageFigure(cov), Feeds: feeds, Gaps: gaps,
	}, nil
}
