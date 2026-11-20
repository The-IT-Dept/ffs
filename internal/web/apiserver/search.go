package apiserver

import (
	"context"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/nodegroup"
	"github.com/the-it-dept/ffs/internal/store"
	"github.com/the-it-dept/ffs/internal/web/apigen"
)

const (
	searchPerKind = 8  // hits asked of the store per kind
	searchMax     = 20 // hits answered
	searchMaxLen  = 100

	nodesLabel = "Nodes"
)

// searchKinds orders the kinds a search interleaves: the control plane and Nodes pages, then the
// store's kinds, then node groups (by name, or holding a host package that matches).
var searchKinds = []string{"page", "workload", "namespace", "image", "advisory", "package", "nodegroup", "node"}

// Search finds objects of every kind for the jump menu, at most 20. Hits whose label starts with
// the query come first, the kinds taking turns, then the hits that contain it elsewhere, again by
// turns; truncated says that more matched than are answered. A package only node groups hold opens
// the node group, and the control plane and Nodes are hits of their own.
func (s *Server) Search(ctx context.Context, req apigen.SearchRequestObject) (apigen.SearchResponseObject, error) {
	q := req.Params.Q
	if n := utf8.RuneCountInString(q); n < 1 || n > searchMaxLen {
		return nil, badParam("q", "must be 1 to 100 characters")
	}
	hits, truncated, err := s.o.Store.Jump(ctx, q, searchPerKind)
	if err != nil {
		return nil, err
	}
	groups, more, err := s.groupHits(ctx, q, hits)
	if err != nil {
		return nil, err
	}
	truncated = truncated || more
	pages, err := s.pageHits(ctx, q)
	if err != nil {
		return nil, err
	}
	found := pages
	for _, h := range hits {
		if h.Kind != "hostpackage" { // they come back as their node groups
			found = append(found, hitOf(h))
		}
	}
	all := interleave(append(found, groups...))
	truncated = truncated || len(all) > searchMax
	out := make([]apigen.SearchHit, 0, min(len(all), searchMax))
	for _, h := range all[:min(len(all), searchMax)] {
		out = append(out, h.hit)
	}
	cluster, at := s.stamp()
	return apigen.Search200JSONResponse{Cluster: cluster, GeneratedAt: at, Query: q, Hits: out, Truncated: truncated}, nil
}

// searchHit is an answer with the kind it takes turns as and whether its label starts with the query.
type searchHit struct {
	hit    apigen.SearchHit
	kind   string
	prefix bool
}

// hitOf shapes a store hit; it has a scope when its kind has one, and a namespace's detail is its
// workload count.
func hitOf(h store.JumpHit) searchHit {
	if h.Kind == "namespace" {
		h.Detail = plural(h.Count, "workload")
	}
	hit := apigen.SearchHit{Kind: apigen.SearchHitKind(h.Kind), Id: h.ID, Label: h.Label, Detail: optString(h.Detail)}
	if kind, ok := hitScopes[h.Kind]; ok {
		hit.Scope = optString(model.Scope{Kind: kind, Value: h.ID}.String())
	}
	if h.Worst != model.PriorityNone {
		w := priorityOf(h.Worst)
		hit.Worst = &w
	}
	return searchHit{hit: hit, kind: h.Kind, prefix: h.Prefix}
}

// interleave orders hits prefix ones first; within each tier the kinds take turns, in searchKinds
// order, each kind's hits keeping their order. A hit of a kind searchKinds does not list is left out.
func interleave(hits []searchHit) []searchHit {
	out := make([]searchHit, 0, len(hits))
	for _, prefix := range []bool{true, false} {
		queues := make([][]searchHit, len(searchKinds))
		for _, h := range hits {
			i := slices.Index(searchKinds, h.kind)
			if h.prefix == prefix && i >= 0 {
				queues[i] = append(queues[i], h)
			}
		}
		for taken := true; taken; {
			taken = false
			for i := range queues {
				if len(queues[i]) > 0 {
					out, queues[i], taken = append(out, queues[i][0]), queues[i][1:], true
				}
			}
		}
	}
	return out
}

// hitScopes is the scope kind of each hit kind that has a scope; advisories and packages have none.
var hitScopes = map[string]model.ScopeKind{
	"workload": model.ScopeWorkload, "namespace": model.ScopeNamespace, "image": model.ScopeImage, "node": model.ScopeNode,
	"nodegroup": model.ScopeNodeGroup,
}

// groupHits are the node groups whose label or name contains q, case-insensitively, prefix matches
// first, then the groups holding a host package (hostpackage hits) that no container image holds,
// each group once, at most searchPerKind; more reports that there were more.
func (s *Server) groupHits(ctx context.Context, q string, hits []store.JumpHit) ([]searchHit, bool, error) {
	gs, err := s.groupSet(ctx)
	if err != nil {
		return nil, false, err
	}
	lq := strings.ToLower(q)
	var prefix, inside []searchHit
	hitOfGroup := func(g model.NodeGroup, detail string, pre bool) searchHit {
		h := hitOf(store.JumpHit{Kind: "nodegroup", ID: gs.key(g), Label: g.Label, Detail: detail})
		h.prefix = pre
		return h
	}
	for _, g := range gs.groups {
		label, name := strings.ToLower(g.Label), strings.ToLower(g.Name)
		detail := plural(len(g.Members), "node")
		switch {
		case strings.HasPrefix(label, lq) || strings.HasPrefix(name, lq):
			prefix = append(prefix, hitOfGroup(g, detail, true))
		case strings.Contains(label, lq) || strings.Contains(name, lq):
			inside = append(inside, hitOfGroup(g, detail, false))
		}
	}
	all := append(prefix, inside...)
	for _, h := range hits {
		if h.Kind != "hostpackage" {
			continue
		}
		id, ok := nodegroup.IDFromDigest(h.ID)
		if !ok {
			continue
		}
		g, ok := gs.byID(id)
		if !ok || slices.ContainsFunc(all, func(x searchHit) bool { return x.hit.Id == gs.key(g) }) {
			continue
		}
		all = append(all, hitOfGroup(g, h.Label+" "+h.Detail+" · host package", h.Prefix))
	}
	return all[:min(len(all), searchPerKind)], len(all) > searchPerKind, nil
}

// pageHits are the control plane and the Nodes page when q names them: "Control plane" or
// "Kubernetes" or a container runtime of the nodes, and "Nodes" or "host packages". Each is its
// cluster-level owner, the control plane with its scope.
func (s *Server) pageHits(ctx context.Context, q string) ([]searchHit, error) {
	lq := strings.ToLower(q)
	match := func(terms ...string) (found, prefix bool) {
		for _, t := range terms {
			t = strings.ToLower(t)
			if strings.HasPrefix(t, lq) {
				return true, true
			}
			found = found || strings.Contains(t, lq)
		}
		return found, false
	}
	var out []searchHit
	keys, err := s.controlPlaneKeys(ctx)
	if err != nil {
		return nil, err
	}
	terms := []string{controlPlaneLabel, "Kubernetes"}
	for _, k := range keys[1:] {
		terms = append(terms, ownerOfKey(k).Name)
	}
	if ok, prefix := match(terms...); ok {
		st, err := s.o.Store.ScopeStats(ctx, model.Scope{Kind: model.ScopeControlPlane})
		if err != nil {
			return nil, err
		}
		ci, _, err := s.o.Store.GetClusterInfo(ctx)
		if err != nil {
			return nil, err
		}
		h := hitOf(store.JumpHit{Kind: "workload", ID: keys[0], Label: controlPlaneLabel, Worst: st.Counts.Worst()})
		if ci.Version != "" {
			h.hit.Detail = optString("Kubernetes " + ci.Version)
		}
		h.hit.Scope = optString(model.Scope{Kind: model.ScopeControlPlane}.String())
		h.kind, h.prefix = "page", prefix
		out = append(out, h)
	}
	if ok, prefix := match(nodesLabel, "Host packages"); ok {
		key := model.NodesOwner(s.o.Config.ClusterName).Key()
		st, err := s.o.Store.OwnerStatsOf(ctx, []string{key})
		if err != nil {
			return nil, err
		}
		nodes, err := s.o.Store.ListNodes(ctx)
		if err != nil {
			return nil, err
		}
		h := hitOf(store.JumpHit{Kind: "workload", ID: key, Label: nodesLabel, Detail: plural(len(nodes), "node"),
			Worst: st[key].Counts.Worst()})
		h.hit.Scope = nil // the Nodes page has no scope; the UI opens it for the Nodes owner
		h.kind, h.prefix = "page", prefix
		out = append(out, h)
	}
	return out, nil
}
