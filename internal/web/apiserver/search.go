package apiserver

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
	"github.com/the-it-dept/ffs/internal/web/apigen"
)

const (
	searchPerKind = 8  // hits asked of the store per kind
	searchMax     = 20 // hits answered
	searchMaxLen  = 100
)

// Search finds objects of every kind for the jump menu, in the store's order (kind, then prefix
// matches first) followed by node groups, at most 20.
func (s *Server) Search(ctx context.Context, req apigen.SearchRequestObject) (apigen.SearchResponseObject, error) {
	q := req.Params.Q
	if n := utf8.RuneCountInString(q); n < 1 || n > searchMaxLen {
		return nil, badParam("q", "must be 1 to 100 characters")
	}
	hits, err := s.o.Store.Jump(ctx, q, searchPerKind)
	if err != nil {
		return nil, err
	}
	groups, err := s.groupHits(ctx, q)
	if err != nil {
		return nil, err
	}
	hits = append(hits, groups...)
	perKind := map[string]int{}
	for _, h := range hits {
		perKind[h.Kind]++
	}
	truncated := len(hits) > searchMax
	for _, n := range perKind {
		truncated = truncated || n >= searchPerKind
	}
	out := make([]apigen.SearchHit, 0, min(len(hits), searchMax))
	for _, h := range hits[:min(len(hits), searchMax)] {
		hit := apigen.SearchHit{Kind: apigen.SearchHitKind(h.Kind), Id: h.ID, Label: h.Label, Detail: optString(h.Detail)}
		if kind, ok := hitScopes[h.Kind]; ok {
			hit.Scope = optString(model.Scope{Kind: kind, Value: h.ID}.String())
		}
		if h.Worst != model.PriorityNone {
			w := priorityOf(h.Worst)
			hit.Worst = &w
		}
		out = append(out, hit)
	}
	cluster, at := s.stamp()
	return apigen.Search200JSONResponse{Cluster: cluster, GeneratedAt: at, Query: q, Hits: out, Truncated: truncated}, nil
}

// hitScopes is the scope kind of each hit kind that has a scope; advisories and packages have none.
var hitScopes = map[string]model.ScopeKind{
	"workload": model.ScopeWorkload, "namespace": model.ScopeNamespace, "image": model.ScopeImage, "node": model.ScopeNode,
	"nodegroup": model.ScopeNodeGroup,
}

// groupHits are the node groups whose label or name contains q, case-insensitively: prefix matches
// first, at most searchPerKind.
func (s *Server) groupHits(ctx context.Context, q string) ([]store.JumpHit, error) {
	groups, err := s.nodeGroups(ctx)
	if err != nil {
		return nil, err
	}
	lq := strings.ToLower(q)
	var prefix, inside []store.JumpHit
	for _, g := range groups {
		label, name := strings.ToLower(g.Label), strings.ToLower(g.Name)
		hit := store.JumpHit{Kind: "nodegroup", ID: g.ID, Label: g.Label, Detail: fmt.Sprintf("%d nodes", len(g.Members))}
		switch {
		case strings.HasPrefix(label, lq) || strings.HasPrefix(name, lq):
			prefix = append(prefix, hit)
		case strings.Contains(label, lq) || strings.Contains(name, lq):
			inside = append(inside, hit)
		}
	}
	all := append(prefix, inside...)
	return all[:min(len(all), searchPerKind)], nil
}
