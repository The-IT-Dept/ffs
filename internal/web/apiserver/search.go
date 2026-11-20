package apiserver

import (
	"context"
	"unicode/utf8"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/web/apigen"
)

const (
	searchPerKind = 8  // hits asked of the store per kind
	searchMax     = 20 // hits answered
	searchMaxLen  = 100
)

// Search finds objects of every kind for the jump menu, in the store's order (kind, then prefix
// matches first), at most 20.
func (s *Server) Search(ctx context.Context, req apigen.SearchRequestObject) (apigen.SearchResponseObject, error) {
	q := req.Params.Q
	if n := utf8.RuneCountInString(q); n < 1 || n > searchMaxLen {
		return nil, badParam("q", "must be 1 to 100 characters")
	}
	hits, err := s.o.Store.Jump(ctx, q, searchPerKind)
	if err != nil {
		return nil, err
	}
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
}
