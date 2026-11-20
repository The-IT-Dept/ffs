package apiserver

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"unicode/utf8"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/web/apigen"
)

const (
	defaultLimit = 50
	maxLimit     = 200
)

// The generated router validates no enum, pattern or bound, so these helpers do.

// scopeParam parses the scope parameter: absent or "" is the cluster. A value that is not a scope,
// or a scope kind not in allowed (when allowed is not empty), is 400 invalid_scope.
func scopeParam(p *string, allowed ...model.ScopeKind) (model.Scope, error) {
	if p == nil || *p == "" {
		return model.Scope{Kind: model.ScopeCluster}, nil
	}
	sc, err := model.ParseScope(*p)
	if err != nil {
		return model.Scope{}, scopeProblem(fmt.Sprintf("%q is not a scope", *p))
	}
	if len(allowed) > 0 && !slices.Contains(allowed, sc.Kind) {
		return model.Scope{}, scopeProblem(fmt.Sprintf("%s scopes are not supported by this operation", sc.Kind))
	}
	return sc, nil
}

func scopeProblem(detail string) *Problem {
	return &Problem{Status: http.StatusBadRequest, Code: apigen.ProblemCodeInvalidScope, Detail: "scope: " + detail}
}

// limitParam is the page size: 50 when absent, else 1 to 200.
func limitParam(p *int) (int, error) {
	if p == nil {
		return defaultLimit, nil
	}
	if *p < 1 || *p > maxLimit {
		return 0, badParam("limit", fmt.Sprintf("must be between 1 and %d", maxLimit))
	}
	return *p, nil
}

// enumParam validates an array parameter of enum values: nil when absent; an unknown value is 400
// invalid_parameter naming the parameter and the value. Empty values are dropped, and the result is
// de-duplicated and sorted.
func enumParam[T interface {
	~string
	Valid() bool
}](name string, p *[]T) ([]T, error) {
	if p == nil {
		return nil, nil
	}
	var out []T
	for _, v := range *p {
		if v == "" {
			continue
		}
		if !v.Valid() {
			return nil, badParam(name, fmt.Sprintf("%q is not a valid value", string(v)))
		}
		out = append(out, v)
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// enumValue validates a single enum parameter: "" when absent or empty; an unknown value is 400
// invalid_parameter naming the parameter and the value.
func enumValue[T interface {
	~string
	Valid() bool
}](name string, p *T) (T, error) {
	if p == nil || *p == "" {
		return "", nil
	}
	if !(*p).Valid() {
		return "", badParam(name, fmt.Sprintf("%q is not a valid value", string(*p)))
	}
	return *p, nil
}

// stringsParam is an array parameter of free values: nil when absent, empty values dropped,
// de-duplicated and sorted.
func stringsParam(p *[]string) []string {
	if p == nil {
		return nil
	}
	var out []string
	for _, v := range *p {
		if v != "" {
			out = append(out, v)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// textParam is a free-text parameter: "" when absent; longer than max characters is 400
// invalid_parameter.
func textParam(name string, p *string, maxLen int) (string, error) {
	if p == nil {
		return "", nil
	}
	if utf8.RuneCountInString(*p) > maxLen {
		return "", badParam(name, fmt.Sprintf("must be at most %d characters", maxLen))
	}
	return *p, nil
}

// canonicalScope is sc as the API names it in answers: a node-group scope by its group's key
// (groupSet.scope), however the request named the group (its ID, label or a stable form of its key).
// Any other scope, and a group that is not found, is sc as given.
func (s *Server) canonicalScope(ctx context.Context, sc model.Scope) (model.Scope, error) {
	if sc.Kind != model.ScopeNodeGroup {
		return sc, nil
	}
	gs, err := s.groupSet(ctx)
	if err != nil {
		return model.Scope{}, err
	}
	if g, ok := gs.find(sc.Value); ok {
		return gs.scope(g), nil
	}
	return sc, nil
}

// resolveScope narrows a parsed scope to one the store answers and checks that its object exists: a
// node scope is its group's (host findings are per group), a node group scope names the group by
// its ID (it may name it by its key or label: groupSet.find), and a workload scope must name a
// stored owner. An unknown node, node group or workload is 404 not_found. Every other scope is
// returned unchanged.
func (s *Server) resolveScope(ctx context.Context, sc model.Scope) (model.Scope, error) {
	switch sc.Kind {
	case model.ScopeNode, model.ScopeNodeGroup:
		gs, err := s.groupSet(ctx)
		if err != nil {
			return model.Scope{}, err
		}
		if sc.Kind == model.ScopeNode {
			g, ok := gs.of(sc.Value)
			if !ok {
				return model.Scope{}, notFound("node " + sc.Value + " not found")
			}
			return model.Scope{Kind: model.ScopeNodeGroup, Value: g.ID}, nil
		}
		g, ok := gs.find(sc.Value)
		if !ok {
			return model.Scope{}, notFound("node group " + sc.Value + " not found")
		}
		return model.Scope{Kind: model.ScopeNodeGroup, Value: g.ID}, nil
	case model.ScopeWorkload:
		ok, err := s.o.Store.OwnerExists(ctx, sc.Value)
		if err != nil {
			return model.Scope{}, err
		}
		if !ok {
			return model.Scope{}, notFound("workload " + sc.Value + " not found")
		}
	case model.ScopeCluster, model.ScopeNamespace, model.ScopeImage, model.ScopeControlPlane:
	}
	return sc, nil
}
