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

// resolveScope narrows a parsed scope to one the store answers. A node scope needs the node agent's
// grouping, which this build does not have, so it is 400 invalid_scope; every other scope is
// returned unchanged.
func (s *Server) resolveScope(_ context.Context, sc model.Scope) (model.Scope, error) {
	if sc.Kind == model.ScopeNode {
		return model.Scope{}, scopeProblem("node scopes need the node agent")
	}
	return sc, nil
}
