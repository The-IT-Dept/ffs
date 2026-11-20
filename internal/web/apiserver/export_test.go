package apiserver

import (
	"context"
	"net/http"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
	"github.com/the-it-dept/ffs/internal/web/apigen"
)

// ScopeGapsAndCount lists a scope's gaps and counts them the rail's way, for the tests that pin
// that the two agree.
func (s *Server) ScopeGapsAndCount(ctx context.Context, sc model.Scope) ([]apigen.Gap, int, error) {
	gaps, err := s.scopeGaps(ctx, sc)
	if err != nil {
		return nil, 0, err
	}
	n, err := s.scopeGapCount(ctx, sc)
	return gaps, n, err
}

// ResponseError answers a request whose handler failed with err, as the strict handler does.
func (s *Server) ResponseError(w http.ResponseWriter, r *http.Request, err error) {
	s.responseError(w, r, err)
}

// RailGroupCoverage is the cluster rail's coverage of every node group, read in one pass, and
// scopeCoverage of each group's scope, both in group order, with each group's key, for the test that
// pins that the two agree.
func (s *Server) RailGroupCoverage(ctx context.Context) (keys []string, batched, perGroup []store.CoverageFigure, err error) {
	gs, err := s.groupSet(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	if batched, err = s.groupCoverage(ctx, gs); err != nil {
		return nil, nil, nil, err
	}
	for _, g := range gs.groups {
		c, err := s.scopeCoverage(ctx, gs.scope(g))
		if err != nil {
			return nil, nil, nil, err
		}
		keys, perGroup = append(keys, gs.key(g)), append(perGroup, c)
	}
	return keys, batched, perGroup, nil
}
