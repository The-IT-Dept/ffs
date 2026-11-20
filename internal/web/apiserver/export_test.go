package apiserver

import (
	"context"

	"github.com/the-it-dept/ffs/internal/model"
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
