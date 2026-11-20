package apiserver

import (
	"context"
	"net/http"

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

// ResponseError answers a request whose handler failed with err, as the strict handler does.
func (s *Server) ResponseError(w http.ResponseWriter, r *http.Request, err error) {
	s.responseError(w, r, err)
}
