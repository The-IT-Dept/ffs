package apiserver

import (
	"context"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/web/apigen"
)

const opListTransitions = "listTransitions"

// ListTransitions is the finding history of a scope, newest first.
func (s *Server) ListTransitions(ctx context.Context, req apigen.ListTransitionsRequestObject) (apigen.ListTransitionsResponseObject, error) {
	p := req.Params
	sc, err := scopeParam(p.Scope, model.ScopeCluster, model.ScopeNamespace, model.ScopeWorkload, model.ScopeControlPlane)
	if err != nil {
		return nil, err
	}
	limit, err := limitParam(p.Limit)
	if err != nil {
		return nil, err
	}
	after, err := decodeCursor(opListTransitions, p, p.Cursor)
	if err != nil {
		return nil, err
	}
	page, err := s.o.Store.TransitionsPage(ctx, sc, after, limit)
	if err != nil {
		return nil, err
	}
	rows := make([]apigen.TransitionRow, 0, len(page.Rows))
	for _, t := range page.Rows {
		rows = append(rows, apigen.TransitionRow{
			Id: t.ID, At: t.At.UTC(), Advisory: t.AdvisoryID, Workload: workloadRef(t.Owner),
			FromState: string(t.FromState), ToState: apigen.FindingState(t.ToState),
			FromPriority: priorityOf(t.FromPriority), ToPriority: priorityOf(t.ToPriority),
			Trigger: string(t.Trigger), Provisional: t.Provisional,
		})
	}
	cluster, at := s.stamp()
	return apigen.ListTransitions200JSONResponse{Cluster: cluster, GeneratedAt: at, Rows: rows,
		Next: encodeCursor(opListTransitions, p, page.Next)}, nil
}
