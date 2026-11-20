package apiserver

import (
	"context"
	"net/http"

	"github.com/the-it-dept/ffs/internal/web/apigen"
)

// The operations below are not implemented yet; each answers 501. The task that implements an
// operation removes its stub, and the last one removes this file.

func notImplemented() *Problem {
	return &Problem{Status: http.StatusNotImplemented, Code: apigen.ProblemCodeInternal, Detail: "not implemented"}
}

// GetSummary is not implemented yet.
func (s *Server) GetSummary(context.Context, apigen.GetSummaryRequestObject) (apigen.GetSummaryResponseObject, error) {
	return nil, notImplemented()
}

// GetScope is not implemented yet.
func (s *Server) GetScope(context.Context, apigen.GetScopeRequestObject) (apigen.GetScopeResponseObject, error) {
	return nil, notImplemented()
}

// GetExposure is not implemented yet.
func (s *Server) GetExposure(context.Context, apigen.GetExposureRequestObject) (apigen.GetExposureResponseObject, error) {
	return nil, notImplemented()
}

// ListNodeGroups is not implemented yet.
func (s *Server) ListNodeGroups(context.Context, apigen.ListNodeGroupsRequestObject) (apigen.ListNodeGroupsResponseObject, error) {
	return nil, notImplemented()
}

// GetNodeGroup is not implemented yet.
func (s *Server) GetNodeGroup(context.Context, apigen.GetNodeGroupRequestObject) (apigen.GetNodeGroupResponseObject, error) {
	return nil, notImplemented()
}

// GetNode is not implemented yet.
func (s *Server) GetNode(context.Context, apigen.GetNodeRequestObject) (apigen.GetNodeResponseObject, error) {
	return nil, notImplemented()
}

// GetCoverage is not implemented yet.
func (s *Server) GetCoverage(context.Context, apigen.GetCoverageRequestObject) (apigen.GetCoverageResponseObject, error) {
	return nil, notImplemented()
}
