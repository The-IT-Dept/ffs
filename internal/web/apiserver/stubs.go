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

// ListFindings is not implemented yet.
func (s *Server) ListFindings(context.Context, apigen.ListFindingsRequestObject) (apigen.ListFindingsResponseObject, error) {
	return nil, notImplemented()
}

// ListTransitions is not implemented yet.
func (s *Server) ListTransitions(context.Context, apigen.ListTransitionsRequestObject) (apigen.ListTransitionsResponseObject, error) {
	return nil, notImplemented()
}

// GetAdvisory is not implemented yet.
func (s *Server) GetAdvisory(context.Context, apigen.GetAdvisoryRequestObject) (apigen.GetAdvisoryResponseObject, error) {
	return nil, notImplemented()
}

// ListWorkloads is not implemented yet.
func (s *Server) ListWorkloads(context.Context, apigen.ListWorkloadsRequestObject) (apigen.ListWorkloadsResponseObject, error) {
	return nil, notImplemented()
}

// GetWorkload is not implemented yet.
func (s *Server) GetWorkload(context.Context, apigen.GetWorkloadRequestObject) (apigen.GetWorkloadResponseObject, error) {
	return nil, notImplemented()
}

// ListImages is not implemented yet.
func (s *Server) ListImages(context.Context, apigen.ListImagesRequestObject) (apigen.ListImagesResponseObject, error) {
	return nil, notImplemented()
}

// GetImage is not implemented yet.
func (s *Server) GetImage(context.Context, apigen.GetImageRequestObject) (apigen.GetImageResponseObject, error) {
	return nil, notImplemented()
}

// ListImagePackages is not implemented yet.
func (s *Server) ListImagePackages(context.Context, apigen.ListImagePackagesRequestObject) (apigen.ListImagePackagesResponseObject, error) {
	return nil, notImplemented()
}

// ListPackages is not implemented yet.
func (s *Server) ListPackages(context.Context, apigen.ListPackagesRequestObject) (apigen.ListPackagesResponseObject, error) {
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
