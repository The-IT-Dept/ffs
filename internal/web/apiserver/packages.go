package apiserver

import (
	"context"

	"golang.org/x/sync/errgroup"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
	"github.com/the-it-dept/ffs/internal/web/apigen"
)

const opListPackages = "listPackages"

// ListPackages answers the packages explorer: the package versions of the images in use in the
// scope, with the images and workloads holding each and its open findings.
func (s *Server) ListPackages(ctx context.Context, req apigen.ListPackagesRequestObject) (apigen.ListPackagesResponseObject, error) {
	p := req.Params
	sc, err := scopeParam(p.Scope, model.ScopeCluster, model.ScopeNamespace, model.ScopeWorkload, model.ScopeImage)
	if err != nil {
		return nil, err
	}
	if _, err := s.resolveScope(ctx, sc); err != nil {
		return nil, err
	}
	prios, err := enumParam("priority", p.Priority)
	if err != nil {
		return nil, err
	}
	facets, err := enumParam("facets", p.Facets)
	if err != nil {
		return nil, err
	}
	sort, err := enumValue("sort", p.Sort)
	if err != nil {
		return nil, err
	}
	limit, err := limitParam(p.Limit)
	if err != nil {
		return nil, err
	}
	text, err := textParam("q", p.Q, maxQLen)
	if err != nil {
		return nil, err
	}
	after, err := decodeCursor(opListPackages, p, p.Cursor)
	if err != nil {
		return nil, err
	}
	q := store.PackageEntityQuery{Scope: sc, Ecosystems: stringsParam(p.Ecosystem), Worst: priorities(prios), Q: text, Sort: string(sort),
		After: after, Limit: limit}

	var (
		page   store.PackagePage
		counts map[string][]store.FacetValue
	)
	g, gctx := errgroup.WithContext(ctx)
	if len(facets) > 0 {
		g.Go(func() (err error) {
			counts, err = s.o.Store.PackageFacets(gctx, q, stringsOf(facets))
			return err
		})
	}
	g.Go(func() (err error) {
		page, err = s.o.Store.PackagesPage(gctx, q)
		return err
	})
	if err := g.Wait(); err != nil {
		return nil, err
	}
	rows := make([]apigen.PackageRow, 0, len(page.Rows))
	for _, r := range page.Rows {
		rows = append(rows, apigen.PackageRow{Ecosystem: r.Ecosystem, Name: r.Name, Version: r.Version, Images: r.Images,
			Workloads: r.Workloads, Counts: priorityCounts(r.Counts), Worst: priorityOf(r.Worst), Classifier: optString(r.Classifier)})
	}
	cluster, at := s.stamp()
	return apigen.ListPackages200JSONResponse{
		Cluster: cluster, GeneratedAt: at, Total: page.Total, Rows: rows, Next: encodeCursor(opListPackages, p, page.Next),
		Facets: entityFacets(counts, map[string][]string{"ecosystem": q.Ecosystems, "priority": priorityNames(q.Worst)}),
	}, nil
}
