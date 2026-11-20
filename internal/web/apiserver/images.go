package apiserver

import (
	"cmp"
	"context"
	"slices"
	"strings"

	"golang.org/x/sync/errgroup"

	"github.com/the-it-dept/ffs/internal/match/upstream"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
	"github.com/the-it-dept/ffs/internal/web/apigen"
)

const (
	opListImages        = "listImages"
	opListImagePackages = "listImagePackages"

	// notableMax is how many packages an image page lists as notable.
	notableMax = 8
)

// ListImages answers the images explorer: the container images in use in the scope, including
// pending and unresolvable ones, with what ffs cannot see in each.
func (s *Server) ListImages(ctx context.Context, req apigen.ListImagesRequestObject) (apigen.ListImagesResponseObject, error) {
	p := req.Params
	sc, err := scopeParam(p.Scope, model.ScopeCluster, model.ScopeNamespace, model.ScopeWorkload)
	if err != nil {
		return nil, err
	}
	statuses, err := enumParam("status", p.Status)
	if err != nil {
		return nil, err
	}
	coverage, err := enumParam("coverage", p.Coverage)
	if err != nil {
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
	after, err := decodeCursor(opListImages, p, p.Cursor)
	if err != nil {
		return nil, err
	}
	q := store.ImageQuery{Scope: sc, Sources: stringsParam(p.Source), Coverage: coverageClasses(coverage),
		Namespaces: stringsParam(p.Namespace), Worst: priorities(prios), Q: text, Sort: store.ImageSort(sort), After: after, Limit: limit}
	for _, st := range statuses {
		q.Statuses = append(q.Statuses, model.ImageStatus(st))
	}

	var (
		page   store.ImagePage
		counts map[string][]store.FacetValue
	)
	g, gctx := errgroup.WithContext(ctx)
	if len(facets) > 0 {
		g.Go(func() (err error) {
			counts, err = s.o.Store.ImageFacets(gctx, q, stringsOf(facets))
			return err
		})
	}
	g.Go(func() (err error) {
		page, err = s.o.Store.ImagesPage(gctx, q)
		return err
	})
	if err := g.Wait(); err != nil {
		return nil, err
	}
	digests := make([]string, len(page.Rows))
	for i, r := range page.Rows {
		digests[i] = r.Image.Digest
	}
	classified, err := s.o.Store.ClassifiedPackages(ctx, digests)
	if err != nil {
		return nil, err
	}
	rows := make([]apigen.ImageRow, 0, len(page.Rows))
	for _, r := range page.Rows {
		img := r.Image
		rows = append(rows, apigen.ImageRow{
			Digest: img.Digest, Repo: img.Repo, Platform: img.Platform, Status: apigen.ImageStatus(img.Status),
			StatusReason: img.StatusReason, Source: img.Source, Coverage: apigen.CoverageClass(r.Class),
			// A digest with no images row comes back pending, which imageGaps reads the same way.
			Gaps:      imageGaps(img, true, upstream.UncoveredClassified(classified[img.Digest])),
			Workloads: r.Workloads, Counts: priorityCounts(r.Counts), Fixable: r.Fixable,
		})
	}
	cluster, at := s.stamp()
	return apigen.ListImages200JSONResponse{
		Cluster: cluster, GeneratedAt: at, Total: page.Total, Rows: rows, Next: encodeCursor(opListImages, p, page.Next),
		Facets: entityFacets(counts, map[string][]string{"status": stringsOf(q.Statuses), "source": q.Sources,
			"coverage": stringsOf(q.Coverage), "namespace": q.Namespaces, "priority": priorityNames(q.Worst)}),
	}, nil
}

// imageOf reads an image by digest. A digest with no images row that an owner runs is a pending
// image with the repository of the container that runs it; any other unknown digest is 404.
func (s *Server) imageOf(ctx context.Context, digest string) (img model.Image, hasRow bool, owners []string, err error) {
	img, hasRow, err = s.o.Store.GetImage(ctx, digest)
	if err != nil {
		return model.Image{}, false, nil, err
	}
	owners, err = s.o.Store.OwnersForDigests(ctx, []string{digest})
	if err != nil {
		return model.Image{}, false, nil, err
	}
	if hasRow {
		return img, true, owners, nil
	}
	if len(owners) == 0 {
		return model.Image{}, false, nil, notFound("image " + digest + " not found")
	}
	img = model.Image{Digest: digest, Status: model.ImagePending}
	if o, ok, err := s.o.Store.GetOwner(ctx, owners[0]); err != nil {
		return model.Image{}, false, nil, err
	} else if ok {
		for _, c := range o.Containers {
			if c.Digest == digest {
				img.Repo, img.Platform = c.Repo, c.Platform
				break
			}
		}
	}
	return img, false, owners, nil
}

// GetImage is one image: identity, SBOM provenance, ecosystems, counts, who runs it, upgrade
// candidates, coverage, lifecycle and notable packages. The digest arrives as one path segment, so
// placeholder IDs that hold slashes work.
func (s *Server) GetImage(ctx context.Context, req apigen.GetImageRequestObject) (apigen.GetImageResponseObject, error) {
	digest := req.Digest
	img, hasRow, owners, err := s.imageOf(ctx, digest)
	if err != nil {
		return nil, err
	}
	tags, err := s.o.Store.TagsOf(ctx, digest)
	if err != nil {
		return nil, err
	}
	sbom := apigen.SbomInfo{Source: img.Source}
	if name, version, ok, err := s.o.Store.SBOMDescriptor(ctx, digest); err != nil {
		return nil, err
	} else if ok {
		sbom.Tool, sbom.ToolVersion = optString(name), optString(version)
	}
	if p, ok, err := s.o.Store.AgentProvenanceOf(ctx, digest); err != nil {
		return nil, err
	} else if ok {
		sbom.Agent = &apigen.AgentProvenance{Node: p.Node, AgentVersion: p.AgentVersion, ReceivedAt: p.ReceivedAt.UTC()}
	}
	ecosystems, err := s.o.Store.ImageEcosystems(ctx, digest)
	if err != nil {
		return nil, err
	}
	stats, err := s.o.Store.ScopeStats(ctx, model.Scope{Kind: model.ScopeImage, Value: digest})
	if err != nil {
		return nil, err
	}
	upgrades, err := s.suggestions(ctx, func(owner string, sg model.Suggestion) bool {
		return sg.Repo == img.Repo && slices.Contains(owners, owner)
	})
	if err != nil {
		return nil, err
	}
	classified, err := s.o.Store.ClassifiedPackages(ctx, []string{digest})
	if err != nil {
		return nil, err
	}
	pkgs, err := s.o.Store.PackagesForImage(ctx, digest)
	if err != nil {
		return nil, err
	}
	notable, err := s.notablePackages(ctx, digest)
	if err != nil {
		return nil, err
	}

	cpeOnly := upstream.UncoveredClassified(classified[digest])
	class := model.CoverageNone
	if hasRow {
		class = store.CoverageClassOf(img)
	}
	usedBy := make([]apigen.WorkloadRef, 0, len(owners))
	for _, key := range owners {
		usedBy = append(usedBy, workloadRef(ownerOfKey(key)))
	}
	eols := []apigen.EOL{}
	if s.o.EOL != nil {
		now := s.o.Now()
		for _, st := range s.o.EOL.ImageEOL(img.Repo, pkgs) {
			eols = append(eols, eolOf(st, now))
		}
	}
	ecos := make([]apigen.EcosystemCount, 0, len(ecosystems))
	for _, e := range ecosystems {
		ecos = append(ecos, apigen.EcosystemCount{Ecosystem: e.Value, Packages: e.Count})
	}
	cluster, at := s.stamp()
	return apigen.GetImage200JSONResponse{
		Cluster: cluster, GeneratedAt: at, Digest: digest, IndexDigest: img.IndexDigest, Repo: img.Repo, Platform: img.Platform,
		Tags: nz(tags), VersionAnnotation: img.VersionAnnotation, Status: apigen.ImageStatus(img.Status), StatusReason: img.StatusReason,
		Source: img.Source, Sbom: sbom, Ecosystems: ecos, Counts: priorityCounts(stats.Counts), Fixable: stats.Fixable,
		UsedBy: usedBy, Upgrades: upgrades,
		Coverage: apigen.ImageCoverage{Class: apigen.CoverageClass(class), UnattributedExecutables: img.Coverage.UnattributedELF,
			RustWithoutAuditable: img.Coverage.RustWithoutAuditable, Notes: nz(slices.Clone(img.Coverage.Notes)), CpeOnly: nz(cpeOnly),
			Gaps: imageGaps(img, hasRow, cpeOnly)},
		Eol: eols, Notable: notable,
	}, nil
}

// notablePackages lists an image's packages that matter most: those a binary classifier found
// first, then the rest by open findings, then by name; at most notableMax.
func (s *Server) notablePackages(ctx context.Context, digest string) ([]apigen.ImagePackageRow, error) {
	var all []store.ImagePackageRow
	for after := ""; ; {
		page, err := s.o.Store.ImagePackages(ctx, digest, "", nil, after, maxLimit)
		if err != nil {
			return nil, err
		}
		all = append(all, page.Rows...)
		if page.Next == "" {
			break
		}
		after = page.Next
	}
	slices.SortStableFunc(all, func(a, b store.ImagePackageRow) int {
		if ca, cb := a.Package.Classifier != "", b.Package.Classifier != ""; ca != cb {
			if ca {
				return -1
			}
			return 1
		}
		return cmp.Or(cmp.Compare(b.Findings, a.Findings), strings.Compare(a.Package.Name, b.Package.Name))
	})
	out := make([]apigen.ImagePackageRow, 0, min(len(all), notableMax))
	for _, r := range all[:min(len(all), notableMax)] {
		out = append(out, imagePackageRow(r))
	}
	return out, nil
}

func imagePackageRow(r store.ImagePackageRow) apigen.ImagePackageRow {
	p := r.Package
	return apigen.ImagePackageRow{Name: p.Name, Version: p.Installed(), Ecosystem: p.Ecosystem, Purl: optString(p.PURL),
		Classifier: optString(p.Classifier), Path: optString(p.Path), Findings: r.Findings, Worst: priorityOf(r.Worst)}
}

// ListImagePackages searches one image's packages by name, version or ID, with the ecosystem facet.
func (s *Server) ListImagePackages(ctx context.Context, req apigen.ListImagePackagesRequestObject) (apigen.ListImagePackagesResponseObject, error) {
	p, digest := req.Params, req.Digest
	if _, _, _, err := s.imageOf(ctx, digest); err != nil {
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
	// The cursor is tied to the image as well as the query.
	op := opListImagePackages + " " + digest
	after, err := decodeCursor(op, p, p.Cursor)
	if err != nil {
		return nil, err
	}
	ecosystems := stringsParam(p.Ecosystem)
	page, err := s.o.Store.ImagePackages(ctx, digest, text, ecosystems, after, limit)
	if err != nil {
		return nil, err
	}
	counts, err := s.o.Store.ImageEcosystems(ctx, digest)
	if err != nil {
		return nil, err
	}
	rows := make([]apigen.ImagePackageRow, 0, len(page.Rows))
	for _, r := range page.Rows {
		rows = append(rows, imagePackageRow(r))
	}
	cluster, at := s.stamp()
	return apigen.ListImagePackages200JSONResponse{
		Cluster: cluster, GeneratedAt: at, Total: page.Total, Rows: rows, Next: encodeCursor(op, p, page.Next),
		Facets: apigen.Facets{"ecosystem": facetValues(counts, ecosystems)},
	}, nil
}
