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

const opListWorkloads = "listWorkloads"

// Coverage notes of a workload whose images are not all catalogued.
const (
	noteCPE           = "daily, CPE-based coverage only: "
	noteNotCatalogued = "image not catalogued yet: "
	noteNotResolved   = "image not resolved yet: "
)

// pods is the live pod count per owner key, or nil while it is not known.
func (s *Server) pods() map[string]int {
	if s.o.Pods == nil {
		return nil
	}
	return s.o.Pods.PodCounts()
}

// podsOf is an owner's pod count: nil while the counts are not known, else the count (0 when the
// owner has no pods).
func podsOf(m map[string]int, key string) *int {
	if m == nil {
		return nil
	}
	n := m[key]
	return &n
}

// ownerOfKey is the owner an owner key names.
func ownerOfKey(key string) model.OwnerRef {
	ref, _ := model.Scope{Kind: model.ScopeWorkload, Value: key}.Owner()
	return ref
}

// priorities converts validated API priorities to the model's.
func priorities(ps []apigen.Priority) []model.Priority {
	var out []model.Priority
	for _, p := range ps {
		out = append(out, modelPriority(p))
	}
	return out
}

func coverageClasses(cs []apigen.CoverageClass) []model.CoverageClass {
	var out []model.CoverageClass
	for _, c := range cs {
		out = append(out, model.CoverageClass(c))
	}
	return out
}

// entityFacets shapes entity facet counts, marking the selected values.
func entityFacets(counts map[string][]store.FacetValue, selected map[string][]string) apigen.Facets {
	out := apigen.Facets{}
	for f, vals := range counts {
		out[f] = facetValues(vals, selected[f])
	}
	return out
}

func priorityNames(ps []model.Priority) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = string(priorityOf(p))
	}
	return out
}

// ListWorkloads answers the workloads explorer: workload owners, including those with no findings,
// with their counts, coverage, best fix and pods.
func (s *Server) ListWorkloads(ctx context.Context, req apigen.ListWorkloadsRequestObject) (apigen.ListWorkloadsResponseObject, error) {
	p := req.Params
	sc, err := scopeParam(p.Scope, model.ScopeCluster, model.ScopeNamespace)
	if err != nil {
		return nil, err
	}
	signals, err := enumParam("signal", p.Signal)
	if err != nil {
		return nil, err
	}
	prios, err := enumParam("priority", p.Priority)
	if err != nil {
		return nil, err
	}
	coverage, err := enumParam("coverage", p.Coverage)
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
	after, err := decodeCursor(opListWorkloads, p, p.Cursor)
	if err != nil {
		return nil, err
	}
	q := store.WorkloadQuery{Scope: sc, Kinds: stringsParam(p.Kind), Namespaces: stringsParam(p.Namespace),
		Worst: priorities(prios), Coverage: coverageClasses(coverage), Q: text, Sort: store.WorkloadSort(sort), After: after, Limit: limit}
	for _, sg := range signals {
		q.Signals = append(q.Signals, model.Signal(sg))
	}

	var (
		page   store.WorkloadPage
		counts map[string][]store.FacetValue
	)
	g, gctx := errgroup.WithContext(ctx)
	if len(facets) > 0 {
		g.Go(func() (err error) {
			counts, err = s.o.Store.WorkloadFacets(gctx, q, stringsOf(facets))
			return err
		})
	}
	g.Go(func() (err error) {
		page, err = s.o.Store.WorkloadsPage(gctx, q)
		return err
	})
	if err := g.Wait(); err != nil {
		return nil, err
	}
	keys := make([]string, len(page.Rows))
	for i, r := range page.Rows {
		keys[i] = r.Owner.Key
	}
	best, err := s.o.Store.BestFixes(ctx, keys)
	if err != nil {
		return nil, err
	}
	pods := s.pods()
	rows := make([]apigen.WorkloadRow, 0, len(page.Rows))
	for _, r := range page.Rows {
		o := r.Owner
		row := apigen.WorkloadRow{
			Workload: workloadRef(model.OwnerRef{Kind: o.Kind, Namespace: o.Namespace, Name: o.Name}), ManagedBy: managedBy(o.Managed),
			NotRunning: o.NotRunning, Exposed: o.Exposed, Privileged: o.Privileged, SaPower: o.PowerfulSA,
			Counts: priorityCounts(r.Stats.Counts), Open: r.Stats.Open, Fixable: r.Stats.Fixable, Exploited: r.Stats.Exploited,
			Coverage: coverageFigure(r.Coverage), CoverageClass: apigen.CoverageClass(r.Class), Pods: podsOf(pods, o.Key),
		}
		if fs, ok := best[o.Key]; ok {
			fix := fixActionOf(fs.Sample)
			row.BestFix = &fix
		}
		rows = append(rows, row)
	}
	cluster, at := s.stamp()
	return apigen.ListWorkloads200JSONResponse{
		Cluster: cluster, GeneratedAt: at, Total: page.Total, Rows: rows, Next: encodeCursor(opListWorkloads, p, page.Next),
		Facets: entityFacets(counts, map[string][]string{"kind": q.Kinds, "namespace": q.Namespaces, "signal": stringsOf(q.Signals),
			"priority": priorityNames(q.Worst), "coverage": stringsOf(q.Coverage)}),
	}, nil
}

// GetWorkload is one owner: its context, containers and their images, counts, coverage, upgrade
// suggestions and best fix. A namespace of "-" names a cluster-level owner.
func (s *Server) GetWorkload(ctx context.Context, req apigen.GetWorkloadRequestObject) (apigen.GetWorkloadResponseObject, error) {
	ref := model.OwnerRef{Kind: req.Kind, Namespace: req.Namespace, Name: req.Name}
	if ref.Namespace == "-" {
		ref.Namespace = ""
	}
	key := ref.Key()
	o, ok, err := s.o.Store.GetOwner(ctx, key)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, notFound("workload " + key + " not found")
	}
	entity, hasEntity, err := s.o.Store.OwnerEntityOf(ctx, key)
	if err != nil {
		return nil, err
	}
	stats, err := s.o.Store.OwnerStatsOf(ctx, []string{key})
	if err != nil {
		return nil, err
	}
	cov, err := s.o.Store.CoverageOf(ctx, model.Scope{Kind: model.ScopeWorkload, Value: key})
	if err != nil {
		return nil, err
	}
	notes, err := s.coverageNotes(ctx, o)
	if err != nil {
		return nil, err
	}
	containers, err := s.workloadContainers(ctx, o)
	if err != nil {
		return nil, err
	}
	upgrades, err := s.suggestions(ctx, func(owner string, _ model.Suggestion) bool { return owner == key })
	if err != nil {
		return nil, err
	}
	best, err := s.o.Store.BestFixes(ctx, []string{key})
	if err != nil {
		return nil, err
	}

	st := stats[key]
	exposure := make([]apigen.ExposureEdge, 0, len(o.Context.Exposure))
	for _, e := range o.Context.Exposure {
		exposure = append(exposure, apigen.ExposureEdge{Entry: apigen.EntryKind(e.Entry), EntryName: e.EntryName, Listener: e.Listener,
			Hostname: e.Hostname, Route: e.Route, Service: e.Service, Internal: e.Internal})
	}
	cluster, at := s.stamp()
	out := apigen.GetWorkload200JSONResponse{
		Cluster: cluster, GeneratedAt: at, Workload: workloadRef(o.Ref), ManagedBy: managedBy(o.ManagedBy),
		ServiceAccount: o.ServiceAccount, NotRunning: o.NotRunning, Pods: podsOf(s.pods(), key),
		Exposed: o.Context.Exposed, Exposure: exposure, Privileged: o.Context.Privileged, PrivilegeReasons: nz(o.Context.PrivilegeReasons),
		SaPower: o.Context.PowerfulSA, SaReasons: nz(o.Context.SAReasons), Containers: containers,
		Counts: priorityCounts(st.Counts), Open: st.Open, Fixable: st.Fixable, Exploited: st.Exploited, Excepted: st.Excepted,
		Coverage: coverageFigure(cov), CoverageNotes: notes, Upgrades: upgrades,
	}
	if hasEntity {
		// The effective privilege also counts containers that run as a root image user.
		out.Privileged = entity.Privileged
	}
	if fs, ok := best[key]; ok {
		fix := fixActionOf(fs.Sample)
		out.BestFix = &fix
	}
	return out, nil
}

// workloadContainers lists an owner's containers with the status and coverage of their images. A
// digest with no images row is pending.
func (s *Server) workloadContainers(ctx context.Context, o model.Owner) ([]apigen.WorkloadContainer, error) {
	out := make([]apigen.WorkloadContainer, 0, len(o.Containers))
	for _, c := range o.Containers {
		wc := apigen.WorkloadContainer{Name: c.Name, Kind: string(c.Kind), Image: c.ImageRef, Repo: c.Repo,
			Digest: optString(c.Digest), Platform: optString(c.Platform)}
		if c.Digest != "" {
			img, ok, err := s.o.Store.GetImage(ctx, c.Digest)
			if err != nil {
				return nil, err
			}
			status, class := apigen.ImageStatusPending, apigen.CoverageClassNone
			if ok {
				status, class = apigen.ImageStatus(img.Status), apigen.CoverageClass(store.CoverageClassOf(img))
			}
			wc.Status, wc.Coverage = &status, &class
		}
		out = append(out, wc)
	}
	return out, nil
}

// suggestions shapes the stored upgrade suggestions keep selects, by owner and repository.
func (s *Server) suggestions(ctx context.Context, keep func(owner string, sg model.Suggestion) bool) ([]apigen.Suggestion, error) {
	list, err := s.o.Store.ListSuggestions(ctx)
	if err != nil {
		return nil, err
	}
	out := []apigen.Suggestion{}
	for _, os := range list {
		if keep(os.OwnerKey, os.Suggestion) {
			out = append(out, suggestionOf(os.Suggestion))
		}
	}
	return out, nil
}

// imageNotes are an image's coverage notes, plus the read-time note naming the classifier-found
// packages that get daily, CPE-based coverage only. pkgs are its classifier-found packages.
func imageNotes(img model.Image, pkgs []model.Package) []string {
	notes := slices.Clone(img.Coverage.Notes)
	if names := upstream.UncoveredClassified(pkgs); len(names) > 0 {
		notes = append(notes, noteCPE+strings.Join(names, ", "))
	}
	return notes
}

// coverageNotes is the de-duplicated union of an owner's images' coverage notes, plus why any of
// them has no catalogue (not resolved yet, not catalogued yet, unresolvable or failed), so an owner
// whose images were never catalogued does not read as one with no findings.
func (s *Server) coverageNotes(ctx context.Context, o model.Owner) ([]string, error) {
	var notes []string
	add := func(n string) {
		if n != "" && !slices.Contains(notes, n) {
			notes = append(notes, n)
		}
	}
	var digests []string
	for _, c := range o.Containers {
		if c.Digest != "" {
			digests = append(digests, c.Digest)
		}
	}
	classified, err := s.o.Store.ClassifiedPackages(ctx, digests)
	if err != nil {
		return nil, err
	}
	for _, c := range o.Containers {
		if c.Digest == "" {
			add(noteNotResolved + cmp.Or(c.ImageRef, c.Repo, c.Name))
			continue
		}
		img, ok, err := s.o.Store.GetImage(ctx, c.Digest)
		if err != nil {
			return nil, err
		}
		if !ok {
			add(noteNotCatalogued + cmp.Or(c.Repo, c.ImageRef, c.Digest))
			continue
		}
		for _, n := range imageNotes(img, classified[c.Digest]) {
			add(n)
		}
		switch img.Status {
		case model.ImagePending:
			add(noteNotCatalogued + cmp.Or(img.Repo, c.Repo, c.Digest))
		case model.ImageUnresolvable:
			add(cmp.Or(img.StatusReason, "image could not be resolved"))
		case model.ImageCatalogFailed:
			add(cmp.Or(img.StatusReason, "image could not be catalogued"))
		case model.ImageCatalogued:
		}
	}
	return nz(notes), nil
}
