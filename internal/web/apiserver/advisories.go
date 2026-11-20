package apiserver

import (
	"context"
	"maps"
	"slices"

	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
	"github.com/the-it-dept/ffs/internal/web/apigen"
)

// GetAdvisory is an advisory with its severity by source, exploitation data, timeline, the open
// findings it causes grouped by the action that clears them, and the packages it affects.
func (s *Server) GetAdvisory(ctx context.Context, req apigen.GetAdvisoryRequestObject) (apigen.GetAdvisoryResponseObject, error) {
	id, err := s.o.Store.Canonical(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	adv, ok, err := s.o.Store.GetAdvisory(ctx, id)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, notFound("advisory " + req.Id + " not found")
	}
	id = adv.ID

	severities, err := s.advisorySeverities(ctx, adv)
	if err != nil {
		return nil, err
	}
	firstMatched, err := s.o.Store.AdvisoryFirstMatched(ctx, id)
	if err != nil {
		return nil, err
	}
	byAdvisory, err := s.o.Store.FindingGroups(ctx, store.FindingQuery{Advisory: id}, store.GroupAdvisory)
	if err != nil {
		return nil, err
	}
	byFix, err := s.o.Store.FindingGroups(ctx, store.FindingQuery{Advisory: id, Limit: maxLimit}, store.GroupFix)
	if err != nil {
		return nil, err
	}
	packages, hostFindings, err := s.advisoryPackages(ctx, id)
	if err != nil {
		return nil, err
	}
	hostGroups, err := s.hostGroups(ctx, hostFindings)
	if err != nil {
		return nil, err
	}
	nodeGroups := mergeHostGroups(hostGroups)
	cov, err := s.o.Store.CoverageOf(ctx, model.Scope{Kind: model.ScopeCluster})
	if err != nil {
		return nil, err
	}

	cluster, at := s.stamp()
	out := apigen.GetAdvisory200JSONResponse{
		Cluster: cluster, GeneratedAt: at, Id: id, Aliases: nz(adv.Aliases), Title: adv.Title, Links: nz(adv.Links),
		Malicious: adv.Malicious, Withdrawn: adv.Withdrawn, Severities: severities,
		Timeline: apigen.AdvisoryTimeline{Published: optTime(adv.Published), Observed: optTime(adv.Observed), FirstMatched: optTime(firstMatched)},
		ByFix:    make([]apigen.FindingGroupRow, 0, len(byFix.Rows)), Packages: packages, Uncatalogued: cov.InUse - cov.SeenInto,
		NodeGroups: &nodeGroups,
	}
	if adv.KEVAdded != nil {
		out.Kev = &apigen.KevInfo{Added: openapi_types.Date{Time: adv.KEVAdded.UTC()}}
	}
	if adv.EPSS != 0 || adv.EPSSPercentile != 0 {
		out.Epss = &apigen.EpssInfo{Score: adv.EPSS, Percentile: adv.EPSSPercentile}
	}
	if len(byAdvisory.Rows) > 0 {
		r := byAdvisory.Rows[0]
		out.Counts, out.Workloads, out.Findings = priorityCounts(r.Counts), r.Distinct, r.Findings
	}
	for _, r := range byFix.Rows {
		out.ByFix = append(out.ByFix, groupRowOf(r, store.GroupFix))
	}
	return out, nil
}

// advisorySeverities lists the severity each source gives the advisory: the vendors of its matches,
// then its CNA, then its OSV records. The one its open findings were ranked with is marked used.
func (s *Server) advisorySeverities(ctx context.Context, adv model.Advisory) ([]apigen.SourceSeverity, error) {
	vendors, err := s.o.Store.AdvisorySeverities(ctx, adv.ID)
	if err != nil {
		return nil, err
	}
	used, err := s.o.Store.AdvisorySeverityUsed(ctx, adv.ID)
	if err != nil {
		return nil, err
	}
	out := []apigen.SourceSeverity{}
	add := func(source string, sev model.Severity) {
		out = append(out, apigen.SourceSeverity{Source: source, Severity: apigen.Severity(sev.String()), Used: source == used})
	}
	for _, v := range vendors {
		add(v.Source, v.Severity)
	}
	if adv.CNASeverity != model.SeverityUnknown {
		source := adv.CNASource
		if source == "" {
			source = "cna"
		}
		add(source, adv.CNASeverity)
	}
	if adv.OSVSeverity != model.SeverityUnknown {
		add("osv", adv.OSVSeverity)
	}
	return out, nil
}

// advisoryPackages lists the package versions the advisory's open findings are on, with the fixed
// versions its open and excepted findings name, and returns its open host findings. It reads every
// one of those findings: they come in priority order, so a single page would drop the fixed
// versions of lower-priority packages.
func (s *Server) advisoryPackages(ctx context.Context, id string) ([]apigen.AdvisoryPackage, []model.Finding, error) {
	groups, err := s.o.Store.FindingGroups(ctx, store.FindingQuery{Advisory: id, Limit: maxLimit}, store.GroupPackage)
	if err != nil {
		return nil, nil, err
	}
	var host []model.Finding
	type pkgKey struct{ ecosystem, name, installed string }
	fixed := map[pkgKey]map[string]bool{}
	q := store.FindingQuery{Advisory: id, States: []model.FindingState{model.StateOpen, model.StateExcepted}, Limit: maxLimit}
	for {
		page, err := s.o.Store.FindingsPage(ctx, q)
		if err != nil {
			return nil, nil, err
		}
		for _, f := range page.Rows {
			if f.State == model.StateOpen && isHostFinding(f) {
				host = append(host, f)
			}
			for _, p := range f.Packages {
				k := pkgKey{p.Ecosystem, p.Name, p.Installed}
				for _, v := range p.Fixed {
					if fixed[k] == nil {
						fixed[k] = map[string]bool{}
					}
					fixed[k][v] = true
				}
			}
		}
		if page.Next == "" {
			break
		}
		q.After = page.Next
	}
	out := make([]apigen.AdvisoryPackage, 0, len(groups.Rows))
	for _, r := range groups.Rows {
		eco, name, version, ok := parsePackageKey(r.Key)
		if !ok {
			continue
		}
		fx := slices.Sorted(maps.Keys(fixed[pkgKey{eco, name, version}]))
		out = append(out, apigen.AdvisoryPackage{Name: name, Ecosystem: eco, Installed: version, Fixed: nz(fx), Findings: r.Findings})
	}
	return out, host, nil
}
