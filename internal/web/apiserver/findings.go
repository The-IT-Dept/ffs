package apiserver

import (
	"cmp"
	"context"
	"slices"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/nodegroup"
	"github.com/the-it-dept/ffs/internal/store"
	"github.com/the-it-dept/ffs/internal/web/apigen"
)

const (
	opListFindings = "listFindings"

	// resolvedWindow is how far back the resolved state reaches (spec §11.4).
	resolvedWindow = 30 * 24 * time.Hour

	maxQLen      = 200
	maxIDLen     = 200
	maxNameLen   = 300
	maxFixKeyLen = 300
)

// findingQuery validates the explorer's parameters into a store query. Without a state filter it
// selects open findings; resolved findings always cover the last 30 days.
func (s *Server) findingQuery(ctx context.Context, p apigen.ListFindingsParams) (store.FindingQuery, error) {
	sc, err := scopeParam(p.Scope)
	if err != nil {
		return store.FindingQuery{}, err
	}
	if sc, err = s.resolveScope(ctx, sc); err != nil {
		return store.FindingQuery{}, err
	}
	states, err := enumParam("state", p.State)
	if err != nil {
		return store.FindingQuery{}, err
	}
	prios, err := enumParam("priority", p.Priority)
	if err != nil {
		return store.FindingQuery{}, err
	}
	fix, err := enumParam("fix", p.Fix)
	if err != nil {
		return store.FindingQuery{}, err
	}
	signals, err := enumParam("signal", p.Signal)
	if err != nil {
		return store.FindingQuery{}, err
	}
	limit, err := limitParam(p.Limit)
	if err != nil {
		return store.FindingQuery{}, err
	}
	sort, err := enumValue("sort", p.Sort)
	if err != nil {
		return store.FindingQuery{}, err
	}
	q := store.FindingQuery{
		Scope: sc, States: []model.FindingState{model.StateOpen}, ResolvedSince: s.o.Now().Add(-resolvedWindow),
		Ecosystems: stringsParam(p.Ecosystem), Namespaces: stringsParam(p.Namespace), Kinds: stringsParam(p.Kind),
		Sort: store.FindingSort(sort), Limit: limit,
	}
	if len(states) > 0 {
		q.States = make([]model.FindingState, len(states))
		for i, v := range states {
			q.States[i] = model.FindingState(v)
		}
	}
	for _, v := range prios {
		q.Priorities = append(q.Priorities, modelPriority(v))
	}
	for _, v := range fix {
		q.Fix = append(q.Fix, model.FixClass(v))
	}
	for _, v := range signals {
		q.Signals = append(q.Signals, model.Signal(v))
	}
	for _, t := range []struct {
		name   string
		p      *string
		maxLen int
		dst    *string
	}{
		{"advisory", p.Advisory, maxIDLen, &q.Advisory}, {"package", p.Package, maxNameLen, &q.Package},
		{"repo", p.Repo, maxNameLen, &q.Repo}, {"fixKey", p.FixKey, maxFixKeyLen, &q.FixKey}, {"q", p.Q, maxQLen, &q.Q},
	} {
		if *t.dst, err = textParam(t.name, t.p, t.maxLen); err != nil {
			return store.FindingQuery{}, err
		}
	}
	if q.After, err = decodeCursor(opListFindings, p, p.Cursor); err != nil {
		return store.FindingQuery{}, err
	}
	return q, nil
}

// ListFindings answers the findings explorer: a flat page or a page of groups, with the requested
// facets counted alongside.
func (s *Server) ListFindings(ctx context.Context, req apigen.ListFindingsRequestObject) (apigen.ListFindingsResponseObject, error) {
	p := req.Params
	q, err := s.findingQuery(ctx, p)
	if err != nil {
		return nil, err
	}
	groupName, err := enumValue("group", p.Group)
	if err != nil {
		return nil, err
	}
	group := store.FindingGroup(groupName)
	names, err := enumParam("facets", p.Facets)
	if err != nil {
		return nil, err
	}
	facets := make([]store.FindingFacet, len(names))
	for i, n := range names {
		facets[i] = store.FindingFacet(n)
	}

	var (
		page   store.FindingPage
		groups store.GroupPage
		counts map[store.FindingFacet][]store.FacetValue
	)
	g, gctx := errgroup.WithContext(ctx)
	if len(facets) > 0 {
		g.Go(func() (err error) {
			counts, err = s.o.Store.FindingFacets(gctx, q, facets)
			return err
		})
	}
	g.Go(func() (err error) {
		if group != "" {
			groups, err = s.o.Store.FindingGroups(gctx, q, group)
		} else {
			page, err = s.o.Store.FindingsPage(gctx, q)
		}
		return err
	})
	if err := g.Wait(); err != nil {
		return nil, err
	}

	cluster, at := s.stamp()
	out := apigen.ListFindings200JSONResponse{Cluster: cluster, GeneratedAt: at, Rows: []apigen.FindingRow{},
		GroupRows: []apigen.FindingGroupRow{}, Facets: findingFacets(q, counts)}
	if group != "" {
		out.Total, out.Groups, out.Findings = groups.Groups, groups.Groups, groups.Findings
		for _, r := range groups.Rows {
			out.GroupRows = append(out.GroupRows, groupRowOf(r, group))
		}
		if group == store.GroupAdvisory {
			if err := s.titleAdvisoryGroups(ctx, out.GroupRows); err != nil {
				return nil, err
			}
		}
		out.Next = encodeCursor(opListFindings, p, groups.Next)
		return out, nil
	}
	out.Total, out.Findings = page.Total, page.Total
	if out.Rows, err = s.findingRows(ctx, page.Rows); err != nil {
		return nil, err
	}
	out.Next = encodeCursor(opListFindings, p, page.Next)
	return out, nil
}

// findingFacets shapes the facet counts, marking the values q selects. The state facet's selection
// is the effective one, so open is selected when no state was asked for.
func findingFacets(q store.FindingQuery, counts map[store.FindingFacet][]store.FacetValue) apigen.Facets {
	selected := map[store.FindingFacet][]string{
		store.FacetState: stringsOf(q.States), store.FacetFix: stringsOf(q.Fix), store.FacetSignal: stringsOf(q.Signals),
		store.FacetEcosystem: q.Ecosystems, store.FacetNamespace: q.Namespaces, store.FacetKind: q.Kinds,
	}
	for _, p := range q.Priorities {
		selected[store.FacetPriority] = append(selected[store.FacetPriority], string(priorityOf(p)))
	}
	out := apigen.Facets{}
	for f, vals := range counts {
		out[string(f)] = facetValues(vals, selected[f])
	}
	for i, v := range out[string(store.FacetKind)] {
		if label, ok := clusterLevelKinds[v.Value]; ok {
			out[string(store.FacetKind)][i].Label = &label
		}
	}
	return out
}

// clusterLevelKinds labels the kind facet values of the cluster-level owners.
var clusterLevelKinds = map[string]string{
	store.ClusterLevelKindPrefix + model.OwnerKindCluster:          "Kubernetes (control plane)",
	store.ClusterLevelKindPrefix + model.OwnerKindContainerRuntime: "Container runtime (control plane)",
	store.ClusterLevelKindPrefix + model.OwnerKindNodes:            "Nodes (host packages)",
}

// facetValues shapes store facet values, in their order, marking the selected ones.
func facetValues(vals []store.FacetValue, selected []string) []apigen.FacetValue {
	out := make([]apigen.FacetValue, 0, len(vals))
	for _, v := range vals {
		out = append(out, apigen.FacetValue{Value: v.Value, Count: v.Count, Selected: slices.Contains(selected, v.Value)})
	}
	return out
}

func stringsOf[T ~string](vs []T) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = string(v)
	}
	return out
}

// findingRows shapes a page of findings, reading their advisories in one call. A host finding names
// the node groups it affects.
func (s *Server) findingRows(ctx context.Context, fs []model.Finding) ([]apigen.FindingRow, error) {
	ids := make([]string, 0, len(fs))
	for _, f := range fs {
		ids = append(ids, f.AdvisoryID)
	}
	advs, err := s.o.Store.Advisories(ctx, ids)
	if err != nil {
		return nil, err
	}
	hostGroups, err := s.hostGroups(ctx, fs)
	if err != nil {
		return nil, err
	}
	out := make([]apigen.FindingRow, 0, len(fs))
	for _, f := range fs {
		adv := advs[f.AdvisoryID]
		row := apigen.FindingRow{
			Id:       f.Fingerprint,
			Advisory: apigen.FindingAdvisory{Id: f.AdvisoryID, Title: adv.Title, Kev: adv.KEVAdded != nil},
			Workload: workloadRef(f.Owner), Repo: f.ImageRepo, Packages: findingPackages(f.Packages),
			Severity: apigen.Severity(f.Severity.String()), SeveritySource: f.SeveritySource, Priority: priorityOf(f.Priority),
			Reasons: nz(f.Reasons), State: apigen.FindingState(f.State), ExceptedBy: optString(f.ExceptedBy),
			FixState: string(f.FixState), FixAvailable: f.FixAvailable, Fix: fixActionOf(f), Signals: signalsOf(f),
			Published: optTime(f.Published), Observed: optTime(f.Observed), Matched: optTime(f.Matched),
		}
		if adv.EPSS != 0 || adv.EPSSPercentile != 0 {
			epss := adv.EPSS
			row.Advisory.Epss = &epss
		}
		if f.ResolvedAt != nil {
			row.ResolvedAt = optTime(*f.ResolvedAt)
		}
		if isHostFinding(f) {
			groups := nz(hostGroups[f.Fingerprint])
			row.NodeGroups = &groups
		}
		out = append(out, row)
	}
	return out, nil
}

// isHostFinding reports whether f is on a node's host packages: its owner is the Nodes owner.
func isHostFinding(f model.Finding) bool {
	return f.Owner.Kind == model.OwnerKindNodes && f.Owner.Namespace == ""
}

// groupVersion is one installed version of a FindingNodeGroup.
type groupVersion = struct {
	Package string `json:"package"`
	Version string `json:"version"`
}

// hostGroups lists, per host finding of fs by fingerprint, the current node groups whose host
// packages it is on (its nodegroup: digests), by label: each by its key, with its member count and
// the installed versions of the finding's packages there. A group that no longer has members is
// left out.
func (s *Server) hostGroups(ctx context.Context, fs []model.Finding) (map[string][]apigen.FindingNodeGroup, error) {
	out := map[string][]apigen.FindingNodeGroup{}
	var (
		digests []string
		names   []store.PackageName
	)
	for _, f := range fs {
		if !isHostFinding(f) {
			continue
		}
		for _, d := range f.Digests {
			if _, ok := nodegroup.IDFromDigest(d); ok && !slices.Contains(digests, d) {
				digests = append(digests, d)
			}
		}
		for _, p := range f.Packages {
			if n := (store.PackageName{Ecosystem: p.Ecosystem, Name: p.Name}); !slices.Contains(names, n) {
				names = append(names, n)
			}
		}
	}
	if len(digests) == 0 {
		return out, nil
	}
	gs, err := s.groupSet(ctx)
	if err != nil {
		return nil, err
	}
	versions, err := s.o.Store.InstalledVersions(ctx, digests, names)
	if err != nil {
		return nil, err
	}
	for _, f := range fs {
		if !isHostFinding(f) {
			continue
		}
		var groups []apigen.FindingNodeGroup
		for _, d := range f.Digests {
			id, ok := nodegroup.IDFromDigest(d)
			if !ok {
				continue
			}
			g, ok := gs.byID(id)
			if !ok || slices.ContainsFunc(groups, func(x apigen.FindingNodeGroup) bool { return x.Id == gs.key(g) }) {
				continue
			}
			fg := apigen.FindingNodeGroup{Id: gs.key(g), Label: g.Label, Nodes: len(g.Members), Versions: []groupVersion{}}
			for _, v := range versions[d] {
				if slices.ContainsFunc(f.Packages, func(p model.FindingPackage) bool { return p.Ecosystem == v.Ecosystem && p.Name == v.Name }) {
					fg.Versions = append(fg.Versions, groupVersion{Package: v.Name, Version: v.Version})
				}
			}
			groups = append(groups, fg)
		}
		slices.SortFunc(groups, func(a, b apigen.FindingNodeGroup) int { return strings.Compare(a.Label, b.Label) })
		out[f.Fingerprint] = groups
	}
	return out, nil
}

// mergeHostGroups merges the node groups of several host findings: each group once, with the union
// of their installed versions, by package and version; groups by label.
func mergeHostGroups(byFinding map[string][]apigen.FindingNodeGroup) []apigen.FindingNodeGroup {
	out := []apigen.FindingNodeGroup{}
	for _, groups := range byFinding {
		for _, g := range groups {
			i := slices.IndexFunc(out, func(x apigen.FindingNodeGroup) bool { return x.Id == g.Id })
			if i < 0 {
				out = append(out, apigen.FindingNodeGroup{Id: g.Id, Label: g.Label, Nodes: g.Nodes, Versions: []groupVersion{}})
				i = len(out) - 1
			}
			for _, v := range g.Versions {
				if !slices.Contains(out[i].Versions, v) {
					out[i].Versions = append(out[i].Versions, v)
				}
			}
		}
	}
	for i := range out {
		slices.SortFunc(out[i].Versions, func(a, b groupVersion) int {
			return cmp.Or(strings.Compare(a.Package, b.Package), strings.Compare(a.Version, b.Version))
		})
	}
	slices.SortFunc(out, func(a, b apigen.FindingNodeGroup) int { return strings.Compare(a.Label, b.Label) })
	return out
}

// groupRowOf shapes a group of findings. The store labels every group with its key; the label here
// is what the UI shows: the fix action's label for fix groups, "<namespace>/<name>" for workloads,
// "<name> <version>" for packages, and the key (repository, namespace, advisory ID) otherwise.
func groupRowOf(r store.GroupRow, g store.FindingGroup) apigen.FindingGroupRow {
	out := apigen.FindingGroupRow{Key: r.Key, Label: r.Label, Findings: r.Findings, Distinct: r.Distinct,
		Counts: priorityCounts(r.Counts), Fixable: r.Fixable, Exploited: r.Exploited, Worst: priorityOf(r.Worst)}
	switch g {
	case store.GroupFix:
		if r.Sample != nil {
			fix := fixActionOf(*r.Sample)
			out.Label, out.Fix = fix.Label, &fix
		}
	case store.GroupWorkload:
		if ref, ok := (model.Scope{Kind: model.ScopeWorkload, Value: r.Key}).Owner(); ok {
			out.Label = strings.TrimPrefix(ref.Namespace+"/"+ref.Name, "/")
		}
	case store.GroupPackage:
		if eco, name, version, ok := parsePackageKey(r.Key); ok && eco != "" {
			out.Label = name + " " + version
		}
	case store.GroupAdvisory, store.GroupImage, store.GroupNamespace:
	}
	return out
}

// parsePackageKey splits a package group key, "<ecosystem>/<name>@<version>". The ecosystem holds no
// slash and the version no @, while a name may hold either (github.com/a/b, @scope/pkg).
func parsePackageKey(key string) (ecosystem, name, version string, ok bool) {
	ecosystem, rest, ok := strings.Cut(key, "/")
	if !ok {
		return "", "", "", false
	}
	i := strings.LastIndex(rest, "@")
	if i <= 0 {
		return "", "", "", false
	}
	return ecosystem, rest[:i], rest[i+1:], true
}

// titleAdvisoryGroups labels advisory groups with their advisory's title, where it has one.
func (s *Server) titleAdvisoryGroups(ctx context.Context, rows []apigen.FindingGroupRow) error {
	ids := make([]string, len(rows))
	for i, r := range rows {
		ids[i] = r.Key
	}
	advs, err := s.o.Store.Advisories(ctx, ids)
	if err != nil {
		return err
	}
	for i := range rows {
		if a, ok := advs[rows[i].Key]; ok && a.Title != "" {
			rows[i].Label = a.Title
		}
	}
	return nil
}
