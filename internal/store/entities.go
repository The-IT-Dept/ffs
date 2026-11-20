package store

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/the-it-dept/ffs/internal/model"
)

// The entity explorers: workloads, images and packages, each counting entities, clean, pending and
// unresolvable ones included. Workloads are the namespaced owners; the cluster-level and node owners
// are shown under control plane and nodes.

// OwnerEntity is an owner as the explorers list it.
type OwnerEntity struct {
	Key, Kind, Namespace, Name string
	ManagedBy                  string           // ManagedBy.Tool ("" when none)
	Managed                    *model.ManagedBy // the full ManagedBy; nil when none
	Exposed, Privileged        bool
	PowerfulSA, NotRunning     bool
}

// The owner_entities view (052) carries no data column, so the full ManagedBy comes from a join.
const (
	ownerEntityFrom = `owner_entities e JOIN owners o ON o.key = e.key`
	ownerEntityCols = `e.key, e.kind, e.namespace, e.name, e.managed_by, json_extract(o.data, '$.ManagedBy'),
	e.exposed, e.privileged, e.sa_power, e.not_running`
)

// ownerEntityDest returns scan destinations for ownerEntityCols into e, and a function that
// finishes e once scanned.
func ownerEntityDest(e *OwnerEntity) ([]any, func() error) {
	var managed sql.NullString
	return []any{&e.Key, &e.Kind, &e.Namespace, &e.Name, &e.ManagedBy, &managed, &e.Exposed, &e.Privileged, &e.PowerfulSA, &e.NotRunning},
		func() error {
			if !managed.Valid {
				return nil
			}
			e.Managed = &model.ManagedBy{}
			if err := json.Unmarshal([]byte(managed.String), e.Managed); err != nil {
				return fmt.Errorf("owner %s managed by: %w", e.Key, err)
			}
			return nil
		}
}

// scanOwnerEntity reads ownerEntityCols.
func scanOwnerEntity(r scanner) (OwnerEntity, error) {
	var e OwnerEntity
	dest, done := ownerEntityDest(&e)
	if err := r.Scan(dest...); err != nil {
		return OwnerEntity{}, err
	}
	return e, done()
}

// containerDigest selects the container image digests of col: not the synthetic Kubernetes and
// runtime digests, nor a node group's host packages.
func containerDigest(col string) string {
	return `NOT (` + col + ` LIKE 'k8s:%' OR ` + col + ` LIKE 'runtime:%' OR ` + col + ` LIKE 'nodegroup:%')`
}

// installedExpr is model.Package.Installed in SQL over the packages row aliased a: the version with
// its epoch, unless the version already carries it. It joins finding_packages.version.
func installedExpr(a string) string {
	return `CASE WHEN ` + a + `.epoch = '' OR substr(` + a + `.version, 1, length(` + a + `.epoch) + 1) = ` + a + `.epoch || ':'
		THEN ` + a + `.version ELSE ` + a + `.epoch || ':' || ` + a + `.version END`
}

// ownerCoverageCTE is owner_cov: each owner's distinct in-use container digests, those seen into
// (catalogued and matched) and those seen into in full detail.
var ownerCoverageCTE = `owner_cov(owner_key, in_use, seen_into, cov_full) AS (SELECT oi.owner_key, count(DISTINCT oi.digest),
		count(DISTINCT CASE WHEN ` + seenSQL("i", "oi.digest") + ` THEN oi.digest END),
		count(DISTINCT CASE WHEN ` + fullSQL("i", "oi.digest") + ` THEN oi.digest END)
		FROM owner_images oi LEFT JOIN images i ON i.digest = oi.digest WHERE ` + containerDigest("oi.digest") + ` GROUP BY oi.owner_key)`

// coverageClass is the class of a coverage figure: none when nothing is seen into, full when every
// in-use image is seen into in full detail, else partial. coverageClassSQL mirrors it.
func coverageClass(c CoverageFigure) model.CoverageClass {
	switch {
	case c.SeenInto == 0:
		return model.CoverageNone
	case c.Full == c.InUse:
		return model.CoverageFull
	}
	return model.CoveragePartial
}

// coverageClassSQL is coverageClass over the in_use, seen_into and cov_full columns.
const coverageClassSQL = `CASE WHEN seen_into = 0 THEN 'none' WHEN cov_full = in_use THEN 'full' ELSE 'partial' END`

// worstSQL is the worst priority of the urgent, high, medium and low counts, 0 when all are zero.
const worstSQL = `CASE WHEN urgent > 0 THEN 4 WHEN high > 0 THEN 3 WHEN medium > 0 THEN 2 WHEN low > 0 THEN 1 ELSE 0 END`

// priorityValues are the values of an entity priority facet, PriorityNone as "none".
var priorityValues = []string{"urgent", "high", "medium", "low", priorityNoneValue}

// worstName is the SQL of a worst column's facet value.
const worstName = `CASE worst WHEN 4 THEN 'urgent' WHEN 3 THEN 'high' WHEN 2 THEN 'medium' WHEN 1 THEN 'low' ELSE 'none' END`

// worstArgs binds worst priorities: PriorityNone is worst = 0.
func worstArgs(ps []model.Priority) []any {
	out := make([]any, len(ps))
	for i, p := range ps {
		out[i] = int(p)
	}
	return out
}

// likePrefix is a LIKE ... ESCAPE '\' pattern matching values that start with q.
func likePrefix(q string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(q) + "%"
}

// enumFacet lists every value of an enumerated facet with its count, zero counts included.
func enumFacet(values []string, counts map[string]int) []FacetValue {
	out := make([]FacetValue, len(values))
	for i, v := range values {
		out[i] = FacetValue{Value: v, Count: counts[v]}
	}
	return sortFacet(out)
}

// facetQuery runs a (value, count) statement into a counts map.
func (s *Store) facetQuery(ctx context.Context, query string, args []any) (map[string]int, error) {
	counts := map[string]int{}
	return counts, s.facetCounts(ctx, stmt{query: query, args: args}, counts)
}

// --- workloads

// WorkloadSort orders the workloads explorer.
type WorkloadSort string

const (
	WorkloadRisk      WorkloadSort = "-risk"     // urgent DESC, high DESC, fixable DESC, key
	WorkloadName      WorkloadSort = "name"      // name, key
	WorkloadNamespace WorkloadSort = "namespace" // namespace, name, key
	WorkloadFindings  WorkloadSort = "-findings" // open DESC, key
)

var workloadSorts = map[WorkloadSort][]keyCol{
	WorkloadRisk:      {{"urgent", true, kindInt}, {"high", true, kindInt}, {"fixable", true, kindInt}, {"key", false, kindString}},
	WorkloadName:      {{"name", false, kindString}, {"key", false, kindString}},
	WorkloadNamespace: {{"namespace", false, kindString}, {"name", false, kindString}, {"key", false, kindString}},
	WorkloadFindings:  {{"open", true, kindInt}, {"key", false, kindString}},
}

// WorkloadQuery selects workloads. Empty fields match everything.
type WorkloadQuery struct {
	Scope      model.Scope // cluster | namespace
	Kinds      []string
	Namespaces []string
	Signals    []model.Signal        // exposed | privileged | sa_power | not_running (owner_entities columns); others ignored
	Worst      []model.Priority      // worst open priority; model.PriorityNone = no open finding (worst = 0)
	Coverage   []model.CoverageClass // full = every in-use image full; none = no image seen into; partial otherwise
	Q          string                // substring of name or namespace
	Sort       WorkloadSort          // "" = WorkloadRisk
	After      string
	Limit      int
}

// WorkloadRow is one workload with its rollup counts and coverage.
type WorkloadRow struct {
	Owner    OwnerEntity
	Stats    OwnerStats
	Coverage CoverageFigure
	Class    model.CoverageClass
}

// WorkloadPage is one page of workloads; Total counts every workload q matches, ignoring After.
type WorkloadPage struct {
	Rows  []WorkloadRow
	Next  string
	Total int
}

// workloadSignalCols are the owner_entities columns of the workload signals.
var workloadSignalCols = map[model.Signal]string{model.SignalExposed: "exposed", model.SignalPrivileged: "privileged",
	model.SignalSAPower: "sa_power", model.SignalNotRunning: "not_running"}

// workloadSignals are the workload signal facet's values, in model.Signals order.
var workloadSignals = []model.Signal{model.SignalExposed, model.SignalPrivileged, model.SignalSAPower, model.SignalNotRunning}

// workloadsCTE is wl: every workload owner with its entity columns, rollup counts, coverage figure,
// worst open priority and coverage class.
var workloadsCTE = `WITH ` + ownerCoverageCTE + `,
	wl0(key, kind, namespace, name, managed_by, managed, exposed, privileged, sa_power, not_running, ` + ownerStatsCols + `,
		in_use, seen_into, cov_full) AS (SELECT ` + ownerEntityCols + `, ` + prefixedCols("coalesce(st.", ownerStatsCols, ", 0)") + `,
		coalesce(c.in_use, 0), coalesce(c.seen_into, 0), coalesce(c.cov_full, 0)
		FROM ` + ownerEntityFrom + ` LEFT JOIN owner_stats st ON st.owner_key = e.key LEFT JOIN owner_cov c ON c.owner_key = e.key
		WHERE e.namespace != ''),
	wl AS (SELECT *, ` + worstSQL + ` AS worst, ` + coverageClassSQL + ` AS wclass FROM wl0)`

// workloadWhere returns q's predicates over wl, without facet omit's selection.
func workloadWhere(q WorkloadQuery, omit string) (where, error) {
	var w where
	switch q.Scope.Kind {
	case model.ScopeCluster, "":
	case model.ScopeNamespace:
		w.add(`namespace = ?`, q.Scope.Value)
	default:
		return where{}, scopeErr(q.Scope)
	}
	if omit != "kind" && len(q.Kinds) > 0 {
		w.add(inCond("kind", len(q.Kinds)), anys(q.Kinds)...)
	}
	if omit != "namespace" && len(q.Namespaces) > 0 {
		w.add(inCond("namespace", len(q.Namespaces)), anys(q.Namespaces)...)
	}
	if omit != "signal" {
		for _, sg := range q.Signals {
			if col, ok := workloadSignalCols[sg]; ok {
				w.add(col + ` = 1`)
			}
		}
	}
	if omit != "priority" && len(q.Worst) > 0 {
		w.add(inCond("worst", len(q.Worst)), worstArgs(q.Worst)...)
	}
	if omit != "coverage" && len(q.Coverage) > 0 {
		w.add(inCond("wclass", len(q.Coverage)), anys(q.Coverage)...)
	}
	if q.Q != "" {
		pat := likePattern(q.Q)
		w.add(`(name LIKE ? ESCAPE '\' OR namespace LIKE ? ESCAPE '\')`, pat, pat)
	}
	return w, nil
}

// WorkloadsPage returns one keyset page of the workloads q matches: the owners with a namespace,
// with or without findings.
func (s *Store) WorkloadsPage(ctx context.Context, q WorkloadQuery) (WorkloadPage, error) {
	sort := cmp.Or(q.Sort, WorkloadRisk)
	cols, ok := workloadSorts[sort]
	if !ok {
		return WorkloadPage{}, fmt.Errorf("store: unknown workload sort %q", sort)
	}
	tag := "workloads:" + string(sort)
	after, err := decodeCursor(q.After, tag, cols)
	if err != nil {
		return WorkloadPage{}, err
	}
	w, err := workloadWhere(q, "")
	if err != nil {
		return WorkloadPage{}, err
	}
	var page WorkloadPage
	if err := s.rdb.QueryRowContext(ctx, workloadsCTE+` SELECT count(*) FROM wl`+w.String(), w.args...).Scan(&page.Total); err != nil {
		return WorkloadPage{}, fmt.Errorf("store: count workloads: %w", err)
	}
	if after != nil {
		cond, args := keysetAfter(cols, after)
		w.add(cond, args...)
	}
	limit := clampLimit(q.Limit)
	rows, err := s.rdb.QueryContext(ctx, workloadsCTE+` SELECT `+tupleExprs(cols)+`, key, kind, namespace, name, managed_by, managed,
		exposed, privileged, sa_power, not_running, in_use, seen_into, cov_full, `+ownerStatsCols+` FROM wl`+w.String()+orderBy(cols)+` LIMIT ?`,
		append(w.args, limit+1)...)
	if err != nil {
		return WorkloadPage{}, fmt.Errorf("store: workloads page: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var last []any
	for rows.Next() {
		if len(page.Rows) == limit {
			page.Next = encodeCursor(tag, last)
			break
		}
		tuple, values := tupleDest(cols)
		var r WorkloadRow
		owner, done := ownerEntityDest(&r.Owner)
		lead := slices.Concat(tuple, owner, []any{&r.Coverage.InUse, &r.Coverage.SeenInto, &r.Coverage.Full})
		if r.Stats, err = scanOwnerStats(rows, lead...); err != nil {
			return WorkloadPage{}, err
		}
		if err := done(); err != nil {
			return WorkloadPage{}, err
		}
		r.Class = coverageClass(r.Coverage)
		page.Rows = append(page.Rows, r)
		last = values()
	}
	return page, rows.Err()
}

// WorkloadFacets counts workloads by kind, namespace, signal, priority (worst open) and coverage,
// each under q minus its own selection.
func (s *Store) WorkloadFacets(ctx context.Context, q WorkloadQuery, facets []string) (map[string][]FacetValue, error) {
	out := make(map[string][]FacetValue, len(facets))
	for _, f := range facets {
		w, err := workloadWhere(q, f)
		if err != nil {
			return nil, err
		}
		var query string
		switch f {
		case "kind", "namespace":
			query = `SELECT ` + f + `, count(*) FROM wl` + w.String() + ` GROUP BY ` + f
		case "priority":
			query = `SELECT ` + worstName + `, count(*) FROM wl` + w.String() + ` GROUP BY worst`
		case "coverage":
			query = `SELECT wclass, count(*) FROM wl` + w.String() + ` GROUP BY wclass`
		case "signal":
			sums, unpivot := make([]string, len(workloadSignals)), make([]string, len(workloadSignals))
			for i, sg := range workloadSignals {
				sums[i] = fmt.Sprintf("sum(%s = 1) AS s%d", workloadSignalCols[sg], i)
				unpivot[i] = fmt.Sprintf("SELECT '%s', s%d FROM s", sg, i)
			}
			query = `, s AS MATERIALIZED (SELECT ` + strings.Join(sums, ", ") + ` FROM wl` + w.String() + `) ` + strings.Join(unpivot, " UNION ALL ")
		default:
			return nil, fmt.Errorf("store: unknown workload facet %q", f)
		}
		if f != "signal" {
			query = ` ` + query
		}
		counts, err := s.facetQuery(ctx, workloadsCTE+query, w.args)
		if err != nil {
			return nil, fmt.Errorf("store: workload %s facet: %w", f, err)
		}
		switch f {
		case "kind":
			out[f] = openFacet(counts, q.Kinds, 0)
		case "namespace":
			out[f] = openFacet(counts, q.Namespaces, 0)
		case "priority":
			out[f] = enumFacet(priorityValues, counts)
		case "coverage":
			out[f] = enumFacet(coverageValues, counts)
		case "signal":
			out[f] = enumFacet(anyStrings(workloadSignals), counts)
		}
	}
	return out, nil
}

// coverageValues are the values of a coverage facet.
var coverageValues = []string{string(model.CoverageFull), string(model.CoveragePartial), string(model.CoverageNone)}

func anyStrings[T ~string](vs []T) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = string(v)
	}
	return out
}

// --- images

// ImageSort orders the images explorer.
type ImageSort string

const (
	ImageRisk      ImageSort = "-risk"      // urgent DESC, high DESC, fixable DESC, digest
	ImageRepoSort  ImageSort = "repo"       // repo, digest
	ImageWorkloads ImageSort = "-workloads" // workloads DESC, digest
)

var imageSorts = map[ImageSort][]keyCol{
	ImageRisk:      {{"urgent", true, kindInt}, {"high", true, kindInt}, {"fixable", true, kindInt}, {"digest", false, kindString}},
	ImageRepoSort:  {{"repo", false, kindString}, {"digest", false, kindString}},
	ImageWorkloads: {{"workloads", true, kindInt}, {"digest", false, kindString}},
}

// ImageQuery selects in-use container images. Empty fields match everything.
type ImageQuery struct {
	Scope      model.Scope // cluster | namespace | workload
	Statuses   []model.ImageStatus
	Sources    []string
	Coverage   []model.CoverageClass
	Namespaces []string
	Worst      []model.Priority
	Q          string    // substring of repo, or digest prefix
	Sort       ImageSort // "" = ImageRisk
	After      string
	Limit      int
}

// ImageRow is one in-use container image. Workloads, Counts and Fixable count the owners in scope
// and their open findings on the digest.
type ImageRow struct {
	Image     model.Image // Status pending and Repo from the container when no images row exists
	Workloads int
	Counts    PriorityCounts
	Fixable   int
	Class     model.CoverageClass
}

// ImagePage is one page of images; Total counts every image q matches, ignoring After.
type ImagePage struct {
	Rows  []ImageRow
	Next  string
	Total int
}

// imagesCTE is im: one row per in-use container digest of the owners in q's scope and namespaces,
// with its image columns (pending, and repo and platform from the container, without an images
// row), the owners running it and their open findings on it. A catalogued image whose first match
// has not run yet reads as pending, not seen into.
func imagesCTE(q ImageQuery) (string, []any, error) {
	var w where
	w.add(containerDigest("oi.digest"))
	switch q.Scope.Kind {
	case model.ScopeCluster, "":
	case model.ScopeNamespace:
		w.add(`o.namespace = ?`, q.Scope.Value)
	case model.ScopeWorkload:
		w.add(`oi.owner_key = ?`, q.Scope.Value)
	default:
		return "", nil, scopeErr(q.Scope)
	}
	if len(q.Namespaces) > 0 {
		w.add(inCond("o.namespace", len(q.Namespaces)), anys(q.Namespaces)...)
	}
	// Counts read finding_digests alone when every owner counts, else only the owners in inuse: from
	// each (digest, owner) of inuse to the owner's findings and their row for that digest, so only the
	// scope's findings are read.
	counts := `SELECT fd.digest, sum(fd.priority = 4) AS u, sum(fd.priority = 3) AS h, sum(fd.priority = 2) AS m, sum(fd.priority = 1) AS l,
		sum(fd.fix_available) AS fx FROM finding_digests fd WHERE fd.state = 'open' AND fd.digest IN (SELECT digest FROM inuse) GROUP BY fd.digest`
	if q.Scope.Kind == model.ScopeNamespace || q.Scope.Kind == model.ScopeWorkload || len(q.Namespaces) > 0 {
		counts = `SELECT fd.digest, sum(fd.priority = 4) AS u, sum(fd.priority = 3) AS h, sum(fd.priority = 2) AS m, sum(fd.priority = 1) AS l,
			sum(fd.fix_available) AS fx FROM inuse u CROSS JOIN findings f ON f.owner_key = u.owner_key
			CROSS JOIN finding_digests fd ON fd.fingerprint = f.fingerprint AND fd.digest = u.digest WHERE fd.state = 'open' GROUP BY fd.digest`
	}
	container := func(field string) string {
		return `(SELECT json_extract(c.value, '$.` + field + `') FROM owners o2, json_each(o2.data, '$.Containers') c
			WHERE o2.key = d.any_owner AND json_extract(c.value, '$.Digest') = d.digest LIMIT 1)`
	}
	cte := `WITH inuse AS (SELECT DISTINCT oi.digest, oi.owner_key, o.namespace FROM owner_images oi JOIN owners o ON o.key = oi.owner_key` +
		w.String() + `),
	d AS (SELECT digest, count(DISTINCT owner_key) AS workloads, min(owner_key) AS any_owner FROM inuse GROUP BY digest),
	cnt AS (` + counts + `),
	im0 AS (SELECT d.digest, d.workloads, coalesce(i.index_digest, '') AS index_digest,
		coalesce(i.repo, ` + container("Repo") + `, '') AS repo, coalesce(i.platform, ` + container("Platform") + `, '') AS platform,
		CASE WHEN i.status = 'catalogued' AND NOT ` + matchedSQL("d.digest") + ` THEN 'pending' ELSE coalesce(i.status, 'pending') END AS status,
		coalesce(i.status_reason, '') AS status_reason, coalesce(i.source, '') AS source,
		coalesce(i.version_annotation, '') AS version_annotation, coalesce(i.config_user, '') AS config_user,
		coalesce(i.coverage, '{}') AS coverage, i.catalogued_at AS catalogued_at, coalesce(i.attempts, 0) AS attempts,
		i.quarantined_until AS quarantined_until,
		CASE WHEN ` + matchedSQL("d.digest") + ` THEN coalesce(i.cov_class, 'none') ELSE 'none' END AS cov,
		coalesce(c.u, 0) AS urgent, coalesce(c.h, 0) AS high, coalesce(c.m, 0) AS medium, coalesce(c.l, 0) AS low, coalesce(c.fx, 0) AS fixable
		FROM d LEFT JOIN images i ON i.digest = d.digest LEFT JOIN cnt c ON c.digest = d.digest),
	im AS (SELECT *, ` + worstSQL + ` AS worst FROM im0)`
	return cte, w.args, nil
}

// imageWhere returns q's predicates over im, without facet omit's selection (the namespaces are
// applied by imagesCTE).
func imageWhere(q ImageQuery, omit string) where {
	var w where
	if omit != "status" && len(q.Statuses) > 0 {
		w.add(inCond("status", len(q.Statuses)), anys(q.Statuses)...)
	}
	if omit != "source" && len(q.Sources) > 0 {
		w.add(inCond("source", len(q.Sources)), anys(q.Sources)...)
	}
	if omit != "coverage" && len(q.Coverage) > 0 {
		w.add(inCond("cov", len(q.Coverage)), anys(q.Coverage)...)
	}
	if omit != "priority" && len(q.Worst) > 0 {
		w.add(inCond("worst", len(q.Worst)), worstArgs(q.Worst)...)
	}
	if q.Q != "" {
		w.add(`(repo LIKE ? ESCAPE '\' OR digest LIKE ? ESCAPE '\')`, likePattern(q.Q), likePrefix(q.Q))
	}
	return w
}

// ImagesPage returns one keyset page of the in-use container images q matches, with or without
// an images row.
func (s *Store) ImagesPage(ctx context.Context, q ImageQuery) (ImagePage, error) {
	sort := cmp.Or(q.Sort, ImageRisk)
	cols, ok := imageSorts[sort]
	if !ok {
		return ImagePage{}, fmt.Errorf("store: unknown image sort %q", sort)
	}
	tag := "images:" + string(sort)
	after, err := decodeCursor(q.After, tag, cols)
	if err != nil {
		return ImagePage{}, err
	}
	cte, cteArgs, err := imagesCTE(q)
	if err != nil {
		return ImagePage{}, err
	}
	w := imageWhere(q, "")
	var kw where
	if after != nil {
		cond, args := keysetAfter(cols, after)
		kw.add(cond, args...)
	}
	limit := clampLimit(q.Limit)
	// The total is counted before the keyset predicate, in the same evaluation of im as the page.
	rows, err := s.rdb.QueryContext(ctx, cte+`, pg AS (SELECT *, count(*) OVER () AS total FROM im`+w.String()+`)
		SELECT `+tupleExprs(cols)+`, total, `+imageCols+`, workloads, urgent, high, medium, low, fixable, cov
		FROM pg`+kw.String()+orderBy(cols)+` LIMIT ?`,
		slices.Concat(cteArgs, w.args, kw.args, []any{limit + 1})...)
	if err != nil {
		return ImagePage{}, fmt.Errorf("store: images page: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var (
		page ImagePage
		last []any
	)
	for rows.Next() {
		if len(page.Rows) == limit {
			page.Next = encodeCursor(tag, last)
			break
		}
		tuple, values := tupleDest(cols)
		var (
			r   ImageRow
			cls string
		)
		img := &imageScan{}
		dest := slices.Concat(tuple, []any{&page.Total}, img.dest(), []any{&r.Workloads, &r.Counts.Urgent, &r.Counts.High,
			&r.Counts.Medium, &r.Counts.Low, &r.Fixable, &cls})
		if err := rows.Scan(dest...); err != nil {
			return ImagePage{}, err
		}
		if r.Image, err = img.image(); err != nil {
			return ImagePage{}, err
		}
		r.Class = model.CoverageClass(cls)
		page.Rows = append(page.Rows, r)
		last = values()
	}
	if err := rows.Err(); err != nil {
		return ImagePage{}, err
	}
	if len(page.Rows) == 0 && after != nil { // past the last row: count apart
		if err := s.rdb.QueryRowContext(ctx, cte+` SELECT count(*) FROM im`+w.String(), slices.Concat(cteArgs, w.args)...).
			Scan(&page.Total); err != nil {
			return ImagePage{}, fmt.Errorf("store: count images: %w", err)
		}
	}
	return page, nil
}

// imageStatusValues are the values of the image status facet.
var imageStatusValues = []string{string(model.ImagePending), string(model.ImageCatalogued), string(model.ImageUnresolvable),
	string(model.ImageCatalogFailed)}

// ImageFacets counts in-use container images by status, source, coverage, namespace and priority
// (worst open), each under q minus its own selection. An image run in two namespaces counts in each.
// The facets share one statement over one evaluation of im; the namespace facet of a query that
// selects namespaces has its own, since im is built without that selection.
func (s *Store) ImageFacets(ctx context.Context, q ImageQuery, facets []string) (map[string][]FacetValue, error) {
	var shared, own []string
	for _, f := range facets {
		switch {
		case !slices.Contains([]string{"status", "source", "coverage", "namespace", "priority"}, f):
			return nil, fmt.Errorf("store: unknown image facet %q", f)
		case f == "namespace" && len(q.Namespaces) > 0:
			own = append(own, f)
		default:
			shared = append(shared, f)
		}
	}
	counts := map[string]map[string]int{}
	cq := q
	cq.Namespaces = nil
	for _, run := range []struct {
		q      ImageQuery
		facets []string
	}{{q, shared}, {cq, own}} {
		if len(run.facets) == 0 {
			continue
		}
		if err := s.imageFacetCounts(ctx, run.q, q, run.facets, counts); err != nil {
			return nil, err
		}
	}
	out := make(map[string][]FacetValue, len(facets))
	for _, f := range facets {
		switch f {
		case "status":
			out[f] = enumFacet(imageStatusValues, counts[f])
		case "source":
			out[f] = openFacet(counts[f], q.Sources, 0)
		case "coverage":
			out[f] = enumFacet(coverageValues, counts[f])
		case "priority":
			out[f] = enumFacet(priorityValues, counts[f])
		case "namespace":
			out[f] = openFacet(counts[f], q.Namespaces, 0)
		}
	}
	return out, nil
}

// imageFacetCounts adds to counts the (facet, value, count) rows of facets, counted in one statement
// over im built for cq, each under q minus the facet's own selection.
func (s *Store) imageFacetCounts(ctx context.Context, cq, q ImageQuery, facets []string, counts map[string]map[string]int) error {
	cte, args, err := imagesCTE(cq)
	if err != nil {
		return err
	}
	parts := make([]string, len(facets))
	for i, f := range facets {
		w := imageWhere(q, f)
		label := `'` + f + `'`
		switch f {
		case "status", "source":
			parts[i] = `SELECT ` + label + `, ` + f + `, count(*) FROM im` + w.String() + ` GROUP BY ` + f
		case "coverage":
			parts[i] = `SELECT ` + label + `, cov, count(*) FROM im` + w.String() + ` GROUP BY cov`
		case "priority":
			parts[i] = `SELECT ` + label + `, ` + worstName + `, count(*) FROM im` + w.String() + ` GROUP BY worst`
		case "namespace":
			parts[i] = `SELECT ` + label + `, u.namespace, count(DISTINCT u.digest) FROM inuse u WHERE u.digest IN (SELECT digest FROM im` +
				w.String() + `) GROUP BY u.namespace`
		}
		args = append(args, w.args...)
	}
	rows, err := s.rdb.QueryContext(ctx, cte+` `+strings.Join(parts, ` UNION ALL `), args...)
	if err != nil {
		return fmt.Errorf("store: image facets: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			f, v string
			n    int
		)
		if err := rows.Scan(&f, &v, &n); err != nil {
			return err
		}
		if counts[f] == nil {
			counts[f] = map[string]int{}
		}
		counts[f][v] += n
	}
	return rows.Err()
}

// --- packages

// PackageEntityQuery selects the packages of a scope's in-use container images, or of one image.
type PackageEntityQuery struct {
	Scope      model.Scope // cluster | namespace | workload | image
	Ecosystems []string
	Worst      []model.Priority
	Q          string // name substring
	Sort       string // "-risk" (default) | "name" | "-images"
	After      string
	Limit      int
}

// PackageRow is one package version: Images and Workloads count the scope's digests and owners
// that hold it, Counts and Worst its open findings in scope. Version is the installed form
// (epoch-prefixed exactly as findings record it).
type PackageRow struct {
	Ecosystem, Name, Version string
	Images, Workloads        int
	Counts                   PriorityCounts
	Worst                    model.Priority
	Classifier               string
}

// PackagePage is one page of packages; Total counts every package q matches, ignoring After.
type PackagePage struct {
	Rows  []PackageRow
	Next  string
	Total int
}

var packageSorts = map[string][]keyCol{
	"-risk": {{"worst", true, kindInt}, {"urgent", true, kindInt}, {"high", true, kindInt}, {"images", true, kindInt},
		{"ecosystem", false, kindString}, {"name", false, kindString}, {"version", false, kindString}},
	"name":    {{"name", false, kindString}, {"ecosystem", false, kindString}, {"version", false, kindString}},
	"-images": {{"images", true, kindInt}, {"ecosystem", false, kindString}, {"name", false, kindString}, {"version", false, kindString}},
}

// packagesCTE is pk: one row per (ecosystem, name, installed version) of the packages of q's scope
// digests, with the digests holding it and its open findings in scope (over the cluster, those on
// container images); and so, the scope's (digest, owner) pairs, which packageWorkloads counts for
// the rows of a page only.
//
// The packages are first grouped by their stored (ecosystem, name, version, epoch), which over the
// cluster streams through the packages_explore index (055) in its order, then by installed version.
// Two stored forms of one installed version (the epoch in the version or beside it) are rare; their
// images are counted again across both, so an image holding both counts once.
func packagesCTE(sc model.Scope) (string, []any, error) {
	var (
		digests, owners string
		args            []any
	)
	cd := containerDigest("oi.digest")
	from := `packages p`
	switch sc.Kind {
	case model.ScopeCluster, "":
		digests = `SELECT DISTINCT oi.digest FROM owner_images oi WHERE ` + cd
		owners = `SELECT DISTINCT oi.digest, oi.owner_key FROM owner_images oi WHERE ` + cd
		from = `packages p INDEXED BY packages_explore`
	case model.ScopeNamespace:
		digests = `SELECT DISTINCT oi.digest FROM owner_images oi JOIN owners o ON o.key = oi.owner_key WHERE o.namespace = ? AND ` + cd
		owners = `SELECT DISTINCT oi.digest, oi.owner_key FROM owner_images oi JOIN owners o ON o.key = oi.owner_key WHERE o.namespace = ? AND ` + cd
		args = []any{sc.Value, sc.Value}
	case model.ScopeWorkload:
		digests = `SELECT DISTINCT oi.digest FROM owner_images oi WHERE oi.owner_key = ? AND ` + cd
		owners = `SELECT DISTINCT oi.digest, oi.owner_key FROM owner_images oi WHERE oi.owner_key = ? AND ` + cd
		args = []any{sc.Value, sc.Value}
	case model.ScopeImage:
		digests = `SELECT ? AS digest`
		owners = `SELECT DISTINCT oi.digest, oi.owner_key FROM owner_images oi WHERE oi.digest = ?`
		args = []any{sc.Value, sc.Value}
	default:
		return "", nil, scopeErr(sc)
	}
	fw, err := findingScopeWhere(sc)
	if err != nil {
		return "", nil, err
	}
	// Over the cluster, only the findings of workloads count, which are the findings on container
	// images: a host package or the cluster's own Kubernetes package at the same version is not one
	// of these packages. The cluster-level owners are few, and their findings are found through
	// findings_fix.
	inScope := ` AND fp.fingerprint NOT IN (SELECT f.fingerprint FROM findings f WHERE f.state = 'open'
		AND f.owner_key IN (SELECT owner_key FROM owner_stats WHERE namespace = ''))`
	if len(fw.conds) > 0 {
		inScope = ` AND fp.fingerprint IN (SELECT fingerprint FROM findings` + fw.String() + `)`
	}
	args = append(args, fw.args...)
	cte := `WITH sd AS (` + digests + `), so AS MATERIALIZED (` + owners + `),
	pkv AS (SELECT p.ecosystem, p.name, p.version, p.epoch, count(DISTINCT p.digest) AS images, max(p.classifier) AS classifier
		FROM ` + from + ` WHERE p.digest IN (SELECT digest FROM sd) GROUP BY p.ecosystem, p.name, p.version, p.epoch),
	pkm AS (SELECT pkv.ecosystem, pkv.name, ` + installedExpr("pkv") + ` AS version, count(*) AS forms, sum(pkv.images) AS images,
		max(pkv.classifier) AS classifier FROM pkv GROUP BY 1, 2, 3),
	pk0 AS (SELECT ecosystem, name, version, CASE WHEN forms = 1 THEN images ELSE (SELECT count(DISTINCT p3.digest) FROM packages p3
		WHERE p3.ecosystem = pkm.ecosystem AND p3.name = pkm.name AND ` + installedExpr("p3") + ` = pkm.version
		AND p3.digest IN (SELECT digest FROM sd)) END AS images, classifier FROM pkm),
	fc AS (SELECT fp.ecosystem, fp.name, fp.version, sum(fp.priority = 4) AS u, sum(fp.priority = 3) AS h, sum(fp.priority = 2) AS m,
		sum(fp.priority = 1) AS l FROM finding_packages fp WHERE fp.state = 'open'` + inScope + ` GROUP BY 1, 2, 3),
	pk1 AS (SELECT pk0.*, coalesce(fc.u, 0) AS urgent, coalesce(fc.h, 0) AS high, coalesce(fc.m, 0) AS medium, coalesce(fc.l, 0) AS low
		FROM pk0 LEFT JOIN fc ON fc.ecosystem = pk0.ecosystem AND fc.name = pk0.name AND fc.version = pk0.version),
	pk AS (SELECT *, ` + worstSQL + ` AS worst FROM pk1)`
	return cte, args, nil
}

// packageWorkloads counts the scope's owners (so, materialized once) running a digest that holds
// the package of the pk row aliased a; packages_explore serves the lookup by name.
func packageWorkloads(a string) string {
	return `(SELECT count(DISTINCT so.owner_key) FROM packages p2 INDEXED BY packages_explore JOIN so ON so.digest = p2.digest
		WHERE p2.ecosystem = ` + a + `.ecosystem AND p2.name = ` + a + `.name AND ` + installedExpr("p2") + ` = ` + a + `.version)`
}

// packageWhere returns q's predicates over pk, without facet omit's selection.
func packageWhere(q PackageEntityQuery, omit string) where {
	var w where
	if omit != "ecosystem" && len(q.Ecosystems) > 0 {
		w.add(inCond("ecosystem", len(q.Ecosystems)), anys(q.Ecosystems)...)
	}
	if omit != "priority" && len(q.Worst) > 0 {
		w.add(inCond("worst", len(q.Worst)), worstArgs(q.Worst)...)
	}
	if q.Q != "" {
		w.add(`name LIKE ? ESCAPE '\'`, likePattern(q.Q))
	}
	return w
}

// PackagesPage returns one keyset page of the packages q matches. The total and the page come
// from one evaluation of pk: the total is counted before the keyset predicate, and counted apart
// only when a page after a cursor comes back empty.
func (s *Store) PackagesPage(ctx context.Context, q PackageEntityQuery) (PackagePage, error) {
	sort := cmp.Or(q.Sort, "-risk")
	cols, ok := packageSorts[sort]
	if !ok {
		return PackagePage{}, fmt.Errorf("store: unknown package sort %q", sort)
	}
	tag := "packages:" + sort
	after, err := decodeCursor(q.After, tag, cols)
	if err != nil {
		return PackagePage{}, err
	}
	cte, cteArgs, err := packagesCTE(q.Scope)
	if err != nil {
		return PackagePage{}, err
	}
	w := packageWhere(q, "")
	var kw where
	if after != nil {
		cond, args := keysetAfter(cols, after)
		kw.add(cond, args...)
	}
	limit := clampLimit(q.Limit)
	// Workloads are counted for the page's rows only, after the LIMIT.
	rows, err := s.rdb.QueryContext(ctx, cte+`, pg AS (SELECT *, count(*) OVER () AS total FROM pk`+w.String()+`),
		pl AS (SELECT * FROM pg`+kw.String()+orderBy(cols)+` LIMIT ?)
		SELECT `+tupleExprs(cols)+`, total, ecosystem, name, version, images, `+packageWorkloads("pl")+`,
		urgent, high, medium, low, worst, coalesce(classifier, '') FROM pl`+orderBy(cols),
		slices.Concat(cteArgs, w.args, kw.args, []any{limit + 1})...)
	if err != nil {
		return PackagePage{}, fmt.Errorf("store: packages page: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var (
		page PackagePage
		last []any
	)
	for rows.Next() {
		if len(page.Rows) == limit {
			page.Next = encodeCursor(tag, last)
			break
		}
		tuple, values := tupleDest(cols)
		var (
			r     PackageRow
			worst int
		)
		if err := rows.Scan(slices.Concat(tuple, []any{&page.Total, &r.Ecosystem, &r.Name, &r.Version, &r.Images, &r.Workloads,
			&r.Counts.Urgent, &r.Counts.High, &r.Counts.Medium, &r.Counts.Low, &worst, &r.Classifier})...); err != nil {
			return PackagePage{}, err
		}
		r.Worst = model.Priority(worst)
		page.Rows = append(page.Rows, r)
		last = values()
	}
	if err := rows.Err(); err != nil {
		return PackagePage{}, err
	}
	if len(page.Rows) == 0 && after != nil {
		if err := s.rdb.QueryRowContext(ctx, cte+` SELECT count(*) FROM pk`+w.String(), slices.Concat(cteArgs, w.args)...).
			Scan(&page.Total); err != nil {
			return PackagePage{}, fmt.Errorf("store: count packages: %w", err)
		}
	}
	return page, nil
}

// PackageFacets counts packages by ecosystem and priority (worst open), each under q minus its own
// selection, in one statement over one evaluation of pk.
func (s *Store) PackageFacets(ctx context.Context, q PackageEntityQuery, facets []string) (map[string][]FacetValue, error) {
	out := make(map[string][]FacetValue, len(facets))
	if len(facets) == 0 {
		return out, nil
	}
	cte, cteArgs, err := packagesCTE(q.Scope)
	if err != nil {
		return nil, err
	}
	var (
		parts []string
		args  = slices.Clone(cteArgs)
	)
	for _, f := range facets {
		w := packageWhere(q, f)
		switch f {
		case "ecosystem":
			parts = append(parts, `SELECT 'ecosystem', ecosystem, count(*) FROM pk`+w.String()+` GROUP BY ecosystem`)
		case "priority":
			parts = append(parts, `SELECT 'priority', `+worstName+`, count(*) FROM pk`+w.String()+` GROUP BY worst`)
		default:
			return nil, fmt.Errorf("store: unknown package facet %q", f)
		}
		args = append(args, w.args...)
	}
	rows, err := s.rdb.QueryContext(ctx, cte+` `+strings.Join(parts, ` UNION ALL `), args...)
	if err != nil {
		return nil, fmt.Errorf("store: package facets: %w", err)
	}
	defer func() { _ = rows.Close() }()
	counts := map[string]map[string]int{}
	for rows.Next() {
		var (
			f, v string
			n    int
		)
		if err := rows.Scan(&f, &v, &n); err != nil {
			return nil, err
		}
		if counts[f] == nil {
			counts[f] = map[string]int{}
		}
		counts[f][v] += n
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, f := range facets {
		if f == "ecosystem" {
			out[f] = openFacet(counts[f], q.Ecosystems, 0)
		} else {
			out[f] = enumFacet(priorityValues, counts[f])
		}
	}
	return out, nil
}

// --- one image's packages

// ImagePackageRow is a package of an image with the open findings on that image that affect it.
type ImagePackageRow struct {
	Package  model.Package
	Findings int
	Worst    model.Priority
}

// ImagePackagePage is one page of an image's packages; Total ignores After.
type ImagePackagePage struct {
	Rows  []ImagePackageRow
	Next  string
	Total int
}

var imagePackageKey = []keyCol{{"p.name", false, kindString}, {"p.version", false, kindString}, {"p.id", false, kindString}}

// ImagePackages returns one keyset page of digest's packages, by name, version and id: those whose
// name or version contains q or whose id starts with it, in ecosystems. It serves a node group's
// host packages (nodegroup:<id>) as well as a container image's.
func (s *Store) ImagePackages(ctx context.Context, digest, q string, ecosystems []string, after string, limit int) (ImagePackagePage, error) {
	vals, err := decodeCursor(after, "imagepackages", imagePackageKey)
	if err != nil {
		return ImagePackagePage{}, err
	}
	var w where
	w.add(`p.digest = ?`, digest)
	if q != "" {
		pat := likePattern(q)
		w.add(`(p.name LIKE ? ESCAPE '\' OR p.version LIKE ? ESCAPE '\' OR p.id LIKE ? ESCAPE '\')`, pat, pat, likePrefix(q))
	}
	if len(ecosystems) > 0 {
		w.add(inCond("p.ecosystem", len(ecosystems)), anys(ecosystems)...)
	}
	var page ImagePackagePage
	if err := s.rdb.QueryRowContext(ctx, `SELECT count(*) FROM packages p`+w.String(), w.args...).Scan(&page.Total); err != nil {
		return ImagePackagePage{}, fmt.Errorf("store: count image packages: %w", err)
	}
	if vals != nil {
		cond, args := keysetAfter(imagePackageKey, vals)
		w.add(cond, args...)
	}
	n := clampLimit(limit)
	st := stmt{query: `SELECT ` + prefixedCols("p.", packageCols, "") + `, coalesce(fc.findings, 0), coalesce(fc.worst, 0)
		FROM packages p LEFT JOIN (SELECT fp.ecosystem, fp.name, fp.version, count(*) AS findings, max(fp.priority) AS worst
			FROM finding_packages fp WHERE fp.state = 'open' AND fp.fingerprint IN (SELECT fingerprint FROM finding_digests WHERE digest = ?)
			GROUP BY 1, 2, 3) fc ON fc.ecosystem = p.ecosystem AND fc.name = p.name AND fc.version = ` + installedExpr("p") +
		w.String() + orderBy(imagePackageKey) + ` LIMIT ?`, args: slices.Concat([]any{digest}, w.args, []any{n + 1})}
	rows, err := s.rdb.QueryContext(ctx, st.query, st.args...)
	if err != nil {
		return ImagePackagePage{}, fmt.Errorf("store: image packages: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		if len(page.Rows) == n {
			p := page.Rows[n-1].Package
			page.Next = encodeCursor("imagepackages", []any{p.Name, p.Version, p.ID})
			break
		}
		var (
			r     ImagePackageRow
			worst int
		)
		pkgRow := &packageScan{}
		if err := rows.Scan(append(pkgRow.dest(), &r.Findings, &worst)...); err != nil {
			return ImagePackagePage{}, err
		}
		if r.Package, err = pkgRow.pkg(); err != nil {
			return ImagePackagePage{}, err
		}
		r.Worst = model.Priority(worst)
		page.Rows = append(page.Rows, r)
	}
	return page, rows.Err()
}

// prefixedCols wraps each column of a column list in before and after: ("p.", cols, "") qualifies
// them, ("coalesce(st.", cols, ", 0)") defaults them.
func prefixedCols(before, cols, after string) string {
	parts := strings.Split(cols, ",")
	for i, c := range parts {
		parts[i] = before + strings.TrimSpace(c) + after
	}
	return strings.Join(parts, ", ")
}

// ImageEcosystems counts digest's packages per ecosystem, most first, then by ecosystem.
func (s *Store) ImageEcosystems(ctx context.Context, digest string) ([]FacetValue, error) {
	counts, err := s.facetQuery(ctx, `SELECT ecosystem, count(*) FROM packages WHERE digest = ? GROUP BY ecosystem`, []any{digest})
	if err != nil {
		return nil, fmt.Errorf("store: image ecosystems: %w", err)
	}
	return openFacet(counts, nil, 0), nil
}

// PackageName names a package within its ecosystem.
type PackageName struct{ Ecosystem, Name string }

// InstalledVersion is the installed version of a named package in one digest.
type InstalledVersion struct {
	PackageName
	Version string // epoch-prefixed exactly as findings record it
}

// installedVersionsQuery reads the installed versions of the "<ecosystem>\x1f<name>" list (the
// second argument) in the digests of the first.
//
//nolint:gosec // G202: joins this package's SQL fragments; every value is a bound parameter
var installedVersionsQuery = `SELECT DISTINCT p.digest, p.ecosystem, p.name, ` + installedExpr("p") + ` AS installed FROM packages p
	WHERE p.digest IN (SELECT value FROM json_each(?)) AND p.ecosystem || char(31) || p.name IN (SELECT value FROM json_each(?))
	ORDER BY p.digest, p.name, installed, p.ecosystem`

// InstalledVersions returns the installed versions of the named packages in each of digests, by
// digest, then by name and version, each once.
func (s *Store) InstalledVersions(ctx context.Context, digests []string, names []PackageName) (map[string][]InstalledVersion, error) {
	out := map[string][]InstalledVersion{}
	if len(digests) == 0 || len(names) == 0 {
		return out, nil
	}
	keys := make([]string, len(names))
	for i, n := range names {
		keys[i] = n.Ecosystem + "\x1f" + n.Name
	}
	rows, err := s.rdb.QueryContext(ctx, installedVersionsQuery, idList(digests), idList(keys))
	if err != nil {
		return nil, fmt.Errorf("store: installed versions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			digest string
			v      InstalledVersion
		)
		if err := rows.Scan(&digest, &v.Ecosystem, &v.Name, &v.Version); err != nil {
			return nil, err
		}
		out[digest] = append(out[digest], v)
	}
	return out, rows.Err()
}

// EntityCounts are the entity explorers' totals for a scope, counted without their pages.
type EntityCounts struct{ Workloads, Images, Packages int }

// EntityCounts counts the workloads, in-use container images and package versions of a cluster or
// namespace scope: the totals WorkloadsPage, ImagesPage and PackagesPage give with no other
// filter, without their findings, owners or a second pass.
func (s *Store) EntityCounts(ctx context.Context, sc model.Scope) (EntityCounts, error) {
	var (
		owners, images, digests string
		args                    []any
	)
	cd := containerDigest("oi.digest")
	switch sc.Kind {
	case model.ScopeCluster, "":
		owners = `SELECT count(*) FROM owners WHERE namespace != ''`
		images = `SELECT count(DISTINCT oi.digest) FROM owner_images oi JOIN owners o ON o.key = oi.owner_key WHERE ` + cd
		digests = `SELECT DISTINCT oi.digest FROM owner_images oi WHERE ` + cd
	case model.ScopeNamespace:
		owners = `SELECT count(*) FROM owners WHERE namespace != '' AND namespace = ?`
		images = `SELECT count(DISTINCT oi.digest) FROM owner_images oi JOIN owners o ON o.key = oi.owner_key WHERE o.namespace = ? AND ` + cd
		digests = `SELECT DISTINCT oi.digest FROM owner_images oi JOIN owners o ON o.key = oi.owner_key WHERE o.namespace = ? AND ` + cd
		args = []any{sc.Value, sc.Value, sc.Value}
	default:
		return EntityCounts{}, scopeErr(sc)
	}
	from := `packages p`
	if sc.Kind != model.ScopeNamespace {
		from = `packages p INDEXED BY packages_explore`
	}
	var c EntityCounts
	err := s.rdb.QueryRowContext(ctx, `SELECT (`+owners+`), (`+images+`), (SELECT count(*) FROM (SELECT DISTINCT p.ecosystem, p.name, `+
		installedExpr("p")+` FROM `+from+` WHERE p.digest IN (`+digests+`)))`, args...).Scan(&c.Workloads, &c.Images, &c.Packages)
	if err != nil {
		return EntityCounts{}, fmt.Errorf("store: entity counts of %s: %w", sc, err)
	}
	return c, nil
}
