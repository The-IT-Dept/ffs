package store

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/the-it-dept/ffs/internal/model"
)

// The findings explorer: keyset pages, groups and facets over the read model's generated columns
// (migration 050). Counting statements that can be answered from the findings_explore index alone
// name it, because the planner prefers the older findings_state_priority index and SQLite never
// reports an index holding VIRTUAL columns as covering.

// FindingSort orders a findings page. Each sort is a tuple whose last element is the fingerprint.
type FindingSort string

const (
	SortPriority  FindingSort = "-priority"  // priority DESC, advisory_id, fingerprint
	SortSeverity  FindingSort = "-severity"  // severity DESC, priority DESC, fingerprint
	SortPublished FindingSort = "-published" // published DESC, fingerprint
	SortEPSS      FindingSort = "-epss"      // epss DESC, priority DESC, fingerprint
	SortAdvisory  FindingSort = "advisory"   // advisory_id, owner_key, fingerprint
	SortWorkload  FindingSort = "workload"   // owner_key, priority DESC, fingerprint
	SortNamespace FindingSort = "namespace"  // namespace, owner_key, priority DESC, fingerprint
)

var (
	colPriority    = keyCol{"priority", true, kindInt}
	colFingerprint = keyCol{"fingerprint", false, kindString}
	colAdvisoryID  = keyCol{"advisory_id", false, kindString}
	colOwnerKey    = keyCol{"owner_key", false, kindString}
)

var findingSorts = map[FindingSort][]keyCol{
	SortPriority:  {colPriority, colAdvisoryID, colFingerprint},
	SortSeverity:  {{"severity", true, kindInt}, colPriority, colFingerprint},
	SortPublished: {{"published", true, kindString}, colFingerprint},
	SortEPSS:      {{"epss", true, kindFloat}, colPriority, colFingerprint},
	SortAdvisory:  {colAdvisoryID, colOwnerKey, colFingerprint},
	SortWorkload:  {colOwnerKey, colPriority, colFingerprint},
	SortNamespace: {{"namespace", false, kindString}, colOwnerKey, colPriority, colFingerprint},
}

// FindingQuery selects findings for the explorer. Empty fields match everything.
type FindingQuery struct {
	Scope         model.Scope
	States        []model.FindingState // empty = [open]
	ResolvedSince time.Time            // applies to StateResolved only: resolved_at >= ResolvedSince (the API passes now-30d)
	Priorities    []model.Priority
	Fix           []model.FixClass
	Signals       []model.Signal // all must hold: signals & mask = mask
	Ecosystems    []string
	Namespaces    []string
	Kinds         []string
	Advisory      string      // canonical id or any alias (sameAdvisory)
	Package       string      // any package of the finding, by exact name (finding_packages)
	Repo          string      // exact image_repo
	FixKey        string      // exact fix_key (fix-group expansion; served by findings_fix with a workload scope; not a facet)
	Q             string      // case-insensitive substring of advisory_id, owner_key or image_repo (packages: use Package)
	Sort          FindingSort // "" = SortPriority
	After         string
	Limit         int
}

// FindingPage is one page of findings. Total counts every finding q matches, ignoring After; Next
// is "" on the last page.
type FindingPage struct {
	Rows  []model.Finding
	Next  string
	Total int
}

// FindingGroup groups the explorer's findings.
type FindingGroup string

const (
	GroupAdvisory  FindingGroup = "advisory"
	GroupWorkload  FindingGroup = "workload"
	GroupImage     FindingGroup = "image"
	GroupPackage   FindingGroup = "package"
	GroupNamespace FindingGroup = "namespace"
	GroupFix       FindingGroup = "fix"
)

// GroupRow is one group of findings.
type GroupRow struct {
	Key, Label string // advisory id | owner key | image repo | "<ecosystem>/<name>@<version>" | namespace ("" = cluster-level) | fix_key
	Findings   int
	Distinct   int // distinct advisories (workload, image, package, namespace, fix groups) or distinct workloads (advisory group)
	Counts     PriorityCounts
	Fixable    int
	Exploited  int
	Worst      model.Priority
	Sample     *model.Finding // fix groups only: the group's highest-priority finding (its Fix and Suggestion name the action)
}

// GroupPage is one page of groups. Groups and Findings count every group q matches and the
// findings across them, ignoring After.
type GroupPage struct {
	Rows             []GroupRow
	Next             string
	Groups, Findings int
}

// FindingFacet is a facet of the findings explorer.
type FindingFacet string

const (
	FacetState     FindingFacet = "state"
	FacetPriority  FindingFacet = "priority"
	FacetFix       FindingFacet = "fix"
	FacetSignal    FindingFacet = "signal"
	FacetEcosystem FindingFacet = "ecosystem"
	FacetNamespace FindingFacet = "namespace"
	FacetKind      FindingFacet = "kind"
)

// TransitionPage is one page of a scope's transitions, newest first.
type TransitionPage struct {
	Rows []model.Transition
	Next string
}

// stmt is one statement of a count or facet. indexOnly means it names findings_explore and reads
// nothing else of the findings table.
type stmt struct {
	query     string
	args      []any
	indexOnly bool
}

// namespaceFacetTop is how many namespaces the namespace facet lists, besides the selected ones.
const namespaceFacetTop = 50

// FindingsPage returns one keyset page of the findings q matches, in q.Sort order.
func (s *Store) FindingsPage(ctx context.Context, q FindingQuery) (FindingPage, error) {
	ps, err := findingPageStmt(q)
	if err != nil {
		return FindingPage{}, err
	}
	cnt, err := findingCountStmt(q)
	if err != nil {
		return FindingPage{}, err
	}
	var page FindingPage
	if err := s.rdb.QueryRowContext(ctx, cnt.query, cnt.args...).Scan(&page.Total); err != nil {
		return FindingPage{}, fmt.Errorf("store: count findings: %w", err)
	}
	rows, err := s.rdb.QueryContext(ctx, ps.query, ps.args...)
	if err != nil {
		return FindingPage{}, fmt.Errorf("store: findings page: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var last []any
	for rows.Next() {
		if len(page.Rows) == ps.limit {
			page.Next = encodeCursor(ps.tag, last)
			break
		}
		dest, values := tupleDest(ps.cols)
		var fp, data string
		if err := rows.Scan(append(dest, &fp, &data)...); err != nil {
			return FindingPage{}, err
		}
		var f model.Finding
		if err := json.Unmarshal([]byte(data), &f); err != nil {
			return FindingPage{}, fmt.Errorf("store: finding %s: %w", fp, err)
		}
		page.Rows = append(page.Rows, f)
		last = values()
	}
	return page, rows.Err()
}

// pageStmt is a keyset page statement: it selects the sort tuple of cols, then the row, and
// fetches limit+1 rows, so an extra row means there is a next page.
type pageStmt struct {
	stmt
	tag   string
	cols  []keyCol
	limit int
}

// findingPageStmt is the statement of the findings page q asks for: the sort tuple, fingerprint
// and data of the rows after q.After.
func findingPageStmt(q FindingQuery) (pageStmt, error) {
	sort := cmp.Or(q.Sort, SortPriority)
	cols, ok := findingSorts[sort]
	if !ok {
		return pageStmt{}, fmt.Errorf("store: unknown finding sort %q", sort)
	}
	after, err := decodeCursor(q.After, string(sort), cols)
	if err != nil {
		return pageStmt{}, err
	}
	w, err := findingQueryWhere(q, "")
	if err != nil {
		return pageStmt{}, err
	}
	if after != nil {
		cond, args := keysetAfter(cols, after)
		w.add(cond, args...)
	}
	limit := clampLimit(q.Limit)
	return pageStmt{
		stmt: stmt{query: `SELECT ` + tupleExprs(cols) + `, fingerprint, data FROM ` + findingsFrom(q, false) + w.String() + orderBy(cols) + ` LIMIT ?`,
			args: append(w.args, limit+1)},
		tag: string(sort), cols: cols, limit: limit,
	}, nil
}

// FindingGroups returns one keyset page of the groups of the findings q matches. Fix groups are
// ordered by urgent, high and findings, most first, then key, with "none" and then "wontfix" last;
// other groups by their worst priority first. q.Sort is ignored. A finding counts under each of its
// packages, so package groups' Findings may exceed the flat total.
func (s *Store) FindingGroups(ctx context.Context, q FindingQuery, g FindingGroup) (GroupPage, error) {
	w, err := findingQueryWhere(q, "")
	if err != nil {
		return GroupPage{}, err
	}
	const fields = `owner_key, advisory_id, priority, fix_available, signals`
	var source, key string
	switch g {
	case GroupPackage:
		source = `(SELECT fingerprint, ` + fields + ` FROM ` + findingsFrom(q, false) + w.String() + `) f JOIN finding_packages p ON p.fingerprint = f.fingerprint`
		key = `p.ecosystem || '/' || p.name || '@' || p.version`
	case GroupAdvisory, GroupWorkload, GroupImage, GroupNamespace, GroupFix:
		col := map[FindingGroup]string{GroupAdvisory: "advisory_id", GroupWorkload: "owner_key", GroupImage: "image_repo",
			GroupNamespace: "namespace", GroupFix: "fix_key"}[g]
		source, key = `(SELECT `+fields+`, `+col+` AS gkey FROM `+findingsFrom(q, false)+w.String()+`) f`, `f.gkey`
	default:
		return GroupPage{}, fmt.Errorf("store: unknown finding group %q", g)
	}
	distinct, tail := `f.advisory_id`, `0`
	if g == GroupAdvisory {
		distinct = `f.owner_key`
	}
	cols := []keyCol{{"worst", true, kindInt}, {"urgent", true, kindInt}, {"high", true, kindInt}, {"findings", true, kindInt}, {"key", false, kindString}}
	if g == GroupFix {
		tail = `CASE key WHEN 'none' THEN 1 WHEN 'wontfix' THEN 2 ELSE 0 END`
		cols[0] = keyCol{"tail", false, kindInt}
	}
	cte := `WITH g AS (SELECT ` + key + ` AS key, count(*) AS findings, count(DISTINCT ` + distinct + `) AS distinct_n,
			sum(f.priority = 4) AS urgent, sum(f.priority = 3) AS high, sum(f.priority = 2) AS medium, sum(f.priority = 1) AS low,
			sum(f.fix_available) AS fixable, sum(f.signals & 8 != 0) AS exploited, max(f.priority) AS worst
			FROM ` + source + ` GROUP BY 1),
		t AS (SELECT *, ` + tail + ` AS tail FROM g)`
	tag := "group:" + string(g)
	after, err := decodeCursor(q.After, tag, cols)
	if err != nil {
		return GroupPage{}, err
	}

	var page GroupPage
	if err := s.rdb.QueryRowContext(ctx, cte+` SELECT count(*), coalesce(sum(findings), 0) FROM t`, w.args...).
		Scan(&page.Groups, &page.Findings); err != nil {
		return GroupPage{}, fmt.Errorf("store: count finding groups: %w", err)
	}
	var kw where
	if after != nil {
		cond, args := keysetAfter(cols, after)
		kw.add(cond, args...)
	}
	limit := clampLimit(q.Limit)
	args := slices.Concat(w.args, kw.args, []any{limit + 1})
	rows, err := s.rdb.QueryContext(ctx, cte+` SELECT key, findings, distinct_n, urgent, high, medium, low, fixable, exploited, worst, tail
		FROM t`+kw.String()+orderBy(cols)+` LIMIT ?`, args...)
	if err != nil {
		return GroupPage{}, fmt.Errorf("store: finding groups: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var last []any
	for rows.Next() {
		if len(page.Rows) == limit {
			page.Next = encodeCursor(tag, last)
			break
		}
		var (
			r                                  GroupRow
			urgent, high, findings, worst, tl  int64
			medium, low, fixable, exploited, d int64
		)
		if err := rows.Scan(&r.Key, &findings, &d, &urgent, &high, &medium, &low, &fixable, &exploited, &worst, &tl); err != nil {
			return GroupPage{}, err
		}
		r.Label, r.Findings, r.Distinct = r.Key, int(findings), int(d)
		r.Counts = PriorityCounts{Urgent: int(urgent), High: int(high), Medium: int(medium), Low: int(low)}
		r.Fixable, r.Exploited, r.Worst = int(fixable), int(exploited), model.Priority(worst)
		page.Rows = append(page.Rows, r)
		last = []any{worst, urgent, high, findings, r.Key}
		if g == GroupFix {
			last[0] = tl
		}
	}
	if err := rows.Err(); err != nil {
		return GroupPage{}, err
	}
	if g == GroupFix && len(page.Rows) > 0 {
		if err := s.fixSamples(ctx, q, w, page.Rows); err != nil {
			return GroupPage{}, err
		}
	}
	return page, nil
}

// fixSamples sets each fix group's Sample to its highest-priority finding under w, the predicate of q.
func (s *Store) fixSamples(ctx context.Context, q FindingQuery, w where, groups []GroupRow) error {
	keys := make([]string, len(groups))
	for i, g := range groups {
		keys[i] = g.Key
	}
	sw := where{conds: slices.Clone(w.conds), args: slices.Clone(w.args)}
	sw.add(`fix_key IN (SELECT value FROM json_each(?))`, idList(keys))
	st := stmt{query: `SELECT fix_key, fingerprint, data FROM (SELECT fix_key, fingerprint, data,
		row_number() OVER (PARTITION BY fix_key ORDER BY priority DESC, fingerprint) AS rn FROM ` + findingsFrom(q, false) + sw.String() + `)
		WHERE rn = 1`, args: sw.args}
	rows, err := s.rdb.QueryContext(ctx, st.query, st.args...)
	if err != nil {
		return fmt.Errorf("store: fix group samples: %w", err)
	}
	defer func() { _ = rows.Close() }()
	samples := map[string]*model.Finding{}
	for rows.Next() {
		var key string
		var f model.Finding
		var fp, data string
		if err := rows.Scan(&key, &fp, &data); err != nil {
			return err
		}
		if err := json.Unmarshal([]byte(data), &f); err != nil {
			return fmt.Errorf("store: finding %s: %w", fp, err)
		}
		samples[key] = &f
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range groups {
		groups[i].Sample = samples[groups[i].Key]
	}
	return nil
}

// FindingFacets counts the values of each facet in facets, each under q minus that facet's own
// selection. Enumerated facets (state, priority, fix, signal) list every value; the others list the
// values with findings plus every selected value, without "", and namespace keeps the top 50. The
// state facet counts resolved findings since q.ResolvedSince. Values are ordered by count, most
// first, then value.
func (s *Store) FindingFacets(ctx context.Context, q FindingQuery, facets []FindingFacet) (map[FindingFacet][]FacetValue, error) {
	out := make(map[FindingFacet][]FacetValue, len(facets))
	for _, f := range facets {
		stmts, err := findingFacetStmts(q, f)
		if err != nil {
			return nil, err
		}
		counts := map[string]int{}
		for _, st := range stmts {
			if err := s.facetCounts(ctx, st, counts); err != nil {
				return nil, fmt.Errorf("store: %s facet: %w", f, err)
			}
		}
		out[f] = findingFacetValues(f, counts, q)
	}
	return out, nil
}

// facetCounts adds the (value, count) rows of st to counts.
func (s *Store) facetCounts(ctx context.Context, st stmt, counts map[string]int) error {
	rows, err := s.rdb.QueryContext(ctx, st.query, st.args...)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			v string
			n *int64
		)
		if err := rows.Scan(&v, &n); err != nil {
			return err
		}
		if n != nil {
			counts[v] += int(*n)
		}
	}
	return rows.Err()
}

// findingFacetValues orders counts into the values of facet f.
func findingFacetValues(f FindingFacet, counts map[string]int, q FindingQuery) []FacetValue {
	var enum []string
	switch f {
	case FacetState:
		enum = []string{string(model.StateOpen), string(model.StateExcepted), string(model.StateResolved)}
	case FacetPriority:
		// A finding's priority is one of the four levels (priority.Compute starts at low), so "none"
		// is listed only for a stored finding that has none, which would otherwise go uncounted.
		enum = []string{"urgent", "high", "medium", "low"}
		if counts[priorityNoneValue] > 0 {
			enum = append(enum, priorityNoneValue)
		}
	case FacetFix:
		enum = []string{string(model.FixClassUpgrade), string(model.FixClassFixed), string(model.FixClassNone), string(model.FixClassWontFix)}
	case FacetSignal:
		for _, sg := range model.Signals {
			enum = append(enum, string(sg))
		}
	}
	if enum != nil {
		vals := make([]FacetValue, len(enum))
		for i, v := range enum {
			vals[i] = FacetValue{Value: v, Count: counts[v]}
		}
		return sortFacet(vals)
	}
	selected := map[FindingFacet][]string{FacetEcosystem: q.Ecosystems, FacetNamespace: q.Namespaces, FacetKind: q.Kinds}[f]
	top := 0
	if f == FacetNamespace {
		top = namespaceFacetTop
	}
	return openFacet(counts, selected, top)
}

// openFacet lists the values of an open-ended facet: those with a count, the first top of them
// when top > 0, plus every selected value; never "".
func openFacet(counts map[string]int, selected []string, top int) []FacetValue {
	var vals []FacetValue
	for v, n := range counts {
		if v != "" && n > 0 {
			vals = append(vals, FacetValue{Value: v, Count: n})
		}
	}
	vals = sortFacet(vals)
	if top > 0 && len(vals) > top {
		vals = vals[:top]
	}
	for _, v := range selected {
		if v != "" && !slices.ContainsFunc(vals, func(fv FacetValue) bool { return fv.Value == v }) {
			vals = append(vals, FacetValue{Value: v, Count: counts[v]})
		}
	}
	return sortFacet(vals)
}

// sortFacet orders facet values by count, most first, then value.
func sortFacet(vals []FacetValue) []FacetValue {
	slices.SortFunc(vals, func(a, b FacetValue) int {
		if a.Count != b.Count {
			return b.Count - a.Count
		}
		return strings.Compare(a.Value, b.Value)
	})
	return vals
}

// priorityNoneValue is the facet value of model.PriorityNone, whose String is "".
const priorityNoneValue = "none"

// priorityName is the SQL of a priority column's facet value.
const priorityName = `CASE priority WHEN 4 THEN 'urgent' WHEN 3 THEN 'high' WHEN 2 THEN 'medium' WHEN 1 THEN 'low' ELSE 'none' END`

// findingCountStmt counts the findings q matches, ignoring After.
func findingCountStmt(q FindingQuery) (stmt, error) {
	w, err := findingQueryWhere(q, "")
	if err != nil {
		return stmt{}, err
	}
	cov := coverable(q, "")
	return stmt{query: `SELECT count(*) FROM ` + findingsFrom(q, cov) + w.String(), args: w.args, indexOnly: cov}, nil
}

// findingFacetStmts returns the statements counting facet f under q minus f's own selection. Each
// returns (value, count) rows.
func findingFacetStmts(q FindingQuery, f FindingFacet) ([]stmt, error) {
	w, err := findingQueryWhere(q, f)
	if err != nil {
		return nil, err
	}
	cov := coverable(q, f)
	from := findingsFrom(q, cov)
	groupBy := func(value, col string) []stmt {
		return []stmt{{query: `SELECT ` + value + `, count(*) FROM ` + from + w.String() + ` GROUP BY ` + col, args: w.args, indexOnly: cov}}
	}
	switch f {
	case FacetState:
		open := cloneWhere(w)
		open.add(`state IN ('open', 'excepted')`)
		resolved := cloneWhere(w)
		if q.ResolvedSince.IsZero() {
			resolved.add(`state = 'resolved'`)
		} else {
			resolved.add(`state = 'resolved' AND resolved_at >= ?`, nanos(q.ResolvedSince))
		}
		return []stmt{
			{query: `SELECT state, count(*) FROM ` + from + open.String() + ` GROUP BY state`, args: open.args, indexOnly: cov},
			{query: `SELECT 'resolved', count(*) FROM ` + findingsFrom(q, false) + resolved.String(), args: resolved.args},
		}, nil
	case FacetPriority:
		return groupBy(priorityName, "priority"), nil
	case FacetFix:
		return groupBy("fix_class", "fix_class"), nil
	case FacetEcosystem:
		return groupBy("ecosystem", "ecosystem"), nil
	case FacetNamespace:
		return groupBy("namespace", "namespace"), nil
	case FacetKind:
		return groupBy("owner_kind", "owner_kind"), nil
	case FacetSignal:
		sums := make([]string, len(model.Signals))
		unpivot := make([]string, len(model.Signals))
		for i, sg := range model.Signals {
			sums[i] = fmt.Sprintf("sum(signals & %d != 0) AS s%d", sg.Bit(), i)
			unpivot[i] = fmt.Sprintf("SELECT '%s', s%d FROM s", sg, i)
		}
		return []stmt{{query: `WITH s AS MATERIALIZED (SELECT ` + strings.Join(sums, ", ") + ` FROM ` + from + w.String() + `) ` +
			strings.Join(unpivot, " UNION ALL "), args: w.args, indexOnly: cov}}, nil
	}
	return nil, fmt.Errorf("store: unknown finding facet %q", f)
}

// findingsFrom is the FROM of a findings statement of q: findings_explore named when the statement
// can be answered from it, and findings_fix for one workload's fix group, which the planner would
// otherwise read in page order through findings_page. Other statements leave the choice to it.
func findingsFrom(q FindingQuery, coverable bool) string {
	switch {
	case coverable:
		return `findings INDEXED BY findings_explore`
	case q.FixKey != "" && q.Scope.Kind == model.ScopeWorkload:
		return `findings INDEXED BY findings_fix`
	}
	return `findings`
}

// coverable reports whether the statements of q, minus facet omit's selection, read only columns of
// the findings_explore index: a cluster, namespace, workload or control plane scope, no Package,
// Repo, Q or FixKey, and only the open and excepted states.
func coverable(q FindingQuery, omit FindingFacet) bool {
	switch q.Scope.Kind {
	case model.ScopeCluster, "", model.ScopeNamespace, model.ScopeWorkload, model.ScopeControlPlane:
	default:
		return false
	}
	if q.Package != "" || q.Repo != "" || q.Q != "" || q.FixKey != "" {
		return false
	}
	if omit == FacetState {
		return true
	}
	return !slices.ContainsFunc(findingStates(q), func(st model.FindingState) bool {
		return st != model.StateOpen && st != model.StateExcepted
	})
}

// findingStates are q's states, open when it names none.
func findingStates(q FindingQuery) []model.FindingState {
	if len(q.States) == 0 {
		return []model.FindingState{model.StateOpen}
	}
	return q.States
}

// findingQueryWhere returns the predicates of q, without the selection of facet omit ("" = none).
func findingQueryWhere(q FindingQuery, omit FindingFacet) (where, error) {
	w, err := findingScopeWhere(q.Scope)
	if err != nil {
		return where{}, err
	}
	if omit != FacetState {
		addStates(&w, q)
	}
	if omit != FacetPriority && len(q.Priorities) > 0 {
		vals := make([]any, len(q.Priorities))
		for i, p := range q.Priorities {
			vals[i] = int(p)
		}
		w.add(inCond("priority", len(vals)), vals...)
	}
	if omit != FacetFix && len(q.Fix) > 0 {
		w.add(inCond("fix_class", len(q.Fix)), anys(q.Fix)...)
	}
	if omit != FacetSignal {
		if mask := signalMask(q.Signals); mask != 0 {
			w.add(`signals & ? = ?`, mask, mask)
		}
	}
	if omit != FacetEcosystem && len(q.Ecosystems) > 0 {
		w.add(inCond("ecosystem", len(q.Ecosystems)), anys(q.Ecosystems)...)
	}
	if omit != FacetNamespace && len(q.Namespaces) > 0 {
		w.add(inCond("namespace", len(q.Namespaces)), anys(q.Namespaces)...)
	}
	if omit != FacetKind && len(q.Kinds) > 0 {
		w.add(inCond("owner_kind", len(q.Kinds)), anys(q.Kinds)...)
	}
	if q.Advisory != "" {
		list := idList([]string{q.Advisory})
		w.add(sameAdvisory("advisory_id"), list, list)
	}
	if q.Package != "" {
		w.add(`fingerprint IN (SELECT fingerprint FROM finding_packages WHERE name = ?)`, q.Package)
	}
	if q.Repo != "" {
		w.add(`image_repo = ?`, q.Repo)
	}
	if q.FixKey != "" {
		w.add(`fix_key = ?`, q.FixKey)
	}
	if q.Q != "" {
		pat := likePattern(q.Q)
		w.add(`(advisory_id LIKE ? ESCAPE '\' OR owner_key LIKE ? ESCAPE '\' OR image_repo LIKE ? ESCAPE '\')`, pat, pat, pat)
	}
	return w, nil
}

// addStates adds q's state predicate: open and excepted by value, resolved since q.ResolvedSince.
func addStates(w *where, q FindingQuery) {
	var (
		parts    []string
		args     []any
		live     []any
		resolved bool
	)
	for _, st := range findingStates(q) {
		switch {
		case st == model.StateResolved:
			resolved = true
		case !slices.Contains(live, any(string(st))):
			live = append(live, string(st))
		}
	}
	if len(live) > 0 {
		parts, args = append(parts, inCond("state", len(live))), append(args, live...)
	}
	if resolved {
		if q.ResolvedSince.IsZero() {
			parts = append(parts, `state = 'resolved'`)
		} else {
			parts, args = append(parts, `(state = 'resolved' AND resolved_at >= ?)`), append(args, nanos(q.ResolvedSince))
		}
	}
	if len(parts) == 1 {
		w.add(parts[0], args...)
		return
	}
	w.add(`(`+strings.Join(parts, ` OR `)+`)`, args...)
}

// signalMask is the signals column mask of sgs; unknown signals add nothing.
func signalMask(sgs []model.Signal) int64 {
	var mask int64
	for _, sg := range sgs {
		mask |= sg.Bit()
	}
	return mask
}

// inCond is "col IN (?, ?, …)" with n placeholders.
func inCond(col string, n int) string {
	return col + ` IN (` + strings.TrimSuffix(strings.Repeat(`?, `, n), `, `) + `)`
}

// anys converts a slice of strings, or of a string type, for binding.
func anys[T ~string](vs []T) []any {
	out := make([]any, len(vs))
	for i, v := range vs {
		out[i] = string(v)
	}
	return out
}

func cloneWhere(w where) where {
	return where{conds: slices.Clone(w.conds), args: slices.Clone(w.args)}
}

var transitionKey = []keyCol{{"id", true, kindInt}}

// transitionScopeWhere narrows transitions to a cluster, namespace, workload or control plane
// scope; other scopes return ErrScope.
func transitionScopeWhere(sc model.Scope) (where, error) {
	var w where
	switch sc.Kind {
	case model.ScopeCluster, "":
	case model.ScopeNamespace:
		w.add(`namespace = ?`, sc.Value)
	case model.ScopeWorkload:
		w.add(`owner_key = ?`, sc.Value)
	case model.ScopeControlPlane: // owner key ranges, so transitions_owner serves them
		w.add(`((owner_key >= 'Cluster//' AND owner_key < 'Cluster/0') OR (owner_key >= 'ContainerRuntime//' AND owner_key < 'ContainerRuntime/0'))`)
	default:
		return where{}, scopeErr(sc)
	}
	return w, nil
}

// TransitionsPage returns one keyset page of the scope's transitions, newest first, with ID set.
func (s *Store) TransitionsPage(ctx context.Context, sc model.Scope, after string, limit int) (TransitionPage, error) {
	w, err := transitionScopeWhere(sc)
	if err != nil {
		return TransitionPage{}, err
	}
	vals, err := decodeCursor(after, "transitions", transitionKey)
	if err != nil {
		return TransitionPage{}, err
	}
	if vals != nil {
		cond, args := keysetAfter(transitionKey, vals)
		w.add(cond, args...)
	}
	n := clampLimit(limit)
	ts, err := queryAll(ctx, s.rdb, scanTransition, `SELECT id, data FROM transitions`+w.String()+orderBy(transitionKey)+` LIMIT ?`,
		append(w.args, n+1)...)
	if err != nil {
		return TransitionPage{}, fmt.Errorf("store: transitions page: %w", err)
	}
	var page TransitionPage
	if len(ts) > n {
		ts = ts[:n]
		page.Next = encodeCursor("transitions", []any{ts[n-1].ID})
	}
	page.Rows = ts
	return page, nil
}

// TransitionCount counts the scope's transitions at or after since.
func (s *Store) TransitionCount(ctx context.Context, sc model.Scope, since time.Time) (int, error) {
	w, err := transitionScopeWhere(sc)
	if err != nil {
		return 0, err
	}
	if !since.IsZero() {
		w.add(`at >= ?`, nanos(since))
	}
	var n int
	if err := s.rdb.QueryRowContext(ctx, `SELECT count(*) FROM transitions`+w.String(), w.args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count transitions: %w", err)
	}
	return n, nil
}
