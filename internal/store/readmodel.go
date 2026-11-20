package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/the-it-dept/ffs/internal/model"
)

// The web UI's read model (migrations 050–054): generated filter columns on findings, owners,
// images and transitions, and the owner_stats, finding_digests and finding_packages rollups that
// triggers on findings keep inside every writing transaction.

// ErrBadCursor is returned for a page cursor that does not decode to the current query's sort.
var ErrBadCursor = errors.New("store: cursor does not belong to this query")

// ErrScope is returned, wrapped with the scope kind, for a scope a query does not support.
var ErrScope = errors.New("store: scope not supported by this query")

// PriorityCounts counts open findings by priority.
type PriorityCounts struct{ Urgent, High, Medium, Low int }

// Worst is the highest priority with a non-zero count, and PriorityNone when every count is zero.
func (c PriorityCounts) Worst() model.Priority {
	switch {
	case c.Urgent > 0:
		return model.PriorityUrgent
	case c.High > 0:
		return model.PriorityHigh
	case c.Medium > 0:
		return model.PriorityMedium
	case c.Low > 0:
		return model.PriorityLow
	}
	return model.PriorityNone
}

// Total sums the counts.
func (c PriorityCounts) Total() int { return c.Urgent + c.High + c.Medium + c.Low }

// OwnerStats are the rollup counts of an owner, or of a scope. Counts, Open, Fixable, Upgradable,
// Exploited and Provisional count open findings; Excepted counts excepted ones.
type OwnerStats struct {
	Counts                                                      PriorityCounts
	Open, Fixable, Upgradable, Exploited, Provisional, Excepted int
}

// CoverageFigure counts the distinct in-use container images of a scope (InUse), those catalogued
// (SeenInto) and those seen into in full detail (Full).
type CoverageFigure struct{ InUse, SeenInto, Full int }

// FacetValue is one value of a facet and the rows it would select.
type FacetValue struct {
	Value string
	Count int
}

// ownerStatsCols are the owner_stats count columns, in the order scanOwnerStats reads them.
const ownerStatsCols = `urgent, high, medium, low, open, fixable, upgradable, exploited, provisional, excepted`

// ownerStatsSums sums ownerStatsCols, for a scope over several owner_stats rows.
const ownerStatsSums = `sum(urgent), sum(high), sum(medium), sum(low), sum(open), sum(fixable), sum(upgradable),
	sum(exploited), sum(provisional), sum(excepted)`

// findingContributions sums, over the findings aliased f, what each contributes to ownerStatsCols:
// the rule of the 051 triggers.
const findingContributions = `sum(f.state = 'open' AND f.priority = 4), sum(f.state = 'open' AND f.priority = 3),
	sum(f.state = 'open' AND f.priority = 2), sum(f.state = 'open' AND f.priority = 1), sum(f.state = 'open'),
	sum(f.state = 'open' AND f.fix_available), sum(f.state = 'open' AND f.fix_class = 'upgrade'),
	sum(f.state = 'open' AND f.signals & 8 != 0), sum(f.state = 'open' AND f.signals & 32 != 0), sum(f.state = 'excepted')`

// scanOwnerStats scans the lead destinations, then ownerStatsCols in order. NULLs (from a LEFT JOIN
// or a sum over no rows) read as 0.
func scanOwnerStats(r scanner, lead ...any) (OwnerStats, error) {
	var v [10]sql.NullInt64
	dest := make([]any, 0, len(lead)+len(v))
	dest = append(dest, lead...)
	for i := range v {
		dest = append(dest, &v[i])
	}
	if err := r.Scan(dest...); err != nil {
		return OwnerStats{}, err
	}
	n := func(i int) int { return int(v[i].Int64) }
	return OwnerStats{
		Counts: PriorityCounts{Urgent: n(0), High: n(1), Medium: n(2), Low: n(3)},
		Open:   n(4), Fixable: n(5), Upgradable: n(6), Exploited: n(7), Provisional: n(8), Excepted: n(9),
	}, nil
}

// OwnerStatsOf returns the rollup counts of the owners with keys. An owner with no open or excepted
// finding has no entry, so it reads as the zero OwnerStats.
func (s *Store) OwnerStatsOf(ctx context.Context, keys []string) (map[string]OwnerStats, error) {
	out := make(map[string]OwnerStats, len(keys))
	if len(keys) == 0 {
		return out, nil
	}
	rows, err := s.rdb.QueryContext(ctx, `SELECT owner_key, `+ownerStatsCols+` FROM owner_stats
		WHERE owner_key IN (SELECT value FROM json_each(?))`, idList(keys))
	if err != nil {
		return nil, fmt.Errorf("store: owner stats: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var key string
		st, err := scanOwnerStats(rows, &key)
		if err != nil {
			return nil, fmt.Errorf("store: owner stats: %w", err)
		}
		out[key] = st
	}
	return out, rows.Err()
}

// ScopeStats returns the rollup counts of a scope: summed over owner_stats for the cluster,
// namespace, workload and control plane scopes, and over the findings on the digest for image and
// node group scopes. A node scope is resolved to its group by the caller; it returns ErrScope.
func (s *Store) ScopeStats(ctx context.Context, sc model.Scope) (OwnerStats, error) {
	var (
		query string
		args  []any
	)
	switch sc.Kind {
	case model.ScopeCluster:
		query = `SELECT ` + ownerStatsSums + ` FROM owner_stats`
	case model.ScopeNamespace:
		query, args = `SELECT `+ownerStatsSums+` FROM owner_stats WHERE namespace = ?`, []any{sc.Value}
	case model.ScopeWorkload:
		query, args = `SELECT `+ownerStatsSums+` FROM owner_stats WHERE owner_key = ?`, []any{sc.Value}
	case model.ScopeControlPlane:
		query = `SELECT ` + ownerStatsSums + ` FROM owner_stats WHERE ` + controlPlaneOwners
	case model.ScopeImage, model.ScopeNodeGroup:
		digest := sc.Value
		if sc.Kind == model.ScopeNodeGroup {
			digest = nodeGroupDigestPrefix + sc.Value
		}
		query, args = `SELECT `+findingContributions+` FROM finding_digests d JOIN findings f ON f.fingerprint = d.fingerprint
			WHERE d.digest = ?`, []any{digest}
	default:
		return OwnerStats{}, scopeErr(sc)
	}
	st, err := scanOwnerStats(s.rdb.QueryRowContext(ctx, query, args...))
	if err != nil {
		return OwnerStats{}, fmt.Errorf("store: stats of %s: %w", sc, err)
	}
	return st, nil
}

// nodeGroupDigestPrefix prefixes a node group ID to form the synthetic digest of its host packages.
const nodeGroupDigestPrefix = "nodegroup:"

// controlPlaneOwners selects the Cluster and ContainerRuntime owners, over owner_stats or findings.
const controlPlaneOwners = `owner_kind IN ('Cluster', 'ContainerRuntime') AND namespace = ''`

// scopeErr is ErrScope wrapped with the scope's kind.
func scopeErr(sc model.Scope) error { return fmt.Errorf("%w: %s", ErrScope, sc.Kind) }

// findingScopeWhere is the predicate that narrows findings to a scope. A node scope must be resolved
// to its group first; it and unknown kinds return ErrScope.
func findingScopeWhere(sc model.Scope) (where, error) {
	var w where
	switch sc.Kind {
	case model.ScopeCluster:
	case model.ScopeNamespace:
		w.add(`namespace = ?`, sc.Value)
	case model.ScopeWorkload:
		w.add(`owner_key = ?`, sc.Value)
	case model.ScopeImage:
		w.add(`fingerprint IN (SELECT fingerprint FROM finding_digests WHERE digest = ?)`, sc.Value)
	case model.ScopeNodeGroup:
		w.add(`fingerprint IN (SELECT fingerprint FROM finding_digests WHERE digest = 'nodegroup:' || ?)`, sc.Value)
	case model.ScopeControlPlane:
		w.add(controlPlaneOwners)
	default:
		return where{}, scopeErr(sc)
	}
	return w, nil
}

// CoverageClassOf is how far ffs sees into im: the Go copy of the images.cov_class column (053).
// It is none unless the image is catalogued; partial when its SBOM came from an attestation or it
// holds unattributed executables or Rust binaries without cargo-auditable; full otherwise.
func CoverageClassOf(im model.Image) model.CoverageClass {
	switch {
	case im.Status != model.ImageCatalogued:
		return model.CoverageNone
	case im.Source == "attestation" || im.Coverage.UnattributedELF > 0 || im.Coverage.RustWithoutAuditable > 0:
		return model.CoveragePartial
	}
	return model.CoverageFull
}
