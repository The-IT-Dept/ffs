package store

import (
	"context"
	"database/sql"
	"strings"

	"github.com/the-it-dept/ffs/internal/model"
)

// The rollups answer the dashboard's and API's counts with SQL aggregates over indexed columns, so a
// page load decodes no finding or package it does not show (fix wave F37).

// syntheticDigest matches the cluster-level subjects' digests ("k8s:…", "runtime:…"), which are
// not container images.
const syntheticDigest = `(digest LIKE 'k8s:%' OR digest LIKE 'runtime:%')`

// AdvisoryRollup summarises the open findings on one advisory.
type AdvisoryRollup struct {
	AdvisoryID      string
	HighestPriority model.Priority
	Severity        model.Severity // highest
	Owners          int            // distinct owners
	Findings        int
	FixAvailable    bool // any finding has a fixed version
}

// OpenAdvisoryRollups returns one rollup per advisory with an open finding, by advisory id.
func (s *Store) OpenAdvisoryRollups(ctx context.Context) ([]AdvisoryRollup, error) {
	return queryAll(ctx, s.rdb, func(r scanner) (AdvisoryRollup, error) {
		var (
			a          AdvisoryRollup
			prio       int
			severities sql.NullString
			fix        sql.NullInt64
		)
		if err := r.Scan(&a.AdvisoryID, &prio, &a.Owners, &a.Findings, &severities, &fix); err != nil {
			return AdvisoryRollup{}, err
		}
		a.HighestPriority, a.FixAvailable = model.Priority(prio), fix.Int64 > 0
		for _, sv := range strings.Split(severities.String, ",") {
			a.Severity = max(a.Severity, model.ParseSeverity(sv))
		}
		return a, nil
	}, advisoryRollupQuery)
}

// The rollup queries read only columns and expressions of the findings_rollup index (migration
// 030), so SQLite answers them from the index: keep the json_extract expressions identical.
const (
	advisoryRollupQuery = `SELECT advisory_id, max(priority), count(DISTINCT owner_key), count(*),
		group_concat(DISTINCT json_extract(data, '$.Severity')), max(json_extract(data, '$.FixAvailable'))
		FROM findings WHERE state = 'open' GROUP BY advisory_id ORDER BY advisory_id`
	ownerCountsQuery = `SELECT owner_key, priority, count(*) FROM findings WHERE state = 'open' GROUP BY owner_key, priority`
)

// OpenCountsByOwner returns the open findings of every owner that has any, by owner key and priority.
func (s *Store) OpenCountsByOwner(ctx context.Context) (map[string]map[model.Priority]int, error) {
	type row struct {
		key  string
		prio model.Priority
		n    int
	}
	rows, err := queryAll(ctx, s.rdb, func(r scanner) (row, error) {
		var x row
		var prio int
		err := r.Scan(&x.key, &prio, &x.n)
		x.prio = model.Priority(prio)
		return x, err
	}, ownerCountsQuery)
	if err != nil {
		return nil, err
	}
	out := map[string]map[model.Priority]int{}
	for _, x := range rows {
		if out[x.key] == nil {
			out[x.key] = map[model.Priority]int{}
		}
		out[x.key][x.prio] = x.n
	}
	return out, nil
}

// ClassifiedPackages returns, by image digest, the packages of digests that a binary classifier
// found: the only ones the read-time coverage notes look at.
func (s *Store) ClassifiedPackages(ctx context.Context, digests []string) (map[string][]model.Package, error) {
	ps, err := queryAll(ctx, s.rdb, scanPackage, `SELECT `+packageCols+` FROM packages
		WHERE classifier != '' AND digest IN (SELECT value FROM json_each(?)) ORDER BY digest, name, version, id`, idList(digests))
	if err != nil {
		return nil, err
	}
	out := map[string][]model.Package{}
	for _, p := range ps {
		out[p.ImageDigest] = append(out[p.ImageDigest], p)
	}
	return out, nil
}

// ImageStatuses returns the status of each of digests that has an image row.
func (s *Store) ImageStatuses(ctx context.Context, digests []string) (map[string]model.ImageStatus, error) {
	type row struct {
		digest string
		status model.ImageStatus
	}
	rows, err := queryAll(ctx, s.rdb, func(r scanner) (row, error) {
		var x row
		err := r.Scan(&x.digest, &x.status)
		return x, err
	}, `SELECT digest, status FROM images WHERE digest IN (SELECT value FROM json_each(?))`, idList(digests))
	if err != nil {
		return nil, err
	}
	out := make(map[string]model.ImageStatus, len(rows))
	for _, x := range rows {
		out[x.digest] = x.status
	}
	return out, nil
}

// InUseImageCoverage counts the container images some owner runs (cluster-level subjects excluded):
// how many are catalogued, and how many are not, which includes images with no row yet.
func (s *Store) InUseImageCoverage(ctx context.Context) (catalogued, uncatalogued int, err error) {
	err = s.rdb.QueryRowContext(ctx, `SELECT
			count(CASE WHEN i.status = ? THEN 1 END), count(CASE WHEN i.status IS NULL OR i.status != ? THEN 1 END)
		FROM (SELECT DISTINCT digest FROM owner_images WHERE NOT `+syntheticDigest+`) o
		LEFT JOIN images i ON i.digest = o.digest`, string(model.ImageCatalogued), string(model.ImageCatalogued)).
		Scan(&catalogued, &uncatalogued)
	return catalogued, uncatalogued, err
}
