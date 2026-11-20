package store

import (
	"context"
	"fmt"

	"github.com/the-it-dept/ffs/internal/model"
)

// FindingCount is the number of open findings of one owner at one priority, by whether a fix is
// available and whether the advisory is in CISA KEV.
type FindingCount struct {
	OwnerKey, Namespace string
	Priority            model.Priority
	FixAvailable, KEV   bool
	N                   int
}

// OpenFindingCounts counts the open findings by owner, priority, fix availability and KEV listing,
// in SQL: no finding is decoded. KEV is the advisory's listing (Advisory.KEVAdded), as stored now.
func (s *Store) OpenFindingCounts(ctx context.Context) ([]FindingCount, error) {
	out, err := queryAll(ctx, s.rdb, func(r scanner) (FindingCount, error) {
		var c FindingCount
		var p int
		err := r.Scan(&c.OwnerKey, &c.Namespace, &p, &c.FixAvailable, &c.KEV, &c.N)
		c.Priority = model.Priority(p)
		return c, err
	}, `SELECT f.owner_key, f.namespace, f.priority, f.fix_available != 0, json_extract(a.data, '$.KEVAdded') IS NOT NULL, count(*)
		FROM findings f LEFT JOIN advisories a ON a.id = f.advisory_id
		WHERE f.state = ?
		GROUP BY 1, 2, 3, 4, 5 ORDER BY 1, 3, 4, 5`, string(model.StateOpen))
	if err != nil {
		return nil, fmt.Errorf("store: open finding counts: %w", err)
	}
	return out, nil
}
