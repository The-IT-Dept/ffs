package store

import (
	"context"
	"database/sql"
	"time"
)

// SetAdvisoryKEV sets the KEVAdded field of the stored advisory id (or any of its aliases) resolves
// to, and nothing else; nil clears it. An unknown id is a no-op.
func (s *Store) SetAdvisoryKEV(ctx context.Context, id string, added *time.Time) error {
	var v any // nil binds SQL NULL, which json_set stores as JSON null
	if added != nil {
		v = added.UTC().Format(time.RFC3339Nano)
	}
	return s.inTx(ctx, func(tx *sql.Tx) error {
		canon, err := canonical(ctx, tx, id)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE advisories SET data = json_set(data, '$.KEVAdded', ?) WHERE id = ?`, v, canon)
		return err
	})
}

// SetAdvisoryEPSS sets the EPSS and EPSSPercentile fields of the stored advisory id (or any of its
// aliases) resolves to, and nothing else. An unknown id is a no-op.
func (s *Store) SetAdvisoryEPSS(ctx context.Context, id string, epss, percentile float64) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		canon, err := canonical(ctx, tx, id)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx,
			`UPDATE advisories SET data = json_set(data, '$.EPSS', ?, '$.EPSSPercentile', ?) WHERE id = ?`, epss, percentile, canon)
		return err
	})
}

func canonical(ctx context.Context, q querier, id string) (string, error) {
	m, err := canonicals(ctx, q, []string{id})
	return m[id], err
}

// AdvisoryIDsOnDigests returns the sorted distinct advisory ids matched on digests.
func (s *Store) AdvisoryIDsOnDigests(ctx context.Context, digests []string) ([]string, error) {
	return queryAll(ctx, s.rdb, scanString,
		`SELECT DISTINCT advisory_id FROM matches WHERE digest IN (SELECT value FROM json_each(?)) ORDER BY advisory_id`, idList(digests))
}
