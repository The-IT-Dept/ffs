package store

import (
	"context"
	"database/sql"
	"time"
)

// TransitionsKept is how many of a finding's latest transitions PruneTransitions keeps, whatever
// their age.
const TransitionsKept = 20

// PruneTransitions bounds the history of findings that stay: it deletes transitions before
// olderThan, except each fingerprint's latest keep. State flaps and repeated UpgradeAvailable
// announcements on a long-lived open finding would otherwise grow the table without bound, since
// PruneResolved deletes a finding's history only once the finding itself is gone. Only fingerprints
// with more than keep transitions are ranked. It returns the number of transitions deleted.
func (s *Store) PruneTransitions(ctx context.Context, olderThan time.Time, keep int) (int, error) {
	if olderThan.IsZero() {
		return 0, nil // nothing is older than the zero time
	}
	var n int64
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM transitions WHERE at < ? AND id IN (
			SELECT id FROM (SELECT id, row_number() OVER (PARTITION BY fingerprint ORDER BY id DESC) AS rn FROM transitions
				WHERE fingerprint IN (SELECT fingerprint FROM transitions GROUP BY fingerprint HAVING count(*) > ?))
			WHERE rn > ?)`, nanos(olderThan), keep, keep)
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	return int(n), err
}
