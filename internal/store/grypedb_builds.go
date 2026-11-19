package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// grypeDBBuildsKept is how many Grype DB builds RecordGrypeDBBuild keeps. Two builds after an
// observation settle a provisional finding, so a month of daily builds is ample.
const grypeDBBuildsKept = 30

// RecordGrypeDBBuild records the build time of a loaded Grype DB. Recording a build twice is a
// no-op, and only the newest 30 builds are kept.
func (s *Store) RecordGrypeDBBuild(ctx context.Context, built time.Time) error {
	if built.IsZero() {
		return errors.New("store: grype DB build without a build time")
	}
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO grypedb_builds(built) VALUES(?)`, nanos(built)); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM grypedb_builds WHERE built NOT IN (
			SELECT built FROM grypedb_builds ORDER BY built DESC LIMIT ?)`, grypeDBBuildsKept)
		return err
	})
}

// GrypeDBBuilds returns the recorded Grype DB build times in ascending order.
func (s *Store) GrypeDBBuilds(ctx context.Context) ([]time.Time, error) {
	return queryAll(ctx, s.rdb, func(r scanner) (time.Time, error) {
		var v sql.NullInt64
		err := r.Scan(&v)
		return fromNanos(v), err
	}, `SELECT built FROM grypedb_builds ORDER BY built`)
}
