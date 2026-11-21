package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/the-it-dept/ffs/internal/model"
)

// AdvisoriesWithMatches returns, sorted, the ids among the canonical advisory ids that have a stored
// match from source: the advisories a matcher has something to replace on.
func (s *Store) AdvisoriesWithMatches(ctx context.Context, source model.MatchSource, ids []string) ([]string, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	return queryAll(ctx, s.rdb, scanString, `SELECT DISTINCT advisory_id FROM matches
		WHERE advisory_id IN (SELECT value FROM json_each(?)) AND source = ? ORDER BY advisory_id`, idList(ids), string(source))
}

// metaMatchersVersion is the meta key of the matchers version (RecordMatchersVersion).
const metaMatchersVersion = "matchers_version"

// MatchersVersion returns the version of the matchers that last re-matched every live digest with
// every matcher (RecordMatchersVersion), or "" when none has.
func (s *Store) MatchersVersion(ctx context.Context) (string, error) {
	var v string
	err := s.rdb.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, metaMatchersVersion).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// RecordMatchersVersion records that every matcher, at version v, has re-matched every live digest.
func (s *Store) RecordMatchersVersion(ctx context.Context, v string) error {
	_, err := s.wdb.ExecContext(ctx, `INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		metaMatchersVersion, v)
	return err
}
