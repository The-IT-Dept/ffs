package store

import (
	"context"

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
