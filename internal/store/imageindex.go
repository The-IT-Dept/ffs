package store

import (
	"context"
	"database/sql"
	"errors"
)

// PlatformDigest returns the platform manifest digest already recorded for an index digest and platform.
func (s *Store) PlatformDigest(ctx context.Context, indexDigest, platform string) (string, bool, error) {
	var d string
	err := s.rdb.QueryRowContext(ctx, `SELECT digest FROM images WHERE index_digest = ? AND platform = ? LIMIT 1`,
		indexDigest, platform).Scan(&d)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return d, err == nil, err
}
