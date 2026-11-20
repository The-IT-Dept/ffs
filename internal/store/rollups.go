package store

import (
	"context"

	"github.com/the-it-dept/ffs/internal/model"
)

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
