package store

import "context"

// CountExceptedBy returns how many findings the Exception key ("namespace/name") excepts. It reads
// the indexed excepted_by column and decodes no finding.
func (s *Store) CountExceptedBy(ctx context.Context, key string) (int, error) {
	var n int
	err := s.rdb.QueryRowContext(ctx, `SELECT count(*) FROM findings WHERE excepted_by = ?`, key).Scan(&n)
	return n, err
}
