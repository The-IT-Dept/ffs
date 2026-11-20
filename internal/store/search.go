package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/the-it-dept/ffs/internal/model"
)

// CountFindings returns the number of findings matching f, ignoring Limit and Offset.
func (s *Store) CountFindings(ctx context.Context, f FindingFilter) (int, error) {
	w := findingWhere(f)
	var n int
	err := s.rdb.QueryRowContext(ctx, `SELECT count(*) FROM findings`+w.String(), w.args...).Scan(&n)
	return n, err
}

// GetFinding returns the finding with the given fingerprint.
func (s *Store) GetFinding(ctx context.Context, fingerprint string) (model.Finding, bool, error) {
	f, err := scanFinding(s.rdb.QueryRowContext(ctx, `SELECT fingerprint, data FROM findings WHERE fingerprint = ?`, fingerprint))
	if errors.Is(err, sql.ErrNoRows) {
		return model.Finding{}, false, nil
	}
	return f, err == nil, err
}

// likePattern turns q into a case-insensitive substring pattern for LIKE ... ESCAPE '\', with the
// wildcards in q escaped.
func likePattern(q string) string {
	return "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(q) + "%"
}
