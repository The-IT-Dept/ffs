package store

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/the-it-dept/ffs/internal/findings"
)

// PutExceptionRule caches r under its namespace and name. It reports false, and writes nothing,
// when the stored rule is identical.
func (s *Store) PutExceptionRule(ctx context.Context, r findings.ExceptionRule) (changed bool, err error) {
	data, err := jsonText(r)
	if err != nil {
		return false, err
	}
	err = s.inTx(ctx, func(tx *sql.Tx) error {
		var stored string
		switch err := tx.QueryRowContext(ctx, `SELECT rule FROM exceptions WHERE namespace = ? AND name = ?`,
			r.Namespace, r.Name).Scan(&stored); {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return err
		case stored == data:
			return nil
		}
		if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO exceptions(namespace, name, rule) VALUES(?, ?, ?)`,
			r.Namespace, r.Name, data); err != nil {
			return fmt.Errorf("store: exception rule %s: %w", r.Key(), err)
		}
		changed = true
		return nil
	})
	return changed, err
}

// DeleteExceptionRule removes the cached rule of an Exception. It reports false when none existed.
func (s *Store) DeleteExceptionRule(ctx context.Context, namespace, name string) (deleted bool, err error) {
	res, err := s.wdb.ExecContext(ctx, `DELETE FROM exceptions WHERE namespace = ? AND name = ?`, namespace, name)
	if err != nil {
		return false, fmt.Errorf("store: delete exception rule %s/%s: %w", namespace, name, err)
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// ExceptionRules returns every cached rule, sorted by Key.
func (s *Store) ExceptionRules(ctx context.Context) ([]findings.ExceptionRule, error) {
	rules, err := queryAll(ctx, s.rdb, func(r scanner) (findings.ExceptionRule, error) {
		var (
			rule findings.ExceptionRule
			data string
		)
		if err := r.Scan(&data); err != nil {
			return rule, err
		}
		if err := json.Unmarshal([]byte(data), &rule); err != nil {
			return rule, fmt.Errorf("exception rule: %w", err)
		}
		return rule, nil
	}, `SELECT rule FROM exceptions`)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(rules, func(a, b findings.ExceptionRule) int { return cmp.Compare(a.Key(), b.Key()) })
	return rules, nil
}
