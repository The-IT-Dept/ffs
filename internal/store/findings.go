package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/the-it-dept/ffs/internal/model"
)

// FindingFilter selects findings; empty fields match everything. Results are ordered by priority
// descending, then advisory id and owner key.
type FindingFilter struct {
	States      []model.FindingState
	MinPriority model.Priority
	Namespace   string
	OwnerKey    string
	AdvisoryIDs []string // matched through aliases
	Limit       int      // 0 = no limit
	Offset      int
}

// FindingRekey moves a finding to a new fingerprint after its advisory was re-keyed by an alias merge.
type FindingRekey struct{ OldFingerprint, NewFingerprint, AdvisoryID string }

// defaultTransitionsLimit applies when TransitionsAfter is called with limit <= 0.
const defaultTransitionsLimit = 1000

// ApplyFindings upserts findings by fingerprint and appends transitions in slice order, all in one
// transaction. Transition IDs come from an AUTOINCREMENT key (t.ID is ignored), so an ID is never
// reused after a prune. Each upsert's Suggestion is replaced by the stored suggestion for its owner
// and image repository, or nil, so a recompute never overwrites one.
func (s *Store) ApplyFindings(ctx context.Context, upserts []model.Finding, ts []model.Transition) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		sugs := &suggestionCache{tx: tx, seen: map[SuggestionKey]*model.Suggestion{}}
		for _, f := range upserts {
			sg, err := sugs.get(ctx, f.Owner.Key(), f.ImageRepo)
			if err != nil {
				return fmt.Errorf("store: suggestion for %q: %w", f.Fingerprint, err)
			}
			f.Suggestion = sg
			data, err := jsonText(f)
			if err != nil {
				return err
			}
			var resolvedAt any
			if f.ResolvedAt != nil {
				resolvedAt = nanos(*f.ResolvedAt)
			}
			if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO findings(fingerprint, owner_key, namespace, advisory_id, state, priority, data, resolved_at)
				VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
				f.Fingerprint, f.Owner.Key(), f.Owner.Namespace, f.AdvisoryID, string(f.State), int(f.Priority), data, resolvedAt); err != nil {
				return fmt.Errorf("store: finding %q: %w", f.Fingerprint, err)
			}
		}
		return appendTransitions(ctx, tx, ts)
	})
}

// appendTransitions appends ts to the transitions outbox in slice order. t.ID is ignored and a
// zero t.At is set to now.
func appendTransitions(ctx context.Context, tx *sql.Tx, ts []model.Transition) error {
	for _, t := range ts {
		t.ID = 0
		t.At = orNow(t.At)
		data, err := jsonText(t)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO transitions(fingerprint, data, at) VALUES(?, ?, ?)`,
			t.Fingerprint, data, nanos(t.At)); err != nil {
			return fmt.Errorf("store: transition for %q: %w", t.Fingerprint, err)
		}
	}
	return nil
}

// RekeyFindings applies alias re-keys in one transaction. When no finding holds NewFingerprint,
// the old row takes the new fingerprint and advisory id (in its columns and data); otherwise the
// old row is deleted. Notification ledger rows move to the new fingerprint either way, replacing
// any already there. Transitions keep the old fingerprint as history.
func (s *Store) RekeyFindings(ctx context.Context, rks []FindingRekey) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		for _, rk := range rks {
			var taken bool
			if rk.NewFingerprint != rk.OldFingerprint {
				if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM findings WHERE fingerprint = ?)`,
					rk.NewFingerprint).Scan(&taken); err != nil {
					return err
				}
			}
			var err error
			if taken {
				_, err = tx.ExecContext(ctx, `DELETE FROM findings WHERE fingerprint = ?`, rk.OldFingerprint)
			} else {
				_, err = tx.ExecContext(ctx, `UPDATE findings SET fingerprint = ?, advisory_id = ?,
					data = json_set(data, '$.Fingerprint', ?, '$.AdvisoryID', ?) WHERE fingerprint = ?`,
					rk.NewFingerprint, rk.AdvisoryID, rk.NewFingerprint, rk.AdvisoryID, rk.OldFingerprint)
			}
			if err != nil {
				return fmt.Errorf("store: rekey finding %q: %w", rk.OldFingerprint, err)
			}
			// The never-twice ledger follows the finding, so an alias merge is not re-alerted.
			if rk.NewFingerprint != rk.OldFingerprint {
				if _, err := tx.ExecContext(ctx, `UPDATE OR REPLACE notified SET fingerprint = ? WHERE fingerprint = ?`,
					rk.NewFingerprint, rk.OldFingerprint); err != nil {
					return fmt.Errorf("store: rekey ledger %q: %w", rk.OldFingerprint, err)
				}
			}
		}
		return nil
	})
}

// FindingsForOwner returns every finding of the owner, in any state.
func (s *Store) FindingsForOwner(ctx context.Context, key string) ([]model.Finding, error) {
	return s.ListFindings(ctx, FindingFilter{OwnerKey: key})
}

// OwnersWithAdvisories returns the sorted keys of owners with an open or excepted finding on any
// alias of the canonicals of ids.
func (s *Store) OwnersWithAdvisories(ctx context.Context, ids []string) ([]string, error) {
	list := idList(ids)
	return queryAll(ctx, s.rdb, scanString, `SELECT DISTINCT owner_key FROM findings
		WHERE state IN ('open', 'excepted') AND `+sameAdvisory("advisory_id")+` ORDER BY owner_key`, list, list)
}

// ListFindings returns the findings matching f.
func (s *Store) ListFindings(ctx context.Context, f FindingFilter) ([]model.Finding, error) {
	var w where
	if len(f.States) > 0 {
		states := make([]string, len(f.States))
		for i, st := range f.States {
			states[i] = string(st)
		}
		w.add(`state IN (SELECT value FROM json_each(?))`, idList(states))
	}
	if f.MinPriority > model.PriorityNone {
		w.add(`priority >= ?`, int(f.MinPriority))
	}
	if f.Namespace != "" {
		w.add(`namespace = ?`, f.Namespace)
	}
	if f.OwnerKey != "" {
		w.add(`owner_key = ?`, f.OwnerKey)
	}
	if len(f.AdvisoryIDs) > 0 {
		list := idList(f.AdvisoryIDs)
		w.add(sameAdvisory("advisory_id"), list, list)
	}
	return queryAll(ctx, s.rdb, scanFinding, `SELECT fingerprint, data FROM findings`+w.String()+
		` ORDER BY priority DESC, advisory_id, owner_key, fingerprint`+limitOffset(f.Limit, f.Offset), w.args...)
}

func scanFinding(r scanner) (model.Finding, error) {
	var (
		f        model.Finding
		fp, data string
	)
	if err := r.Scan(&fp, &data); err != nil {
		return model.Finding{}, err
	}
	if err := json.Unmarshal([]byte(data), &f); err != nil {
		return model.Finding{}, fmt.Errorf("finding %s: %w", fp, err)
	}
	return f, nil
}

// TransitionsAfter returns up to limit transitions with ID > afterID in ascending ID order, with
// ID populated. limit <= 0 means 1000.
func (s *Store) TransitionsAfter(ctx context.Context, afterID int64, limit int) ([]model.Transition, error) {
	if limit <= 0 {
		limit = defaultTransitionsLimit
	}
	return queryAll(ctx, s.rdb, func(r scanner) (model.Transition, error) {
		var (
			t    model.Transition
			id   int64
			data string
		)
		if err := r.Scan(&id, &data); err != nil {
			return model.Transition{}, err
		}
		if err := json.Unmarshal([]byte(data), &t); err != nil {
			return model.Transition{}, fmt.Errorf("transition %d: %w", id, err)
		}
		t.ID = id
		return t, nil
	}, `SELECT id, data FROM transitions WHERE id > ? ORDER BY id LIMIT ?`, afterID, limit)
}

// Cursor returns the last transition ID the consumer processed, 0 when it has none.
func (s *Store) Cursor(ctx context.Context, consumer string) (int64, error) {
	var id int64
	err := s.rdb.QueryRowContext(ctx, `SELECT id FROM cursors WHERE consumer = ?`, consumer).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return id, err
}

// SetCursor records the last transition ID the consumer processed.
func (s *Store) SetCursor(ctx context.Context, consumer string, id int64) error {
	_, err := s.wdb.ExecContext(ctx, `INSERT OR REPLACE INTO cursors(consumer, id) VALUES(?, ?)`, consumer, id)
	return err
}

// PruneResolved deletes resolved findings with resolved_at before olderThan, and transitions
// before olderThan whose fingerprint no longer has a finding. It returns the findings deleted.
func (s *Store) PruneResolved(ctx context.Context, olderThan time.Time) (int, error) {
	if olderThan.IsZero() {
		return 0, nil // nothing is older than the zero time
	}
	cutoff := olderThan.UTC().UnixNano()
	var n int64
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM findings WHERE state = ? AND resolved_at < ?`, string(model.StateResolved), cutoff)
		if err != nil {
			return err
		}
		if n, err = res.RowsAffected(); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM transitions WHERE at < ?
			AND NOT EXISTS (SELECT 1 FROM findings WHERE findings.fingerprint = transitions.fingerprint)`, cutoff)
		return err
	})
	return int(n), err
}
