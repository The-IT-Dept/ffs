package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/the-it-dept/ffs/internal/model"
)

// FindingMove moves the finding at OldFingerprint to NewFingerprint, owned by Owner on ImageRepo.
type FindingMove struct {
	OldFingerprint, NewFingerprint string
	Owner                          model.OwnerRef
	ImageRepo                      string
}

// Rehome moves findings between owners in one transaction, so a recompute never sees a half-moved
// owner. It first stores upsert (when non-nil) as UpsertOwner does, then applies each move whose
// fingerprints differ:
//   - no finding, or a resolved one, at NewFingerprint: that row is deleted and the moved finding takes
//     its place, with its owner_key, namespace and data ($.Fingerprint, $.Owner, $.ImageRepo)
//     rewritten. Its notification ledger rows move with it and replace any already there, so the moved
//     finding and its ledger win and a later recompute is not a reopening;
//   - an open or excepted finding at NewFingerprint (the target already reported it): that finding is
//     kept and the moved one deleted. Its ledger rows move only where the target has none for the new
//     fingerprint; each target keeps the ledger it already has, and the leftovers are deleted.
//
// Finally every owner in drop is deleted as DeleteOwner does. Transitions keep their old fingerprints
// as history.
//
// Rehome is the cutover counterpart of RekeyFindings (the alias re-key): it also rewrites the owner
// and image repository, replaces resolved targets and keeps the ledger of taken ones, so cutting over
// again never reopens a finding resolved in an earlier cycle.
func (s *Store) Rehome(ctx context.Context, upsert *model.Owner, moves []FindingMove, drop []string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if upsert != nil {
			if err := upsertOwnerTx(ctx, tx, *upsert); err != nil {
				return fmt.Errorf("store: rehome owner %s: %w", upsert.Ref.Key(), err)
			}
		}
		for _, m := range moves {
			if m.NewFingerprint == m.OldFingerprint {
				continue
			}
			if err := moveFinding(ctx, tx, m); err != nil {
				return fmt.Errorf("store: rehome finding %q: %w", m.OldFingerprint, err)
			}
		}
		for _, key := range drop {
			if err := deleteOwnerTx(ctx, tx, key); err != nil {
				return fmt.Errorf("store: rehome drop owner %s: %w", key, err)
			}
		}
		return nil
	})
}

// moveFinding applies one move of Rehome inside tx.
func moveFinding(ctx context.Context, tx *sql.Tx, m FindingMove) error {
	var state string
	err := tx.QueryRowContext(ctx, `SELECT state FROM findings WHERE fingerprint = ?`, m.NewFingerprint).Scan(&state)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		state = ""
	case err != nil:
		return err
	}
	if state != "" && model.FindingState(state) != model.StateResolved {
		// The target already reported the new fingerprint: it keeps its finding and ledger.
		if _, err := tx.ExecContext(ctx, `DELETE FROM findings WHERE fingerprint = ?`, m.OldFingerprint); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE OR IGNORE notified SET fingerprint = ? WHERE fingerprint = ?`,
			m.NewFingerprint, m.OldFingerprint); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM notified WHERE fingerprint = ?`, m.OldFingerprint)
		return err
	}
	if state != "" {
		if _, err := tx.ExecContext(ctx, `DELETE FROM findings WHERE fingerprint = ?`, m.NewFingerprint); err != nil {
			return err
		}
	}
	owner, err := jsonText(m.Owner)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE findings SET fingerprint = ?, owner_key = ?, namespace = ?,
		data = json_set(data, '$.Fingerprint', ?, '$.Owner', json(?), '$.ImageRepo', ?) WHERE fingerprint = ?`,
		m.NewFingerprint, m.Owner.Key(), m.Owner.Namespace, m.NewFingerprint, owner, m.ImageRepo, m.OldFingerprint); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE OR REPLACE notified SET fingerprint = ? WHERE fingerprint = ?`,
		m.NewFingerprint, m.OldFingerprint)
	return err
}
