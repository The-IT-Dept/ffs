package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/the-it-dept/ffs/internal/model"
)

// UpsertOwner stores o under o.Ref.Key() and replaces its owner_images rows. Containers without a
// resolved digest are not indexed.
//
// A cluster-level ContainerRuntime owner is not stored while the node agent has retired the runtime
// owner (NodesState.RuntimeRetired): the check and the write are one transaction, so an inventory flush
// that read the state before a runtime cutover cannot bring the retired owner back.
func (s *Store) UpsertOwner(ctx context.Context, o model.Owner) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if o.Ref.ClusterLevel() && o.Ref.Kind == model.OwnerKindContainerRuntime {
			state, err := nodesState(ctx, tx)
			if err != nil {
				return err
			}
			if state.RuntimeRetired {
				return nil
			}
		}
		return upsertOwnerTx(ctx, tx, o)
	})
}

// upsertOwnerTx is UpsertOwner inside tx.
func upsertOwnerTx(ctx context.Context, tx *sql.Tx, o model.Owner) error {
	data, err := jsonText(o)
	if err != nil {
		return err
	}
	key := o.Ref.Key()
	if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO owners(key, namespace, data, updated_at) VALUES(?, ?, ?, ?)`,
		key, o.Ref.Namespace, data, nanos(o.UpdatedAt)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM owner_images WHERE owner_key = ?`, key); err != nil {
		return err
	}
	for _, c := range o.Containers {
		if c.Digest == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO owner_images(owner_key, digest, container) VALUES(?, ?, ?)`,
			key, c.Digest, c.Name); err != nil {
			return err
		}
	}
	return nil
}

// DeleteOwner removes the owner with its owner_images rows and its upgrade suggestions,
// candidates and announcements.
func (s *Store) DeleteOwner(ctx context.Context, key string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error { return deleteOwnerTx(ctx, tx, key) })
}

// deleteOwnerTx is DeleteOwner inside tx.
func deleteOwnerTx(ctx context.Context, tx *sql.Tx, key string) error {
	for _, q := range []string{
		`DELETE FROM owner_images WHERE owner_key = ?`,
		`DELETE FROM suggestions WHERE owner_key = ?`,
		`DELETE FROM candidates WHERE owner_key = ?`,
		`DELETE FROM announcements WHERE owner_key = ?`,
		`DELETE FROM owners WHERE key = ?`,
	} {
		if _, err := tx.ExecContext(ctx, q, key); err != nil {
			return err
		}
	}
	return nil
}

// GetOwner returns the owner stored under key ("Kind/Namespace/Name").
func (s *Store) GetOwner(ctx context.Context, key string) (model.Owner, bool, error) {
	o, err := scanOwner(s.rdb.QueryRowContext(ctx, `SELECT key, data FROM owners WHERE key = ?`, key))
	if errors.Is(err, sql.ErrNoRows) {
		return model.Owner{}, false, nil
	}
	return o, err == nil, err
}

// ListOwners returns every owner, ordered by key.
func (s *Store) ListOwners(ctx context.Context) ([]model.Owner, error) {
	return queryAll(ctx, s.rdb, scanOwner, `SELECT key, data FROM owners ORDER BY key`)
}

// OwnersForDigests returns the sorted keys of owners running any of digests.
func (s *Store) OwnersForDigests(ctx context.Context, digests []string) ([]string, error) {
	return queryAll(ctx, s.rdb, scanString,
		`SELECT DISTINCT owner_key FROM owner_images WHERE digest IN (SELECT value FROM json_each(?)) ORDER BY owner_key`,
		idList(digests))
}

// DigestsInUse returns the sorted digests referenced by any owner.
func (s *Store) DigestsInUse(ctx context.Context) ([]string, error) {
	return queryAll(ctx, s.rdb, scanString, `SELECT DISTINCT digest FROM owner_images ORDER BY digest`)
}

func scanOwner(r scanner) (model.Owner, error) {
	var (
		o         model.Owner
		key, data string
	)
	if err := r.Scan(&key, &data); err != nil {
		return model.Owner{}, err
	}
	if err := json.Unmarshal([]byte(data), &o); err != nil {
		return model.Owner{}, fmt.Errorf("owner %s: %w", key, err)
	}
	return o, nil
}
