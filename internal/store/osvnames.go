package store

import (
	"context"
	"database/sql"
	"slices"
	"time"

	"github.com/the-it-dept/ffs/internal/model"
)

// PutOSVRecordNames replaces the index names of the cached record id in bucket. Empty names are
// ignored; no names removes the record from the index.
func (s *Store) PutOSVRecordNames(ctx context.Context, bucket, id string, names []string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error { return putOSVRecordNames(ctx, tx, bucket, id, names) })
}

func putOSVRecordNames(ctx context.Context, tx *sql.Tx, bucket, id string, names []string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM osv_record_names WHERE bucket = ? AND id = ?`, bucket, id); err != nil {
		return err
	}
	ins, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO osv_record_names(bucket, id, name) VALUES(?, ?, ?)`)
	if err != nil {
		return err
	}
	defer func() { _ = ins.Close() }()
	for _, n := range names {
		if n == "" {
			continue
		}
		if _, err := ins.ExecContext(ctx, bucket, id, n); err != nil {
			return err
		}
	}
	return nil
}

// OSVRecordIDsByName returns the sorted IDs of the records in bucket indexed under any of names.
func (s *Store) OSVRecordIDsByName(ctx context.Context, bucket string, names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, nil
	}
	ids, err := queryAll(ctx, s.rdb, scanString, osvRecordIDsByNameQuery, bucket, idList(names))
	if err != nil {
		return nil, err
	}
	slices.Sort(ids)
	return slices.Compact(ids), nil
}

// osvRecordIDsByNameQuery leaves DISTINCT and ORDER BY to Go: with them SQLite walks the primary
// key, every index name of the bucket in id order (over a million rows for Ubuntu), instead of
// looking each name up in osv_record_names_by_name.
const osvRecordIDsByNameQuery = `SELECT id FROM osv_record_names WHERE bucket = ? AND name IN (SELECT value FROM json_each(?))`

// OSVRecordsByID returns the decompressed cached records with any of ids, in any bucket, ordered by
// id. A record cached in several buckets is returned once: its most recently modified copy.
func (s *Store) OSVRecordsByID(ctx context.Context, ids []string) ([][]byte, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	return queryAll(ctx, s.rdb, scanZstd, `SELECT raw_zst FROM (
			SELECT id, raw_zst, ROW_NUMBER() OVER (PARTITION BY id ORDER BY modified DESC, ecosystem) AS n
			FROM osv_records WHERE id IN (SELECT value FROM json_each(?)))
		WHERE n = 1 ORDER BY id`, idList(ids))
}

// OSVRecordIDs returns the sorted IDs of the records cached in bucket.
func (s *Store) OSVRecordIDs(ctx context.Context, bucket string) ([]string, error) {
	return queryAll(ctx, s.rdb, scanString, `SELECT id FROM osv_records WHERE ecosystem = ? ORDER BY id`, bucket)
}

// PruneOSVRecords removes the records of bucket last modified before olderThan, with their index
// names, and returns how many it removed. A record whose canonical advisory still has matches from
// the osv source is kept: dropping it would let those findings resolve without a real fix. So is a
// malicious-package record (MAL-): the Grype DB has none, so the cache is the only place a newly
// catalogued image can find one, however old.
func (s *Store) PruneOSVRecords(ctx context.Context, bucket string, olderThan time.Time) (int, error) {
	var n int
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		ids, err := queryAll(ctx, tx, scanString, `SELECT r.id FROM osv_records r
			WHERE r.ecosystem = ? AND r.modified < ? AND substr(r.id, 1, 4) != 'MAL-'
			AND NOT EXISTS (SELECT 1 FROM matches m WHERE m.source = ? AND m.advisory_id =
				COALESCE((SELECT a.canonical FROM advisory_aliases a WHERE a.alias = r.id), r.id))`,
			bucket, nanos(olderThan), string(model.SourceOSV))
		if err != nil || len(ids) == 0 {
			return err
		}
		n = len(ids)
		return deleteOSVRecords(ctx, tx, bucket, ids)
	})
	return n, err
}

// deleteOSVRecords removes the records of bucket with the given ids and their index names.
func deleteOSVRecords(ctx context.Context, tx *sql.Tx, bucket string, ids []string) error {
	list := idList(ids)
	if _, err := tx.ExecContext(ctx, `DELETE FROM osv_record_names WHERE bucket = ? AND id IN (SELECT value FROM json_each(?))`,
		bucket, list); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM osv_records WHERE ecosystem = ? AND id IN (SELECT value FROM json_each(?))`, bucket, list)
	return err
}

func scanZstd(r scanner) ([]byte, error) {
	var zst []byte
	if err := r.Scan(&zst); err != nil {
		return nil, err
	}
	return zstdDecode(zst)
}
