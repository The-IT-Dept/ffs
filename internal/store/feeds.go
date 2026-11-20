package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// FeedState is a feed's watermark and freshness record.
type FeedState struct {
	Name, Watermark          string
	LastSuccess, LastAttempt time.Time
	LastError                string
	Meta                     map[string]string
}

// FeedState returns the stored state of the named feed, or FeedState{Name: name} when unknown.
func (s *Store) FeedState(ctx context.Context, name string) (FeedState, error) {
	st := FeedState{Name: name}
	var (
		success, attempt sql.NullInt64
		meta             string
	)
	err := s.rdb.QueryRowContext(ctx, `SELECT watermark, last_success, last_attempt, last_error, meta FROM feeds WHERE name = ?`, name).
		Scan(&st.Watermark, &success, &attempt, &st.LastError, &meta)
	if errors.Is(err, sql.ErrNoRows) {
		return FeedState{Name: name}, nil
	}
	if err != nil {
		return FeedState{}, err
	}
	st.LastSuccess = fromNanos(success)
	st.LastAttempt = fromNanos(attempt)
	if err := json.Unmarshal([]byte(meta), &st.Meta); err != nil {
		return FeedState{}, fmt.Errorf("store: feed %s meta: %w", name, err)
	}
	return st, nil
}

// PutFeedState replaces the stored state of st.Name.
func (s *Store) PutFeedState(ctx context.Context, st FeedState) error {
	meta := "{}"
	if len(st.Meta) > 0 {
		var err error
		if meta, err = jsonText(st.Meta); err != nil {
			return err
		}
	}
	_, err := s.wdb.ExecContext(ctx, `INSERT OR REPLACE INTO feeds(name, watermark, last_success, last_attempt, last_error, meta)
		VALUES(?, ?, ?, ?, ?, ?)`, st.Name, st.Watermark, nanos(st.LastSuccess), nanos(st.LastAttempt), st.LastError, meta)
	return err
}

// PutOSVRecord caches a raw OSV record, observed now. See PutOSVRecordAt.
func (s *Store) PutOSVRecord(ctx context.Context, eco, id string, modified time.Time, affectedHash string, raw []byte) (bool, error) {
	return s.PutOSVRecordAt(ctx, eco, id, modified, affectedHash, raw, time.Now())
}

// PutOSVRecordAt caches a raw OSV record that ffs observed at observed. changed is true when there
// was no prior row or its affected hash differs; the latest modified time and raw record are stored
// either way. The record's observation time (OSVRecordsObserved) is observed when it changed, and
// the stored one otherwise: it is when ffs first saw the record's current affected content.
func (s *Store) PutOSVRecordAt(ctx context.Context, eco, id string, modified time.Time, affectedHash string, raw []byte, observed time.Time) (bool, error) {
	var changed bool
	err := s.inTx(ctx, func(tx *sql.Tx) (err error) {
		changed, err = putOSVRecord(ctx, tx, eco, id, modified, affectedHash, raw, observed)
		return err
	})
	return changed, err
}

// PutOSVRecordIndexed is PutOSVRecord and, in the same transaction, PutOSVRecordNames with names
// when the record changed or reindex is set. A failed index write rolls the record back too, so a
// record is never cached without the index entry its change calls for, and the next poll sees it
// as changed again.
func (s *Store) PutOSVRecordIndexed(ctx context.Context, eco, id string, modified time.Time, affectedHash string, raw []byte, names []string, reindex bool) (bool, error) {
	var changed bool
	err := s.inTx(ctx, func(tx *sql.Tx) (err error) {
		if changed, err = putOSVRecord(ctx, tx, eco, id, modified, affectedHash, raw, time.Now()); err != nil {
			return err
		}
		if changed || reindex {
			return putOSVRecordNames(ctx, tx, eco, id, names)
		}
		return nil
	})
	return changed, err
}

func putOSVRecord(ctx context.Context, tx *sql.Tx, eco, id string, modified time.Time, affectedHash string, raw []byte, observed time.Time) (changed bool, _ error) {
	var (
		prev    string
		prevObs sql.NullInt64
	)
	err := tx.QueryRowContext(ctx, `SELECT affected_hash, observed FROM osv_records WHERE ecosystem = ? AND id = ?`, eco, id).
		Scan(&prev, &prevObs)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		changed = true
	case err != nil:
		return false, err
	default:
		changed = prev != affectedHash
	}
	obs := nanos(orNow(observed))
	if !changed && prevObs.Valid {
		obs = prevObs
	}
	_, err = tx.ExecContext(ctx, `INSERT OR REPLACE INTO osv_records(ecosystem, id, modified, affected_hash, raw_zst, observed)
		VALUES(?, ?, ?, ?, ?, ?)`, eco, id, nanos(modified), affectedHash, zstdEncode(raw), obs)
	return changed, err
}

// rehashPage is how many cached OSV records RehashOSVRecords reads and rewrites at a time: enough
// to keep the transactions few, few enough that 4 MiB records cannot hold much memory.
const rehashPage = 64

// RehashOSVRecords recomputes the affected hash of every cached OSV record with hash and stores it,
// rehashPage records at a time, and returns how many hashes changed. Nothing else about a record
// changes: not its raw, modified or observation time, and nothing is reported as changed. A record
// hash cannot read keeps its stored hash.
func (s *Store) RehashOSVRecords(ctx context.Context, hash func(raw []byte) (string, error)) (int, error) {
	type rec struct {
		eco, id, hash string
		raw           []byte
	}
	var (
		changed           int
		afterEco, afterID string
	)
	for {
		page, err := queryAll(ctx, s.rdb, func(r scanner) (rec, error) {
			var (
				v   rec
				zst []byte
			)
			if err := r.Scan(&v.eco, &v.id, &v.hash, &zst); err != nil {
				return v, err
			}
			raw, err := zstdDecode(zst)
			v.raw = raw
			return v, err
		}, `SELECT ecosystem, id, affected_hash, raw_zst FROM osv_records WHERE (ecosystem, id) > (?, ?)
			ORDER BY ecosystem, id LIMIT ?`, afterEco, afterID, rehashPage)
		if err != nil {
			return changed, err
		}
		if len(page) == 0 {
			return changed, nil
		}
		afterEco, afterID = page[len(page)-1].eco, page[len(page)-1].id
		var updates []rec
		for _, r := range page {
			if h, err := hash(r.raw); err == nil && h != r.hash {
				updates = append(updates, rec{eco: r.eco, id: r.id, hash: h})
			}
		}
		if len(updates) > 0 {
			err = s.inTx(ctx, func(tx *sql.Tx) error {
				for _, u := range updates {
					if _, err := tx.ExecContext(ctx, `UPDATE osv_records SET affected_hash = ? WHERE ecosystem = ? AND id = ?`,
						u.hash, u.eco, u.id); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return changed, err
			}
			changed += len(updates)
		}
		if len(page) < rehashPage {
			return changed, nil
		}
	}
}

// OSVListed returns the rows of bucket's modified_id.csv recorded by ReplaceOSVListed: record id to
// its listed modified time.
func (s *Store) OSVListed(ctx context.Context, bucket string) (map[string]time.Time, error) {
	type row struct {
		id string
		at int64
	}
	rows, err := queryAll(ctx, s.rdb, func(r scanner) (row, error) {
		var v row
		err := r.Scan(&v.id, &v.at)
		return v, err
	}, `SELECT id, modified FROM osv_listed WHERE bucket = ?`, bucket)
	if err != nil {
		return nil, err
	}
	out := make(map[string]time.Time, len(rows))
	for _, r := range rows {
		out[r.id] = time.Unix(0, r.at).UTC()
	}
	return out, nil
}

// ReplaceOSVListed replaces the rows recorded for bucket with listed (record id to listed modified
// time), in one transaction.
func (s *Store) ReplaceOSVListed(ctx context.Context, bucket string, listed map[string]time.Time) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM osv_listed WHERE bucket = ?`, bucket); err != nil {
			return err
		}
		if len(listed) == 0 {
			return nil
		}
		ins, err := tx.PrepareContext(ctx, `INSERT INTO osv_listed(bucket, id, modified) VALUES(?, ?, ?)`)
		if err != nil {
			return err
		}
		defer func() { _ = ins.Close() }()
		for id, at := range listed {
			if _, err := ins.ExecContext(ctx, bucket, id, at.UTC().UnixNano()); err != nil {
				return err
			}
		}
		return nil
	})
}

// OSVRecordsObserved returns, for each of ids cached in any bucket, the earliest time ffs observed
// its current affected content. Ids not cached, or cached before observation times were kept and
// never backfilled, are absent.
func (s *Store) OSVRecordsObserved(ctx context.Context, ids []string) (map[string]time.Time, error) {
	out := map[string]time.Time{}
	if len(ids) == 0 {
		return out, nil
	}
	type row struct {
		id  string
		obs sql.NullInt64
	}
	rows, err := queryAll(ctx, s.rdb, func(r scanner) (row, error) {
		var v row
		err := r.Scan(&v.id, &v.obs)
		return v, err
	}, `SELECT id, MIN(observed) FROM osv_records WHERE id IN (SELECT value FROM json_each(?)) AND observed IS NOT NULL
		GROUP BY id`, idList(ids))
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if r.obs.Valid {
			out[r.id] = fromNanos(r.obs)
		}
	}
	return out, nil
}

// OSVRecords returns the decompressed raw records of eco modified at or after since; a zero since
// returns them all.
func (s *Store) OSVRecords(ctx context.Context, eco string, since time.Time) ([][]byte, error) {
	var w where
	w.add(`ecosystem = ?`, eco)
	if !since.IsZero() {
		w.add(`modified >= ?`, nanos(since))
	}
	return queryAll(ctx, s.rdb, scanZstd, `SELECT raw_zst FROM osv_records`+w.String()+` ORDER BY id`, w.args...)
}

// DeleteOSVRecords removes the cached records of eco with the given ids, and their index names.
func (s *Store) DeleteOSVRecords(ctx context.Context, eco string, ids []string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error { return deleteOSVRecords(ctx, tx, eco, ids) })
}

// PutUpstreamRanges stores the affected ranges of an advisory for an upstream product.
func (s *Store) PutUpstreamRanges(ctx context.Context, advisoryID, productKey string, ranges []byte) error {
	if ranges == nil {
		ranges = []byte{}
	}
	_, err := s.wdb.ExecContext(ctx, `INSERT OR REPLACE INTO upstream_ranges(advisory_id, product_key, ranges) VALUES(?, ?, ?)`,
		advisoryID, productKey, ranges)
	return err
}

// ReplaceUpstreamRanges replaces every stored range of an advisory with byProduct (product key →
// ranges), in one transaction. An empty byProduct removes them all, as for a rejected CVE.
func (s *Store) ReplaceUpstreamRanges(ctx context.Context, advisoryID string, byProduct map[string][]byte) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM upstream_ranges WHERE advisory_id = ?`, advisoryID); err != nil {
			return err
		}
		for key, ranges := range byProduct {
			if ranges == nil {
				ranges = []byte{}
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO upstream_ranges(advisory_id, product_key, ranges) VALUES(?, ?, ?)`,
				advisoryID, key, ranges); err != nil {
				return err
			}
		}
		return nil
	})
}

// UpstreamRanges returns the stored ranges for productKey, keyed by advisory id.
func (s *Store) UpstreamRanges(ctx context.Context, productKey string) (map[string][]byte, error) {
	type row struct {
		id     string
		ranges []byte
	}
	rows, err := queryAll(ctx, s.rdb, func(r scanner) (row, error) {
		var v row
		err := r.Scan(&v.id, &v.ranges)
		return v, err
	}, `SELECT advisory_id, ranges FROM upstream_ranges WHERE product_key = ?`, productKey)
	if err != nil {
		return nil, err
	}
	m := make(map[string][]byte, len(rows))
	for _, v := range rows {
		m[v.id] = v.ranges
	}
	return m, nil
}
