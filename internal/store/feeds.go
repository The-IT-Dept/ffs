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
	err := s.inTx(ctx, func(tx *sql.Tx) error {
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
			return err
		default:
			changed = prev != affectedHash
		}
		obs := nanos(orNow(observed))
		if !changed && prevObs.Valid {
			obs = prevObs
		}
		_, err = tx.ExecContext(ctx, `INSERT OR REPLACE INTO osv_records(ecosystem, id, modified, affected_hash, raw_zst, observed)
			VALUES(?, ?, ?, ?, ?, ?)`, eco, id, nanos(modified), affectedHash, zstdEncode(raw), obs)
		return err
	})
	return changed, err
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
