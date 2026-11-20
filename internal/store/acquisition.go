package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/the-it-dept/ffs/internal/model"
)

// UnmatchedImage is a catalogued image whose first full match has not completed.
type UnmatchedImage struct {
	Digest   string
	Attempts int // match runs started
}

// MarkUnmatched records that digest's SBOM is stored and its first full match is still to run.
// Marking an image again (it was catalogued again) resets its match attempts.
func (s *Store) MarkUnmatched(ctx context.Context, digest string, at time.Time) error {
	_, err := s.wdb.ExecContext(ctx, `INSERT OR REPLACE INTO images_unmatched(digest, since, attempts) VALUES(?, ?, 0)`,
		digest, nanos(orNow(at)))
	return err
}

// BeginMatch counts a match run of an unmatched image and returns the runs started so far, this one
// included. It returns 0 when digest is not marked unmatched.
func (s *Store) BeginMatch(ctx context.Context, digest string) (int, error) {
	var n int
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE images_unmatched SET attempts = attempts + 1 WHERE digest = ?`, digest); err != nil {
			return err
		}
		err := tx.QueryRowContext(ctx, `SELECT attempts FROM images_unmatched WHERE digest = ?`, digest).Scan(&n)
		if errors.Is(err, sql.ErrNoRows) {
			n = 0
			return nil
		}
		return err
	})
	return n, err
}

// MarkMatched records that digest's full match completed.
func (s *Store) MarkMatched(ctx context.Context, digest string) error {
	_, err := s.wdb.ExecContext(ctx, `DELETE FROM images_unmatched WHERE digest = ?`, digest)
	return err
}

// UnmatchedDigests returns, sorted, the digests among digests whose first full match has not
// completed. The engine treats such a digest's matches as unknown, like an uncatalogued digest's.
func (s *Store) UnmatchedDigests(ctx context.Context, digests []string) ([]string, error) {
	if len(digests) == 0 {
		return nil, nil
	}
	return queryAll(ctx, s.rdb, scanString, `SELECT digest FROM images_unmatched
		WHERE digest IN (SELECT value FROM json_each(?)) ORDER BY digest`, idList(digests))
}

// UnmatchedImages returns the catalogued images whose first full match has not completed, oldest
// first. Marks left for images that are gone or no longer catalogued are dropped.
func (s *Store) UnmatchedImages(ctx context.Context) ([]UnmatchedImage, error) {
	if _, err := s.wdb.ExecContext(ctx, `DELETE FROM images_unmatched WHERE digest NOT IN (SELECT digest FROM images)`); err != nil {
		return nil, err
	}
	return queryAll(ctx, s.rdb, func(r scanner) (UnmatchedImage, error) {
		var u UnmatchedImage
		err := r.Scan(&u.Digest, &u.Attempts)
		return u, err
	}, `SELECT u.digest, u.attempts FROM images_unmatched u JOIN images i ON i.digest = u.digest
		WHERE i.status = ? ORDER BY u.since, u.digest`, string(model.ImageCatalogued))
}

// BeginAcquire records that an SBOM acquisition of digest is starting. stale is true when a
// previous acquisition of digest was recorded and never ended: the process running it stopped.
func (s *Store) BeginAcquire(ctx context.Context, digest string, at time.Time) (stale bool, err error) {
	err = s.inTx(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM acquisitions_inflight WHERE digest = ?)`,
			digest).Scan(&stale); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO acquisitions_inflight(digest, started) VALUES(?, ?)`,
			digest, nanos(orNow(at)))
		return err
	})
	return stale, err
}

// EndAcquire records that the acquisition of digest ended, whatever its outcome.
func (s *Store) EndAcquire(ctx context.Context, digest string) error {
	_, err := s.wdb.ExecContext(ctx, `DELETE FROM acquisitions_inflight WHERE digest = ?`, digest)
	return err
}

// OwnersOfExpiredQuarantine returns the sorted keys of the owners that run an image whose
// catalogFailed or unresolvable quarantine has ended by now.
func (s *Store) OwnersOfExpiredQuarantine(ctx context.Context, now time.Time) ([]string, error) {
	return queryAll(ctx, s.rdb, scanString, `SELECT DISTINCT o.owner_key FROM owner_images o JOIN images i ON i.digest = o.digest
		WHERE i.status IN (?, ?) AND i.quarantined_until IS NOT NULL AND i.quarantined_until <= ? ORDER BY o.owner_key`,
		string(model.ImageCatalogFailed), string(model.ImageUnresolvable), now.UTC().UnixNano())
}
