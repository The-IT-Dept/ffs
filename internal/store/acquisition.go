package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
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

// OwnersOfAgentImages returns the sorted keys of the namespaced owners that run a catalogued image
// whose SBOM a node agent supplied, so the inventory can ask the registry to supersede it. The
// literal 'agent' is sbom.SourceAgent, which the store cannot import.
func (s *Store) OwnersOfAgentImages(ctx context.Context) ([]string, error) {
	return queryAll(ctx, s.rdb, scanString, `SELECT DISTINCT o.owner_key FROM owner_images o JOIN images i ON i.digest = o.digest
		JOIN owners w ON w.key = o.owner_key
		WHERE i.status = ? AND i.source = 'agent' AND w.namespace <> '' ORDER BY o.owner_key`,
		string(model.ImageCatalogued))
}

// metaControllerVersion is the meta key of the version of the controller that last started.
const metaControllerVersion = "controller_version"

// crashReasons match (SQL LIKE, case-insensitive) the failure reasons a crash or stall of ffs itself
// records, which a new controller version may well not repeat: the controller or the cataloguer
// stopping during the work (an out-of-memory kill), match runs that never completed, timeouts, and
// agent work that never came back. Deterministic failures (an SBOM that cannot be decoded, one too
// large, an image beyond the scratch limit, a recovered panic) match none of them.
var crashReasons = []string{
	"%stopped while processing%",                  // the controller (image or host inventory) or the cataloguer stopped mid-job
	"%did not complete%",                          // match runs that kept stopping the controller
	"%timed out%",                                 // the cataloguer's own timeout
	"%did not finish within%",                     // an acquisition past its deadline
	"%deadline exceeded%",                         // a context deadline
	"%out of memory%",                             // an out-of-memory kill, as reported
	"%oomkilled%",                                 // the same, as Kubernetes names it
	"%signal: killed%",                            // a cataloguer process killed by the kernel
	"%sent no result before the request expired%", // agent work whose collector stopped
}

// crashCond is the SQL condition that col holds a crash or stall reason, with its arguments.
func crashCond(col string) (string, []any) {
	parts := make([]string, len(crashReasons))
	args := make([]any, len(crashReasons))
	for i, r := range crashReasons {
		parts[i], args[i] = col+` LIKE ?`, r
	}
	return `(` + strings.Join(parts, ` OR `) + `)`, args
}

// CrashReset counts what ResetCrashQuarantines cleared.
type CrashReset struct {
	Previous string // the controller version stored before; "" when none was
	Images   int    // catalogue quarantines lifted (the images are pending again)
	Jobs     int    // agent job records deleted: node host inventories (nodehost:<node>) and agent image work
	Inflight int    // acquisitions a stopped controller left in flight
	Attempts int    // pending images, left in flight, whose counted attempts were reset
	Matches  int    // images whose interrupted first-match runs no longer count
	Errors   int    // node agent errors that named a lifted quarantine
}

// Cleared is how many records were cleared in all.
func (r CrashReset) Cleared() int {
	return r.Images + r.Jobs + r.Inflight + r.Attempts + r.Matches + r.Errors
}

// ResetCrashQuarantines runs once at controller start. When version differs from the stored
// controller version (or none is stored), it lifts what a crash or stall of the previous controller
// counted against images and nodes, since the new version may not repeat it, in one transaction:
//   - catalogFailed images whose reason is a crash or stall (crashReasons) become pending, with no
//     attempts and no quarantine, so they are acquired again;
//   - agent job records whose last error is one, for node host inventories and agent image work;
//   - every acquisition record left in flight, which would otherwise count as another crash, and the
//     counted attempts of the pending images those records were for, which earlier crashes may have
//     counted, so the new version has every try;
//   - the match runs counted against images whose first match has not completed;
//   - a node agent error that names a lifted host inventory quarantine.
//
// Deterministic failures stay quarantined. version is then stored. With an unchanged version it
// changes nothing, so a build that keeps crashing is still quarantined. changed reports whether the
// version changed.
func (s *Store) ResetCrashQuarantines(ctx context.Context, version string) (r CrashReset, changed bool, err error) {
	err = s.inTx(ctx, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, metaControllerVersion).Scan(&r.Previous)
		switch {
		case errors.Is(err, sql.ErrNoRows):
		case err != nil:
			return err
		case r.Previous == version:
			return nil
		}
		changed = true
		imageCrash, imageArgs := crashCond("status_reason")
		jobCrash, jobArgs := crashCond("last_error")
		for _, step := range []struct {
			n     *int
			query string
			args  []any
		}{
			{&r.Images, `UPDATE images SET status = ?, status_reason = '', attempts = 0, quarantined_until = NULL
				WHERE status = ? AND ` + imageCrash, append([]any{string(model.ImagePending), string(model.ImageCatalogFailed)}, imageArgs...)},
			{&r.Errors, `UPDATE nodes_agent SET last_error = '' WHERE last_error LIKE 'host inventory quarantined until %' AND ` + jobCrash,
				jobArgs},
			{&r.Jobs, `DELETE FROM agent_jobs WHERE ` + jobCrash, jobArgs},
			{&r.Attempts, `UPDATE images SET attempts = 0 WHERE status = ? AND attempts > 0
				AND digest IN (SELECT digest FROM acquisitions_inflight)`, []any{string(model.ImagePending)}},
			{&r.Inflight, `DELETE FROM acquisitions_inflight`, nil},
			{&r.Matches, `UPDATE images_unmatched SET attempts = 0 WHERE attempts > 0`, nil},
		} {
			res, err := tx.ExecContext(ctx, step.query, step.args...)
			if err != nil {
				return err
			}
			n, err := res.RowsAffected()
			if err != nil {
				return err
			}
			*step.n = int(n)
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
			metaControllerVersion, version)
		return err
	})
	if err != nil {
		return CrashReset{}, false, fmt.Errorf("store: reset crash quarantines: %w", err)
	}
	return r, changed, nil
}
