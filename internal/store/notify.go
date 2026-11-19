package store

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/the-it-dept/ffs/internal/model"
)

// LedgerEntry records what a target was last told about a finding: the highest priority sent and
// the state it was sent in (spec §6.10, never twice).
type LedgerEntry struct {
	Target, Fingerprint string
	MaxPriority         model.Priority
	LastState           model.FindingState
	UpdatedAt           time.Time
}

// DeliveryState is the outbox state of a delivery.
type DeliveryState string

const (
	DeliveryPending DeliveryState = "pending"
	DeliverySent    DeliveryState = "sent"
	DeliveryFailed  DeliveryState = "failed"
	DeliveryDropped DeliveryState = "dropped"
)

// Delivery is one message for one target. ID is the message ID, stable across retries and restarts.
type Delivery struct {
	ID, Target, Kind                          string
	Payload                                   []byte
	State                                     DeliveryState
	NotBefore, NextAttempt, CreatedAt, SentAt time.Time
	Attempts, HTTPStatus                      int
	LastError                                 string
}

// NotifyTargetState is the stored notification state of one AlertTarget, keyed by its UID.
type NotifyTargetState struct {
	Target, Name, ConfigHash                 string
	BaselineAt, LastDigestAt, LastDeliveryAt time.Time
	LastError                                string
	ConsecutiveFailures                      int
	Disabled                                 bool
	DisabledReason                           string
}

// NotifyCommit is everything one notification pass writes for a target, applied in one transaction.
type NotifyCommit struct {
	Target                   string
	Cursors                  map[string]int64
	Ledger                   []LedgerEntry
	Deliveries               []Delivery
	BaselineAt, LastDigestAt time.Time // written when non-zero
}

// DeliveryAttempt is the outcome of sending one delivery.
type DeliveryAttempt struct {
	ID, Target    string
	At            time.Time
	State         DeliveryState
	NextAttempt   time.Time // kept unchanged when zero
	Error         string
	HTTPStatus    int
	Disable       bool
	DisableReason string
}

// MaxTransitionID returns the highest transition ID, 0 when there are none.
func (s *Store) MaxTransitionID(ctx context.Context) (int64, error) {
	var id int64
	err := s.rdb.QueryRowContext(ctx, `SELECT COALESCE(MAX(id), 0) FROM transitions`).Scan(&id)
	return id, err
}

// FindingsByFingerprint returns the stored findings among fps, in any state, keyed by fingerprint.
func (s *Store) FindingsByFingerprint(ctx context.Context, fps []string) (map[string]model.Finding, error) {
	list, err := queryAll(ctx, s.rdb, scanFinding,
		`SELECT fingerprint, data FROM findings WHERE fingerprint IN (SELECT value FROM json_each(?))`, idList(fps))
	if err != nil {
		return nil, err
	}
	m := make(map[string]model.Finding, len(list))
	for _, f := range list {
		m[f.Fingerprint] = f
	}
	return m, nil
}

const notifyTargetColumns = `target, name, config_hash, baseline_at, last_digest_at, last_delivery_at, last_error,
	consecutive_failures, disabled, disabled_reason`

// NotifyTarget returns the stored state of the target with UID uid.
func (s *Store) NotifyTarget(ctx context.Context, uid string) (NotifyTargetState, bool, error) {
	st, err := scanNotifyTarget(s.rdb.QueryRowContext(ctx, `SELECT `+notifyTargetColumns+` FROM notify_targets WHERE target = ?`, uid))
	if errors.Is(err, sql.ErrNoRows) {
		return NotifyTargetState{}, false, nil
	}
	return st, err == nil, err
}

// NotifyTargets returns every stored target state, ordered by name then UID.
func (s *Store) NotifyTargets(ctx context.Context) ([]NotifyTargetState, error) {
	return queryAll(ctx, s.rdb, scanNotifyTarget, `SELECT `+notifyTargetColumns+` FROM notify_targets ORDER BY name, target`)
}

func scanNotifyTarget(r scanner) (NotifyTargetState, error) {
	var (
		st                         NotifyTargetState
		baseline, digest, delivery sql.NullInt64
	)
	if err := r.Scan(&st.Target, &st.Name, &st.ConfigHash, &baseline, &digest, &delivery, &st.LastError,
		&st.ConsecutiveFailures, &st.Disabled, &st.DisabledReason); err != nil {
		return NotifyTargetState{}, err
	}
	st.BaselineAt, st.LastDigestAt, st.LastDeliveryAt = fromNanos(baseline), fromNanos(digest), fromNanos(delivery)
	return st, nil
}

// PutNotifyTarget creates or renames the target uid. A changed config hash re-enables it: Disabled,
// DisabledReason and ConsecutiveFailures are cleared, since the endpoint or settings were edited.
func (s *Store) PutNotifyTarget(ctx context.Context, uid, name, configHash string) error {
	_, err := s.wdb.ExecContext(ctx, `INSERT INTO notify_targets(target, name, config_hash) VALUES(?, ?, ?)
		ON CONFLICT(target) DO UPDATE SET name = excluded.name,
			disabled = CASE WHEN config_hash <> excluded.config_hash THEN 0 ELSE disabled END,
			disabled_reason = CASE WHEN config_hash <> excluded.config_hash THEN '' ELSE disabled_reason END,
			consecutive_failures = CASE WHEN config_hash <> excluded.config_hash THEN 0 ELSE consecutive_failures END,
			config_hash = excluded.config_hash`, uid, name, configHash)
	return err
}

// DeleteNotifyTarget removes everything stored for the target uid: its state, ledger, deliveries and
// both of its transition cursors.
func (s *Store) DeleteNotifyTarget(ctx context.Context, uid string) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		for _, q := range []string{
			`DELETE FROM notify_targets WHERE target = ?`,
			`DELETE FROM notified WHERE target = ?`,
			`DELETE FROM deliveries WHERE target = ?`,
		} {
			if _, err := tx.ExecContext(ctx, q, uid); err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM cursors WHERE consumer IN (?, ?)`, "notify:"+uid, "notify-digest:"+uid)
		return err
	})
}

// Ledger returns the target's ledger entries for fps, keyed by fingerprint. Unknown fingerprints are
// absent.
func (s *Store) Ledger(ctx context.Context, target string, fps []string) (map[string]LedgerEntry, error) {
	list, err := queryAll(ctx, s.rdb, func(r scanner) (LedgerEntry, error) {
		var (
			e       LedgerEntry
			state   string
			updated sql.NullInt64
		)
		if err := r.Scan(&e.Target, &e.Fingerprint, &e.MaxPriority, &state, &updated); err != nil {
			return LedgerEntry{}, err
		}
		e.LastState, e.UpdatedAt = model.FindingState(state), fromNanos(updated)
		return e, nil
	}, `SELECT target, fingerprint, max_priority, last_state, updated_at FROM notified
		WHERE target = ? AND fingerprint IN (SELECT value FROM json_each(?))`, target, idList(fps))
	if err != nil {
		return nil, err
	}
	m := make(map[string]LedgerEntry, len(list))
	for _, e := range list {
		m[e.Fingerprint] = e
	}
	return m, nil
}

// CommitNotify applies one notification pass in a single transaction: the cursors, the ledger
// upserts, the new deliveries and the non-zero BaselineAt and LastDigestAt. A delivery whose ID
// exists is left alone, so a re-run pass enqueues nothing twice; unlike INSERT OR IGNORE, a NOT
// NULL violation still fails the commit. Ledger entries and deliveries without a Target take
// c.Target; zero CreatedAt, NotBefore and NextAttempt default to now, CreatedAt and NotBefore.
func (s *Store) CommitNotify(ctx context.Context, c NotifyCommit) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		for consumer, id := range c.Cursors {
			if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO cursors(consumer, id) VALUES(?, ?)`, consumer, id); err != nil {
				return fmt.Errorf("store: cursor %q: %w", consumer, err)
			}
		}
		for _, e := range c.Ledger {
			if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO notified(target, fingerprint, max_priority, last_state, updated_at)
				VALUES(?, ?, ?, ?, ?)`, cmp.Or(e.Target, c.Target), e.Fingerprint, int(e.MaxPriority), string(e.LastState),
				nanos(orNow(e.UpdatedAt))); err != nil {
				return fmt.Errorf("store: ledger %q: %w", e.Fingerprint, err)
			}
		}
		for _, d := range c.Deliveries {
			created := orNow(d.CreatedAt)
			notBefore := d.NotBefore
			if notBefore.IsZero() {
				notBefore = created
			}
			next := d.NextAttempt
			if next.IsZero() {
				next = notBefore
			}
			state := d.State
			if state == "" {
				state = DeliveryPending
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO deliveries(id, target, kind, payload, state, not_before,
				next_attempt, attempts, last_error, http_status, created_at, sent_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				ON CONFLICT(id) DO NOTHING`,
				d.ID, cmp.Or(d.Target, c.Target), d.Kind, d.Payload, string(state), nanos(notBefore), nanos(next),
				d.Attempts, d.LastError, d.HTTPStatus, nanos(created), nanos(d.SentAt)); err != nil {
				return fmt.Errorf("store: delivery %q: %w", d.ID, err)
			}
		}
		if !c.BaselineAt.IsZero() {
			if _, err := tx.ExecContext(ctx, `UPDATE notify_targets SET baseline_at = ? WHERE target = ?`,
				nanos(c.BaselineAt), c.Target); err != nil {
				return err
			}
		}
		if !c.LastDigestAt.IsZero() {
			if _, err := tx.ExecContext(ctx, `UPDATE notify_targets SET last_digest_at = ? WHERE target = ?`,
				nanos(c.LastDigestAt), c.Target); err != nil {
				return err
			}
		}
		return nil
	})
}

const deliveryColumns = `id, target, kind, payload, state, not_before, next_attempt, attempts, last_error, http_status,
	created_at, sent_at`

func scanDelivery(r scanner) (Delivery, error) {
	var (
		d                                Delivery
		state                            string
		notBefore, next, created, sentAt sql.NullInt64
	)
	if err := r.Scan(&d.ID, &d.Target, &d.Kind, &d.Payload, &state, &notBefore, &next, &d.Attempts, &d.LastError,
		&d.HTTPStatus, &created, &sentAt); err != nil {
		return Delivery{}, err
	}
	d.State = DeliveryState(state)
	d.NotBefore, d.NextAttempt, d.CreatedAt, d.SentAt = fromNanos(notBefore), fromNanos(next), fromNanos(created), fromNanos(sentAt)
	return d, nil
}

// PendingDeliveries returns up to limit pending deliveries that are due at now (both not_before and
// next_attempt at or before it), oldest first. limit <= 0 means no limit.
func (s *Store) PendingDeliveries(ctx context.Context, now time.Time, limit int) ([]Delivery, error) {
	return s.pendingDeliveries(ctx, now, limit, "")
}

// PendingDeliveriesFor is PendingDeliveries for the given targets only, so the deliveries of other
// targets (unregistered, disabled or backing off) never take a place in the batch. No targets
// means no deliveries.
func (s *Store) PendingDeliveriesFor(ctx context.Context, now time.Time, targets []string, limit int) ([]Delivery, error) {
	if len(targets) == 0 {
		return nil, nil
	}
	return s.pendingDeliveries(ctx, now, limit, ` AND target IN (SELECT value FROM json_each(?))`, idList(targets))
}

func (s *Store) pendingDeliveries(ctx context.Context, now time.Time, limit int, cond string, args ...any) ([]Delivery, error) {
	at := now.UTC().UnixNano()
	return queryAll(ctx, s.rdb, scanDelivery, `SELECT `+deliveryColumns+` FROM deliveries
		WHERE state = ? AND not_before <= ? AND next_attempt <= ?`+cond+` ORDER BY created_at, id`+limitOffset(limit, 0),
		append([]any{string(DeliveryPending), at, at}, args...)...)
}

// RecordAttempt records one send attempt in a single transaction. The delivery's attempt count goes
// up by one and it takes a.State; a sent delivery also gets SentAt. The target's status follows:
// a success clears its error and failure count, anything else records the error and counts a
// failure. Disable also disables the target and drops its other pending deliveries.
func (s *Store) RecordAttempt(ctx context.Context, a DeliveryAttempt) error {
	at := orNow(a.At)
	sent := a.State == DeliverySent
	var sentAt any
	if sent {
		sentAt = nanos(at)
	}
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE deliveries SET attempts = attempts + 1, state = ?,
			next_attempt = COALESCE(?, next_attempt), last_error = ?, http_status = ?, sent_at = COALESCE(?, sent_at)
			WHERE id = ?`, string(a.State), nanos(a.NextAttempt), a.Error, a.HTTPStatus, sentAt, a.ID); err != nil {
			return fmt.Errorf("store: delivery %q: %w", a.ID, err)
		}
		var err error
		if sent {
			_, err = tx.ExecContext(ctx, `UPDATE notify_targets SET last_delivery_at = ?, last_error = '', consecutive_failures = 0
				WHERE target = ?`, nanos(at), a.Target)
		} else {
			_, err = tx.ExecContext(ctx, `UPDATE notify_targets SET last_error = ?, consecutive_failures = consecutive_failures + 1
				WHERE target = ?`, a.Error, a.Target)
		}
		if err != nil {
			return fmt.Errorf("store: target %q: %w", a.Target, err)
		}
		if !a.Disable {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE notify_targets SET disabled = 1, disabled_reason = ? WHERE target = ?`,
			a.DisableReason, a.Target); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE deliveries SET state = ? WHERE target = ? AND state = ? AND id <> ?`,
			string(DeliveryDropped), a.Target, string(DeliveryPending), a.ID)
		return err
	})
}

// ListDeliveries returns up to limit of the target's deliveries, newest first (the delivery log).
// limit <= 0 means no limit.
func (s *Store) ListDeliveries(ctx context.Context, target string, limit int) ([]Delivery, error) {
	return queryAll(ctx, s.rdb, scanDelivery, `SELECT `+deliveryColumns+` FROM deliveries WHERE target = ?
		ORDER BY created_at DESC, id DESC`+limitOffset(limit, 0), target)
}

// PruneNotify deletes deliveries that are no longer pending and ledger entries last notified as
// resolved, when created or updated before olderThan. It returns the rows deleted.
func (s *Store) PruneNotify(ctx context.Context, olderThan time.Time) (int, error) {
	if olderThan.IsZero() {
		return 0, nil // nothing is older than the zero time
	}
	cutoff := olderThan.UTC().UnixNano()
	var n int64
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM deliveries WHERE state <> ? AND created_at < ?`, string(DeliveryPending), cutoff)
		if err != nil {
			return err
		}
		d, err := res.RowsAffected()
		if err != nil {
			return err
		}
		res, err = tx.ExecContext(ctx, `DELETE FROM notified WHERE last_state = ? AND updated_at < ?`, string(model.StateResolved), cutoff)
		if err != nil {
			return err
		}
		l, err := res.RowsAffected()
		n = d + l
		return err
	})
	return int(n), err
}
