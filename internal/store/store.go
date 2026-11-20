// Package store is the SQLite hub every subsystem reads and writes. It runs in WAL mode with one
// writer connection and a small read-only pool. Times are INTEGER UTC Unix nanoseconds (NULL when
// zero) and nested model values are JSON text columns.
package store

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	// glebarez/go-sqlite is the modernc driver fork Grype's gorm adapter links; it runs the same
	// modernc.org/sqlite/lib engine. modernc.org/sqlite itself must not be imported anywhere in the
	// binary: both register "sqlite" in init and sql.Register panics on the second.
	_ "github.com/glebarez/go-sqlite"
	"github.com/klauspost/compress/zstd"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Store is the persistent store. It is safe for concurrent use.
type Store struct {
	wdb *sql.DB // single writer connection
	rdb *sql.DB // read-only pool
}

// Open opens (creating if needed) the database at path and applies pending migrations.
func Open(ctx context.Context, path string) (*Store, error) { return openThrough(ctx, path, "") }

// openThrough is Open, applying the pending migrations up to and including the one named last
// ("" = every one). Tests use it to build a store on an older schema.
func openThrough(ctx context.Context, path, last string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("store: create directory: %w", err)
	}
	wdb, err := sql.Open("sqlite", "file:"+path+
		"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)"+
		// The read-model rollups are kept by triggers on findings; INSERT OR REPLACE fires the delete
		// trigger for the row it replaces only with recursive_triggers on.
		"&_pragma=recursive_triggers(1)&_txlock=immediate")
	if err != nil {
		return nil, fmt.Errorf("store: open writer: %w", err)
	}
	wdb.SetMaxOpenConns(1)
	s := &Store{wdb: wdb}
	if err := s.migrate(ctx, last); err != nil {
		return nil, errors.Join(err, wdb.Close())
	}
	rdb, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=query_only(1)")
	if err != nil {
		return nil, errors.Join(fmt.Errorf("store: open reader: %w", err), wdb.Close())
	}
	rdb.SetMaxOpenConns(4)
	s.rdb = rdb
	return s, nil
}

// Close closes both connection pools.
func (s *Store) Close() error {
	return errors.Join(s.rdb.Close(), s.wdb.Close())
}

// migrate applies every embedded migration not yet recorded in schema_migrations, in lexical
// order, each in its own transaction, stopping after the one named last when last is not "".
func (s *Store) migrate(ctx context.Context, last string) error {
	if _, err := s.wdb.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS schema_migrations(name TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		return fmt.Errorf("store: create schema_migrations: %w", err)
	}
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	slices.Sort(names)
	for _, p := range names {
		name := filepath.Base(p)
		body, err := migrations.ReadFile(p)
		if err != nil {
			return err
		}
		err = s.inTx(ctx, func(tx *sql.Tx) error {
			var applied bool
			if err := tx.QueryRowContext(ctx,
				`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE name = ?)`, name).Scan(&applied); err != nil {
				return err
			}
			if applied {
				return nil
			}
			if _, err := tx.ExecContext(ctx, string(body)); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(name, applied_at) VALUES(?, ?)`, name, nanos(time.Now()))
			return err
		})
		if err != nil {
			return fmt.Errorf("store: migration %s: %w", name, err)
		}
		if name == last {
			break
		}
	}
	return nil
}

// inTx runs fn in a transaction on the writer, committing when fn returns nil.
func (s *Store) inTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.wdb.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return errors.Join(err, tx.Rollback())
	}
	return tx.Commit()
}

// querier is satisfied by *sql.DB and *sql.Tx, so read helpers run on the reader or inside a write.
type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type scanner interface{ Scan(dest ...any) error }

// queryAll runs query and scans every row with scan.
func queryAll[T any](ctx context.Context, q querier, scan func(scanner) (T, error), query string, args ...any) ([]T, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []T
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func scanString(r scanner) (string, error) {
	var v string
	err := r.Scan(&v)
	return v, err
}

// where accumulates AND-ed conditions and their bound arguments.
type where struct {
	conds []string
	args  []any
}

func (w *where) add(cond string, args ...any) {
	w.conds = append(w.conds, cond)
	w.args = append(w.args, args...)
}

func (w *where) String() string {
	if len(w.conds) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(w.conds, " AND ")
}

// limitOffset renders LIMIT/OFFSET; limit <= 0 means no limit.
func limitOffset(limit, offset int) string {
	if limit <= 0 && offset <= 0 {
		return ""
	}
	if limit <= 0 {
		limit = -1
	}
	return fmt.Sprintf(" LIMIT %d OFFSET %d", limit, max(offset, 0))
}

// nanos returns nil for the zero time, else UTC Unix nanoseconds.
func nanos(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().UnixNano()
}

// fromNanos reverses nanos.
func fromNanos(v sql.NullInt64) time.Time {
	if !v.Valid {
		return time.Time{}
	}
	return time.Unix(0, v.Int64).UTC()
}

// orNow returns t, or the current UTC time when t is zero.
func orNow(t time.Time) time.Time {
	if t.IsZero() {
		return time.Now().UTC()
	}
	return t
}

// idList returns ids as a JSON array for `IN (SELECT value FROM json_each(?))`.
func idList(ids []string) string { return stringsText(ids) }

// jsonText marshals v for a JSON text column.
func jsonText(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}

// stringsText renders a string list as a JSON array, "[]" when empty.
func stringsText(v []string) string {
	if len(v) == 0 {
		return "[]"
	}
	b, _ := json.Marshal(v) // a []string always marshals
	return string(b)
}

// textStrings reverses stringsText; an empty array reads back as nil.
func textStrings(s string) ([]string, error) {
	var v []string
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return nil, err
	}
	if len(v) == 0 {
		return nil, nil
	}
	return v, nil
}

var (
	zenc = mustZstdEncoder()
	zdec = mustZstdDecoder()
)

// mustZstdEncoder returns the encoder of SBOMs and OSV records. By default an encoder keeps one
// window-sized history per GOMAXPROCS, 16 MiB each at the default 8 MiB window, for good: 192 MiB
// on a 12-core node once a burst of OSV records had cycled through them. Two encoders cover the
// writers that run at once (the store has one writer connection), and a 1 MiB window compresses
// syft JSON within 0.3% of the default.
func mustZstdEncoder() *zstd.Encoder {
	e, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(2), zstd.WithWindowSize(1<<20), zstd.WithLowerEncoderMem(true))
	if err != nil {
		panic(err)
	}
	return e
}

func mustZstdDecoder() *zstd.Decoder {
	d, err := zstd.NewReader(nil, zstd.WithDecoderMaxMemory(1<<30))
	if err != nil {
		panic(err)
	}
	return d
}

func zstdEncode(b []byte) []byte { return zenc.EncodeAll(b, nil) }

func zstdDecode(b []byte) ([]byte, error) { return zdec.DecodeAll(b, nil) }
