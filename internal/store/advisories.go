package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/the-it-dept/ffs/internal/model"
)

// Canonical resolves an advisory id or alias to its canonical id; an unknown id resolves to itself.
func (s *Store) Canonical(ctx context.Context, id string) (string, error) {
	m, err := canonicals(ctx, s.rdb, []string{id})
	return m[id], err
}

// canonicals maps each of ids to its canonical id (itself when unknown).
func canonicals(ctx context.Context, q querier, ids []string) (map[string]string, error) {
	m := make(map[string]string, len(ids))
	for _, id := range ids {
		m[id] = id
	}
	rows, err := q.QueryContext(ctx,
		`SELECT alias, canonical FROM advisory_aliases WHERE alias IN (SELECT value FROM json_each(?))`, idList(ids))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var alias, canon string
		if err := rows.Scan(&alias, &canon); err != nil {
			return nil, err
		}
		m[alias] = canon
	}
	return m, rows.Err()
}

// sameAdvisory is a predicate matching an advisory id column against every alias of the canonicals
// of a JSON id list. It takes two bound arguments, both idList(ids).
func sameAdvisory(col string) string {
	return col + ` IN (
		SELECT COALESCE(c.canonical, j.value) FROM json_each(?) j LEFT JOIN advisory_aliases c ON c.alias = j.value
		UNION
		SELECT a.alias FROM json_each(?) j JOIN advisory_aliases c ON c.alias = j.value JOIN advisory_aliases a ON a.canonical = c.canonical)`
}

// UpsertAdvisory merges a into the stored advisory it aliases, field by field: non-zero fields of a
// overwrite, zero fields keep the stored value, and Aliases and Links are unioned. Observed is set
// on first insert only (a.Observed, or now). When the canonical id changes (a GHSA gains a CVE, or
// two stored advisories turn out to be aliases), the advisory and its matches are re-keyed to the
// new canonical in the same transaction.
func (s *Store) UpsertAdvisory(ctx context.Context, a model.Advisory) error {
	if a.ID == "" {
		return errors.New("store: advisory without an id")
	}
	ids := []string{a.ID}
	for _, al := range a.Aliases {
		if al != "" {
			ids = append(ids, al)
		}
	}
	return s.inTx(ctx, func(tx *sql.Tx) error {
		existing, err := queryAll(ctx, tx, scanString,
			`SELECT DISTINCT canonical FROM advisory_aliases WHERE alias IN (SELECT value FROM json_each(?)) ORDER BY canonical`, idList(ids))
		if err != nil {
			return err
		}
		stored, err := queryAll(ctx, tx, scanAdvisory,
			`SELECT data FROM advisories WHERE id IN (SELECT value FROM json_each(?)) ORDER BY id`, idList(existing))
		if err != nil {
			return err
		}

		var merged model.Advisory
		var observed time.Time
		known := slices.Concat(existing, ids)
		for _, r := range stored {
			merged = mergeAdvisory(merged, r)
			if observed.IsZero() || r.Observed.Before(observed) {
				observed = r.Observed
			}
			known = append(known, r.ID)
			known = append(known, r.Aliases...)
		}
		merged = mergeAdvisory(merged, a)
		if observed.IsZero() {
			observed = orNow(a.Observed)
		}
		merged.Observed = observed

		slices.Sort(known)
		known = slices.Compact(known)
		canon := model.CanonicalID(slices.Concat(existing, []string{a.ID}, known)...)
		merged.ID = canon
		merged.Aliases = slices.DeleteFunc(slices.Clone(known), func(id string) bool { return id == canon })
		if len(merged.Aliases) == 0 {
			merged.Aliases = nil
		}

		data, err := jsonText(merged)
		if err != nil {
			return err
		}
		// Former canonicals are now aliases: drop their rows, and move every match keyed by any
		// alias to canon. That covers the former canonicals and ids matched before they were known.
		aliases := idList(merged.Aliases)
		if _, err := tx.ExecContext(ctx, `DELETE FROM advisories WHERE id IN (SELECT value FROM json_each(?))`, aliases); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE OR REPLACE matches SET advisory_id = ? WHERE advisory_id IN (SELECT value FROM json_each(?))`, canon, aliases); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO advisories(id, data, observed) VALUES(?, ?, ?)`,
			canon, data, nanos(observed)); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT OR REPLACE INTO advisory_aliases(alias, canonical) SELECT value, ? FROM json_each(?)`,
			canon, idList(known))
		return err
	})
}

// mergeAdvisory overlays the non-zero fields of src onto dst, unioning Links. ID, Aliases and
// Observed are the caller's concern.
func mergeAdvisory(dst, src model.Advisory) model.Advisory {
	if src.Title != "" {
		dst.Title = src.Title
	}
	if !src.Published.IsZero() {
		dst.Published = src.Published
	}
	if !src.Modified.IsZero() {
		dst.Modified = src.Modified
	}
	for _, l := range src.Links {
		if !slices.Contains(dst.Links, l) {
			dst.Links = append(dst.Links, l)
		}
	}
	if src.CNASeverity != model.SeverityUnknown {
		dst.CNASeverity = src.CNASeverity
	}
	if src.CNACVSS != 0 {
		dst.CNACVSS = src.CNACVSS
	}
	if src.CNASource != "" {
		dst.CNASource = src.CNASource
	}
	if src.KEVAdded != nil {
		dst.KEVAdded = src.KEVAdded
	}
	if src.EPSS != 0 {
		dst.EPSS = src.EPSS
	}
	if src.EPSSPercentile != 0 {
		dst.EPSSPercentile = src.EPSSPercentile
	}
	dst.Malicious = dst.Malicious || src.Malicious
	// Only a REJECTED cvelistV5 record sets Withdrawn (see model.Advisory); OSV records never do.
	dst.Withdrawn = dst.Withdrawn || src.Withdrawn
	return dst
}

// GetAdvisory returns the advisory id or any of its aliases resolves to.
func (s *Store) GetAdvisory(ctx context.Context, id string) (model.Advisory, bool, error) {
	a, err := scanAdvisory(s.rdb.QueryRowContext(ctx,
		`SELECT data FROM advisories WHERE id = COALESCE((SELECT canonical FROM advisory_aliases WHERE alias = ?), ?)`, id, id))
	if errors.Is(err, sql.ErrNoRows) {
		return model.Advisory{}, false, nil
	}
	return a, err == nil, err
}

// Advisories returns the stored advisories that ids (or their aliases) resolve to, keyed by
// canonical id. Unknown ids are absent.
func (s *Store) Advisories(ctx context.Context, ids []string) (map[string]model.Advisory, error) {
	list, err := queryAll(ctx, s.rdb, scanAdvisory, `SELECT data FROM advisories WHERE id IN (
		SELECT COALESCE(c.canonical, j.value) FROM json_each(?) j LEFT JOIN advisory_aliases c ON c.alias = j.value)`, idList(ids))
	if err != nil {
		return nil, err
	}
	m := make(map[string]model.Advisory, len(list))
	for _, a := range list {
		m[a.ID] = a
	}
	return m, nil
}

// AdvisoryIDsInUse returns the sorted distinct advisory ids present in matches.
func (s *Store) AdvisoryIDsInUse(ctx context.Context) ([]string, error) {
	return queryAll(ctx, s.rdb, scanString, `SELECT DISTINCT advisory_id FROM matches ORDER BY advisory_id`)
}

func scanAdvisory(r scanner) (model.Advisory, error) {
	var (
		a    model.Advisory
		data string
	)
	if err := r.Scan(&data); err != nil {
		return model.Advisory{}, err
	}
	if err := json.Unmarshal([]byte(data), &a); err != nil {
		return model.Advisory{}, fmt.Errorf("advisory: %w", err)
	}
	return a, nil
}
