package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

const eolDateLayout = "2006-01-02"

// EOLCycle is one release cycle of a product from endoflife.date.
type EOLCycle struct {
	Product, Cycle, Codename string
	ReleaseDate              time.Time
	EOLDate                  *time.Time // nil when endoflife.date has no date
	IsEOL                    bool       // the feed's isEol at generation time
	Latest                   string     // latest.name; "" when null
	LatestDate               time.Time
}

func eolDate(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(eolDateLayout)
}

func parseEOLDate(v sql.NullString) (time.Time, error) {
	if !v.Valid || v.String == "" {
		return time.Time{}, nil
	}
	return time.ParseInLocation(eolDateLayout, v.String, time.UTC)
}

// ReplaceEOL replaces every stored cycle with cycles, in one transaction.
func (s *Store) ReplaceEOL(ctx context.Context, cycles []EOLCycle) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM eol`); err != nil {
			return err
		}
		stmt, err := tx.PrepareContext(ctx, `INSERT OR REPLACE INTO eol(product, cycle, codename, release_date, eol_date, is_eol, latest, latest_date)
			VALUES(?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer func() { _ = stmt.Close() }()
		for _, c := range cycles {
			var eolD any
			if c.EOLDate != nil {
				eolD = eolDate(*c.EOLDate)
			}
			if _, err := stmt.ExecContext(ctx, c.Product, c.Cycle, c.Codename, eolDate(c.ReleaseDate), eolD, c.IsEOL, c.Latest, eolDate(c.LatestDate)); err != nil {
				return err
			}
		}
		return nil
	})
}

// ListEOL returns every stored cycle, ordered by product then cycle.
func (s *Store) ListEOL(ctx context.Context) ([]EOLCycle, error) {
	return queryAll(ctx, s.rdb, func(r scanner) (EOLCycle, error) {
		var (
			c                    EOLCycle
			release, eolD, latst sql.NullString
		)
		if err := r.Scan(&c.Product, &c.Cycle, &c.Codename, &release, &eolD, &c.IsEOL, &c.Latest, &latst); err != nil {
			return c, err
		}
		var err error
		if c.ReleaseDate, err = parseEOLDate(release); err != nil {
			return c, fmt.Errorf("store: eol %s %s: %w", c.Product, c.Cycle, err)
		}
		if c.LatestDate, err = parseEOLDate(latst); err != nil {
			return c, fmt.Errorf("store: eol %s %s: %w", c.Product, c.Cycle, err)
		}
		if eolD.Valid && eolD.String != "" {
			d, err := parseEOLDate(eolD)
			if err != nil {
				return c, fmt.Errorf("store: eol %s %s: %w", c.Product, c.Cycle, err)
			}
			c.EOLDate = &d
		}
		return c, nil
	}, `SELECT product, cycle, codename, release_date, eol_date, is_eol, latest, latest_date FROM eol ORDER BY product, cycle`)
}
