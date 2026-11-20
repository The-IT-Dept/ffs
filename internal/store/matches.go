package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"

	"github.com/the-it-dept/ffs/internal/model"
)

// ErrEmptyScope is returned by ReplaceMatches when the scope names no digests, packages or advisories.
var ErrEmptyScope = errors.New("store: empty match scope")

// MatchScope selects the matches a ReplaceMatches call owns: the AND of its non-empty fields.
type MatchScope struct {
	Source                           model.MatchSource
	Digests, PackageIDs, AdvisoryIDs []string
}

type matchKey struct{ digest, packageID, advisoryID, source string }

// matchCols holds a match's non-key columns as stored, so stored and incoming rows compare exactly.
type matchCols struct {
	fixState, fixedVersions string
	vendorSeverity          int
	vendorSeveritySource    string
	namespace               string
	dbBuilt                 sql.NullInt64
}

const matchColumns = `digest, package_id, advisory_id, source, fix_state, fixed_versions, vendor_severity,
	vendor_severity_source, namespace, db_built, observed_at`

// ReplaceMatches replaces every match in scope with ms in one transaction. Advisory ids in the
// scope and in ms are canonicalised first, and a match outside the scope is an error. A new row is
// observed at its ObservedAt, or now when it has none; a row whose key survives keeps the earlier of
// its stored and incoming ObservedAt, so a re-match never moves the time ffs first saw a match. It
// returns the sorted digests whose rows were added, removed or changed in any column other than
// observed_at. Later entries of ms win over earlier ones with the same key.
func (s *Store) ReplaceMatches(ctx context.Context, scope MatchScope, ms []model.Match) ([]string, error) {
	if len(scope.Digests) == 0 && len(scope.PackageIDs) == 0 && len(scope.AdvisoryIDs) == 0 {
		return nil, ErrEmptyScope
	}
	var affected []string
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		ids := slices.Clone(scope.AdvisoryIDs)
		for _, m := range ms {
			ids = append(ids, m.AdvisoryID)
		}
		canon, err := canonicals(ctx, tx, ids)
		if err != nil {
			return err
		}
		scopeAdvisories := make([]string, len(scope.AdvisoryIDs))
		for i, id := range scope.AdvisoryIDs {
			scopeAdvisories[i] = canon[id]
		}

		inScope := newScopeSet(scope, scopeAdvisories)
		incoming := make(map[matchKey]model.Match, len(ms))
		var order []matchKey
		for _, m := range ms {
			m.AdvisoryID = canon[m.AdvisoryID]
			if !inScope.contains(m) {
				return fmt.Errorf("store: match %s/%s/%s/%s is outside its replace scope", m.Source, m.ImageDigest, m.PackageID, m.AdvisoryID)
			}
			k := matchKey{m.ImageDigest, m.PackageID, m.AdvisoryID, string(m.Source)}
			if _, dup := incoming[k]; !dup {
				order = append(order, k)
			}
			incoming[k] = m
		}

		w := scopeWhere(scope, scopeAdvisories)
		stored, err := queryAll(ctx, tx, scanStoredMatch, `SELECT `+matchColumns+` FROM matches`+w.String(), w.args...)
		if err != nil {
			return err
		}
		// w holds fixed predicates only; every value is a bound parameter.
		if _, err := tx.ExecContext(ctx, `DELETE FROM matches`+w.String(), w.args...); err != nil { //nolint:gosec // G202: see above
			return err
		}

		changed := map[string]bool{}
		old := make(map[matchKey]storedMatch, len(stored))
		for _, row := range stored {
			old[row.key] = row
			if _, kept := incoming[row.key]; !kept {
				changed[row.key.digest] = true
			}
		}
		ins, err := tx.PrepareContext(ctx, `INSERT INTO matches(`+matchColumns+`) VALUES(?,?,?,?,?,?,?,?,?,?,?)`)
		if err != nil {
			return err
		}
		defer func() { _ = ins.Close() }()
		for _, k := range order {
			m := incoming[k]
			cols := colsOf(m)
			observedAt := orNow(m.ObservedAt).UTC().UnixNano()
			if prev, ok := old[k]; ok {
				observedAt = min(observedAt, prev.observedAt)
				if prev.cols != cols {
					changed[k.digest] = true
				}
			} else {
				changed[k.digest] = true
			}
			if _, err := ins.ExecContext(ctx, k.digest, k.packageID, k.advisoryID, k.source, cols.fixState, cols.fixedVersions,
				cols.vendorSeverity, cols.vendorSeveritySource, cols.namespace, cols.dbBuilt, observedAt); err != nil {
				return err
			}
		}
		for d := range changed {
			affected = append(affected, d)
		}
		slices.Sort(affected)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return affected, nil
}

// scopeWhere selects the rows of scope; advisories is the canonicalised scope list.
func scopeWhere(scope MatchScope, advisories []string) where {
	var w where
	if scope.Source != "" {
		w.add(`source = ?`, string(scope.Source))
	}
	if len(scope.Digests) > 0 {
		w.add(`digest IN (SELECT value FROM json_each(?))`, idList(scope.Digests))
	}
	if len(scope.PackageIDs) > 0 {
		w.add(`package_id IN (SELECT value FROM json_each(?))`, idList(scope.PackageIDs))
	}
	if len(advisories) > 0 {
		w.add(`advisory_id IN (SELECT value FROM json_each(?))`, idList(advisories))
	}
	return w
}

type storedMatch struct {
	key        matchKey
	cols       matchCols
	observedAt int64
}

func scanStoredMatch(r scanner) (storedMatch, error) {
	var row storedMatch
	err := r.Scan(&row.key.digest, &row.key.packageID, &row.key.advisoryID, &row.key.source, &row.cols.fixState,
		&row.cols.fixedVersions, &row.cols.vendorSeverity, &row.cols.vendorSeveritySource, &row.cols.namespace,
		&row.cols.dbBuilt, &row.observedAt)
	return row, err
}

// scopeSet tests membership in a scope; a nil set matches anything.
type scopeSet struct {
	source                          model.MatchSource
	digests, packageIDs, advisories map[string]bool
}

func newScopeSet(scope MatchScope, advisories []string) scopeSet {
	set := func(ids []string) map[string]bool {
		if len(ids) == 0 {
			return nil
		}
		m := make(map[string]bool, len(ids))
		for _, id := range ids {
			m[id] = true
		}
		return m
	}
	return scopeSet{scope.Source, set(scope.Digests), set(scope.PackageIDs), set(advisories)}
}

func (s scopeSet) contains(m model.Match) bool {
	return (s.source == "" || m.Source == s.source) &&
		(s.digests == nil || s.digests[m.ImageDigest]) &&
		(s.packageIDs == nil || s.packageIDs[m.PackageID]) &&
		(s.advisories == nil || s.advisories[m.AdvisoryID])
}

func colsOf(m model.Match) matchCols {
	c := matchCols{
		fixState:             string(m.FixState),
		fixedVersions:        stringsText(m.FixedVersions),
		vendorSeverity:       int(m.VendorSeverity),
		vendorSeveritySource: m.VendorSeveritySource,
		namespace:            m.Namespace,
	}
	if !m.DBBuilt.IsZero() {
		c.dbBuilt = sql.NullInt64{Int64: m.DBBuilt.UTC().UnixNano(), Valid: true}
	}
	return c
}

// MatchesForDigests returns the stored matches of digests.
func (s *Store) MatchesForDigests(ctx context.Context, digests []string) ([]model.Match, error) {
	return queryAll(ctx, s.rdb, scanMatch, `SELECT `+matchColumns+` FROM matches WHERE digest IN (SELECT value FROM json_each(?))
		ORDER BY digest, package_id, advisory_id, source`, idList(digests))
}

func scanMatch(r scanner) (model.Match, error) {
	var (
		m                   model.Match
		source, fix, fixed  string
		sev                 int
		dbBuilt, observedAt sql.NullInt64
	)
	if err := r.Scan(&m.ImageDigest, &m.PackageID, &m.AdvisoryID, &source, &fix, &fixed, &sev, &m.VendorSeveritySource,
		&m.Namespace, &dbBuilt, &observedAt); err != nil {
		return model.Match{}, err
	}
	m.Source = model.MatchSource(source)
	m.FixState = model.FixState(fix)
	m.VendorSeverity = model.Severity(sev)
	m.DBBuilt = fromNanos(dbBuilt)
	m.ObservedAt = fromNanos(observedAt)
	var err error
	if m.FixedVersions, err = textStrings(fixed); err != nil {
		return model.Match{}, fmt.Errorf("match %s/%s fixed versions: %w", m.ImageDigest, m.AdvisoryID, err)
	}
	return m, nil
}
