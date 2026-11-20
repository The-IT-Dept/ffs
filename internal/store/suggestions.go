package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/the-it-dept/ffs/internal/model"
)

// CandidateDigest is one platform manifest of an upgrade candidate a suggestion scored.
type CandidateDigest struct {
	Tag      string
	Tier     model.Tier
	Platform string // "linux/amd64"
	Digest   string // platform manifest digest
}

// OwnerSuggestion is the stored upgrade suggestion for one owner and image repository, with the
// candidates it scored.
type OwnerSuggestion struct {
	OwnerKey   string
	Suggestion model.Suggestion
	Candidates []CandidateDigest // in the order PutSuggestion was given them
	// Stale is set when a candidate it scored was re-matched (MarkSuggestionsStale): it stands until
	// the owner is resolved again.
	Stale bool
	// Applied is the earlier upgrade the owner now runs, nil when none (PutSuggestionApplied).
	Applied *AppliedUpgrade
}

// AppliedUpgrade is an upgrade the resolver suggested and the owner rolled out: the candidate's tag and
// tier, the platform manifests it scored, and the advisories it was to fix.
type AppliedUpgrade struct {
	Tag      string
	Tier     model.Tier
	Digests  []string
	FixedIDs []string
}

// SuggestionKey identifies a stored suggestion.
type SuggestionKey struct{ OwnerKey, Repo string }

// The suggestions table is the only source of Finding.Suggestion: PutSuggestion and
// DeleteSuggestions rewrite the owner's findings on the repository in the same transaction, and
// ApplyFindings takes each upsert's Suggestion from it. A finding carries the suggestion only when
// the suggestion fixes its advisory (see suggestionFor), so a tier-none suggestion, or one that
// leaves a won't-fix advisory open, is never shown as that finding's upgrade.
const (
	setFindingSuggestion = `UPDATE findings SET data = json_set(data, '$.Suggestion',
		CASE WHEN advisory_id IN (SELECT value FROM json_each(?)) THEN json(?) END)
		WHERE owner_key = ? AND json_extract(data, '$.ImageRepo') = ?`
	inList = ` IN (SELECT value FROM json_each(?))`

	deleteOwnerSuggestions = `DELETE FROM suggestions WHERE owner_key = ?`
	deleteOwnerCandidates  = `DELETE FROM candidates WHERE owner_key = ?`
	clearOwnerFindings     = `UPDATE findings SET data = json_set(data, '$.Suggestion', NULL) WHERE owner_key = ? AND json_extract(data, '$.Suggestion') IS NOT NULL`
	deleteRepoSuggestions  = deleteOwnerSuggestions + ` AND repo` + inList
	deleteRepoCandidates   = deleteOwnerCandidates + ` AND repo` + inList
	clearRepoFindings      = clearOwnerFindings + ` AND json_extract(data, '$.ImageRepo')` + inList

	suggestionSelect = `SELECT s.owner_key, s.repo, s.data, s.stale, s.applied, c.tag, c.tier, c.platform, c.digest
		FROM suggestions s LEFT JOIN candidates c ON c.owner_key = s.owner_key AND c.repo = s.repo`
	suggestionOrder = ` ORDER BY s.owner_key, s.repo, c.rowid`

	deleteOwnerAnnouncements = `DELETE FROM announcements WHERE owner_key = ?`
	deleteRepoAnnouncements  = deleteOwnerAnnouncements + ` AND repo` + inList
)

// PutSuggestion stores sg as the suggestion for ownerKey and sg.Repo, replaces its candidates with
// cands, and sets it as the Suggestion of the owner's findings on sg.Repo, in one transaction. The
// stored suggestion is not stale and has no applied upgrade.
func (s *Store) PutSuggestion(ctx context.Context, ownerKey string, sg model.Suggestion, cands []CandidateDigest) error {
	return s.PutSuggestionApplied(ctx, ownerKey, sg, cands, nil)
}

// PutSuggestionApplied is PutSuggestion recording applied (nil for none) as the upgrade the owner
// runs.
func (s *Store) PutSuggestionApplied(ctx context.Context, ownerKey string, sg model.Suggestion, cands []CandidateDigest,
	applied *AppliedUpgrade) error {
	data, err := jsonText(sg)
	if err != nil {
		return err
	}
	// The replaced row's other columns take their defaults: not stale, no applied upgrade. Without an
	// applied upgrade the statement names only the columns of migration 009, as a store migrated
	// before 063 has them.
	q := `INSERT OR REPLACE INTO suggestions(owner_key, repo, from_tag, data, computed_at) VALUES(?, ?, ?, ?, ?)`
	args := []any{ownerKey, sg.Repo, sg.FromTag, data, nanos(orNow(sg.ComputedAt))}
	if applied != nil {
		app, err := jsonText(applied)
		if err != nil {
			return err
		}
		q = `INSERT OR REPLACE INTO suggestions(owner_key, repo, from_tag, data, computed_at, applied) VALUES(?, ?, ?, ?, ?, ?)`
		args = append(args, app)
	}
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, q, args...); err != nil {
			return fmt.Errorf("store: suggestion %s %s: %w", ownerKey, sg.Repo, err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM candidates WHERE owner_key = ? AND repo = ?`, ownerKey, sg.Repo); err != nil {
			return err
		}
		for _, c := range cands {
			if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO candidates(owner_key, repo, tag, tier, platform, digest) VALUES(?, ?, ?, ?, ?, ?)`,
				ownerKey, sg.Repo, c.Tag, string(c.Tier), c.Platform, c.Digest); err != nil {
				return fmt.Errorf("store: candidate %s %s:%s: %w", ownerKey, sg.Repo, c.Tag, err)
			}
		}
		_, err := tx.ExecContext(ctx, setFindingSuggestion, idList(fixedIDs(sg)), data, ownerKey, sg.Repo)
		return err
	})
}

// fixedIDs are the advisories whose findings carry sg: none for a tier-none suggestion.
func fixedIDs(sg model.Suggestion) []string {
	if sg.Tier == model.TierNone {
		return nil
	}
	return sg.FixedIDs
}

// suggestionFor is the Suggestion of a finding on advisoryID given the stored suggestion for its
// owner and repository: sg when it fixes that advisory, else nil.
func suggestionFor(sg *model.Suggestion, advisoryID string) *model.Suggestion {
	if sg == nil || !slices.Contains(fixedIDs(*sg), advisoryID) {
		return nil
	}
	return sg
}

// DeleteSuggestions deletes the owner's suggestions on repos, with their candidates, and clears the
// Suggestion of the owner's findings on those repos, in one transaction. nil repos means every
// repository of the owner; an empty non-nil slice deletes nothing.
func (s *Store) DeleteSuggestions(ctx context.Context, ownerKey string, repos []string) error {
	if repos != nil && len(repos) == 0 {
		return nil
	}
	queries, args := []string{deleteOwnerSuggestions, deleteOwnerCandidates, clearOwnerFindings}, []any{ownerKey}
	if repos != nil {
		queries, args = []string{deleteRepoSuggestions, deleteRepoCandidates, clearRepoFindings}, []any{ownerKey, idList(repos)}
	}
	return s.inTx(ctx, func(tx *sql.Tx) error {
		for _, q := range queries {
			if _, err := tx.ExecContext(ctx, q, args...); err != nil {
				return fmt.Errorf("store: delete suggestions of %s: %w", ownerKey, err)
			}
		}
		return nil
	})
}

// GetSuggestion returns the stored suggestion for ownerKey and repo.
func (s *Store) GetSuggestion(ctx context.Context, ownerKey, repo string) (OwnerSuggestion, bool, error) {
	out, err := s.querySuggestions(ctx, suggestionSelect+` WHERE s.owner_key = ? AND s.repo = ?`+suggestionOrder, ownerKey, repo)
	if err != nil || len(out) == 0 {
		return OwnerSuggestion{}, false, err
	}
	return out[0], true, nil
}

// ListSuggestions returns every stored suggestion, ordered by owner key and repository.
func (s *Store) ListSuggestions(ctx context.Context) ([]OwnerSuggestion, error) {
	return s.querySuggestions(ctx, suggestionSelect+suggestionOrder)
}

// SuggestionKeysForDigests returns the sorted, distinct suggestions that scored a candidate with
// any of digests.
func (s *Store) SuggestionKeysForDigests(ctx context.Context, digests []string) ([]SuggestionKey, error) {
	return queryAll(ctx, s.rdb, func(r scanner) (SuggestionKey, error) {
		var k SuggestionKey
		err := r.Scan(&k.OwnerKey, &k.Repo)
		return k, err
	}, `SELECT DISTINCT owner_key, repo FROM candidates WHERE digest`+inList+` ORDER BY owner_key, repo`, idList(digests))
}

// MarkSuggestionsStale marks the suggestions keys as stale. They stay in place, Suggestion of the
// owners' findings included, until they are stored again or deleted.
func (s *Store) MarkSuggestionsStale(ctx context.Context, keys []SuggestionKey) error {
	if len(keys) == 0 {
		return nil
	}
	pairs := make([][2]string, len(keys))
	for i, k := range keys {
		pairs[i] = [2]string{k.OwnerKey, k.Repo}
	}
	list, err := jsonText(pairs)
	if err != nil {
		return err
	}
	if _, err := s.wdb.ExecContext(ctx, `UPDATE suggestions SET stale = 1 WHERE stale = 0 AND (owner_key, repo) IN
		(SELECT json_extract(value, '$[0]'), json_extract(value, '$[1]') FROM json_each(?))`, list); err != nil {
		return fmt.Errorf("store: mark suggestions stale: %w", err)
	}
	return nil
}

// OwnersWithSuggestions returns which of keys have a stored suggestion.
func (s *Store) OwnersWithSuggestions(ctx context.Context, keys []string) (map[string]bool, error) {
	got, err := queryAll(ctx, s.rdb, scanString, `SELECT DISTINCT owner_key FROM suggestions WHERE owner_key`+inList, idList(keys))
	if err != nil {
		return nil, fmt.Errorf("store: owners with suggestions: %w", err)
	}
	out := make(map[string]bool, len(got))
	for _, k := range got {
		out[k] = true
	}
	return out, nil
}

// OwnersToResolve returns, sorted, the owners whose upgrade suggestions a restart may have left out
// of date: those with a stale suggestion, and those with an open finding at or above medium on an
// image repository that has no stored suggestion. A workload's finding needs a fix; a Cluster or
// ContainerRuntime owner's does not, as its advice does not. The Nodes owner is never advised.
func (s *Store) OwnersToResolve(ctx context.Context) ([]string, error) {
	got, err := queryAll(ctx, s.rdb, scanString, `SELECT owner_key FROM suggestions WHERE stale = 1
		UNION
		SELECT f.owner_key FROM findings f WHERE f.state = ? AND f.priority >= ?
			AND (f.fix_available = 1 OR (f.namespace = '' AND f.owner_kind IN (?, ?)))
			AND NOT (f.namespace = '' AND f.owner_kind = ?)
			AND NOT EXISTS (SELECT 1 FROM suggestions s WHERE s.owner_key = f.owner_key AND s.repo = f.image_repo)
		ORDER BY 1`,
		string(model.StateOpen), int(model.PriorityMedium), model.OwnerKindCluster, model.OwnerKindContainerRuntime, model.OwnerKindNodes)
	if err != nil {
		return nil, fmt.Errorf("store: owners to resolve: %w", err)
	}
	return got, nil
}

// Announced returns the upgrade target (ToTag, ToDigest) last announced for ownerKey on repo.
// Storing or deleting a suggestion leaves it in place, so a suggestion replaced by one that
// recommends nothing, and resolved again to the same target, is not announced twice.
func (s *Store) Announced(ctx context.Context, ownerKey, repo string) (toTag, toDigest string, ok bool, err error) {
	err = s.rdb.QueryRowContext(ctx, `SELECT to_tag, to_digest FROM announcements WHERE owner_key = ? AND repo = ?`,
		ownerKey, repo).Scan(&toTag, &toDigest)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", "", false, nil
	case err != nil:
		return "", "", false, fmt.Errorf("store: announcement %s %s: %w", ownerKey, repo, err)
	}
	return toTag, toDigest, true, nil
}

// AnnounceSuggestion appends ts (the UpgradeAvailable transitions announcing sg) and records sg's
// target as the one announced for ownerKey on sg.Repo, in one transaction.
func (s *Store) AnnounceSuggestion(ctx context.Context, ownerKey string, sg model.Suggestion, ts []model.Transition) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO announcements(owner_key, repo, to_tag, to_digest) VALUES(?, ?, ?, ?)`,
			ownerKey, sg.Repo, sg.ToTag, sg.ToDigest); err != nil {
			return fmt.Errorf("store: announcement %s %s: %w", ownerKey, sg.Repo, err)
		}
		return appendTransitions(ctx, tx, ts)
	})
}

// DeleteAnnouncements forgets the targets announced for ownerKey on repos. nil repos means every
// repository of the owner; an empty non-nil slice deletes nothing.
func (s *Store) DeleteAnnouncements(ctx context.Context, ownerKey string, repos []string) error {
	if repos != nil && len(repos) == 0 {
		return nil
	}
	q, args := deleteOwnerAnnouncements, []any{ownerKey}
	if repos != nil {
		q, args = deleteRepoAnnouncements, []any{ownerKey, idList(repos)}
	}
	if _, err := s.wdb.ExecContext(ctx, q, args...); err != nil {
		return fmt.Errorf("store: delete announcements of %s: %w", ownerKey, err)
	}
	return nil
}

// querySuggestions runs a suggestionSelect query, one row per candidate (or one row with NULL
// candidate columns), and groups the rows into suggestions. One statement reads both tables, so
// a suggestion and its candidates come from the same snapshot.
func (s *Store) querySuggestions(ctx context.Context, query string, args ...any) ([]OwnerSuggestion, error) {
	rows, err := s.rdb.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var (
		out               []OwnerSuggestion
		lastKey, lastRepo string
	)
	for rows.Next() {
		var (
			key, repo, data                    string
			stale                              bool
			applied, tag, tier, platform, dgst sql.NullString
		)
		if err := rows.Scan(&key, &repo, &data, &stale, &applied, &tag, &tier, &platform, &dgst); err != nil {
			return nil, err
		}
		if len(out) == 0 || key != lastKey || repo != lastRepo {
			sg := OwnerSuggestion{OwnerKey: key, Stale: stale}
			if err := json.Unmarshal([]byte(data), &sg.Suggestion); err != nil {
				return nil, fmt.Errorf("suggestion %s %s: %w", key, repo, err)
			}
			if applied.Valid {
				sg.Applied = &AppliedUpgrade{}
				if err := json.Unmarshal([]byte(applied.String), sg.Applied); err != nil {
					return nil, fmt.Errorf("applied upgrade %s %s: %w", key, repo, err)
				}
			}
			out = append(out, sg)
			lastKey, lastRepo = key, repo
		}
		if tag.Valid {
			last := &out[len(out)-1]
			last.Candidates = append(last.Candidates, CandidateDigest{Tag: tag.String, Tier: model.Tier(tier.String),
				Platform: platform.String, Digest: dgst.String})
		}
	}
	return out, rows.Err()
}

// suggestionCache reads stored suggestions inside a write transaction, once per owner and repo.
type suggestionCache struct {
	tx   *sql.Tx
	seen map[SuggestionKey]*model.Suggestion
}

// get returns the stored suggestion for ownerKey and repo, or nil when there is none.
func (c *suggestionCache) get(ctx context.Context, ownerKey, repo string) (*model.Suggestion, error) {
	k := SuggestionKey{ownerKey, repo}
	if sg, ok := c.seen[k]; ok {
		return sg, nil
	}
	var data string
	err := c.tx.QueryRowContext(ctx, `SELECT data FROM suggestions WHERE owner_key = ? AND repo = ?`, ownerKey, repo).Scan(&data)
	var sg *model.Suggestion
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return nil, err
	default:
		sg = &model.Suggestion{}
		if err := json.Unmarshal([]byte(data), sg); err != nil {
			return nil, fmt.Errorf("suggestion %s %s: %w", ownerKey, repo, err)
		}
	}
	c.seen[k] = sg
	return sg, nil
}
