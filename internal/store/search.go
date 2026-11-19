package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/the-it-dept/ffs/internal/model"
)

// defaultSearchLimit applies per kind when Search is called with limit <= 0.
const defaultSearchLimit = 50

// SearchHit is one search result. Kind is "package", "advisory" or "image". For a package, ID and
// Label are its name and Digests are the in-use images that carry that exact (ecosystem, name,
// version); for an advisory, ID is the canonical id and Label its title; for an image, ID is the
// digest, Label the repository and Digests holds the digest.
type SearchHit struct {
	Kind                          string
	ID, Label, Ecosystem, Version string
	Digests                       []string
}

// CountFindings returns the number of findings matching f, ignoring Limit and Offset.
func (s *Store) CountFindings(ctx context.Context, f FindingFilter) (int, error) {
	w := findingWhere(f)
	var n int
	err := s.rdb.QueryRowContext(ctx, `SELECT count(*) FROM findings`+w.String(), w.args...).Scan(&n)
	return n, err
}

// GetFinding returns the finding with the given fingerprint.
func (s *Store) GetFinding(ctx context.Context, fingerprint string) (model.Finding, bool, error) {
	f, err := scanFinding(s.rdb.QueryRowContext(ctx, `SELECT fingerprint, data FROM findings WHERE fingerprint = ?`, fingerprint))
	if errors.Is(err, sql.ErrNoRows) {
		return model.Finding{}, false, nil
	}
	return f, err == nil, err
}

// likePattern turns q into a case-insensitive substring pattern for LIKE ... ESCAPE '\', with the
// wildcards in q escaped.
func likePattern(q string) string {
	return "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(q) + "%"
}

// Search finds packages by name, advisories by id or alias and images by repository, each kind
// capped at limit (50 when limit <= 0). Packages and images are limited to digests an owner runs.
// Advisories come back under their canonical id, whichever alias matched.
func (s *Store) Search(ctx context.Context, q string, limit int) ([]SearchHit, error) {
	if limit <= 0 {
		limit = defaultSearchLimit
	}
	pat := likePattern(q)

	pkgs, err := queryAll(ctx, s.rdb, func(r scanner) (SearchHit, error) {
		h := SearchHit{Kind: "package"}
		var digests string
		if err := r.Scan(&h.Ecosystem, &h.ID, &h.Version, &digests); err != nil {
			return SearchHit{}, err
		}
		h.Label = h.ID
		h.Digests = strings.Split(digests, ",")
		return h, nil
	}, `SELECT p.ecosystem, p.name, p.version, group_concat(DISTINCT p.digest)
		FROM packages p JOIN owner_images o ON o.digest = p.digest
		WHERE p.name LIKE ? ESCAPE '\' GROUP BY p.ecosystem, p.name, p.version
		ORDER BY p.name, p.version, p.ecosystem LIMIT ?`, pat, limit)
	if err != nil {
		return nil, err
	}

	advs, err := queryAll(ctx, s.rdb, func(r scanner) (SearchHit, error) {
		h := SearchHit{Kind: "advisory"}
		return h, r.Scan(&h.ID, &h.Label)
	}, `SELECT id, COALESCE(json_extract(data, '$.Title'), '') FROM advisories
		WHERE id IN (SELECT canonical FROM advisory_aliases WHERE alias LIKE ? ESCAPE '\'
			UNION SELECT id FROM advisories WHERE id LIKE ? ESCAPE '\')
		ORDER BY id LIMIT ?`, pat, pat, limit)
	if err != nil {
		return nil, err
	}

	imgs, err := queryAll(ctx, s.rdb, func(r scanner) (SearchHit, error) {
		h := SearchHit{Kind: "image"}
		if err := r.Scan(&h.ID, &h.Label); err != nil {
			return SearchHit{}, err
		}
		h.Digests = []string{h.ID}
		return h, nil
	}, `SELECT digest, repo FROM images i WHERE repo LIKE ? ESCAPE '\'
		AND EXISTS (SELECT 1 FROM owner_images o WHERE o.digest = i.digest)
		ORDER BY repo, digest LIMIT ?`, pat, limit)
	if err != nil {
		return nil, err
	}
	return append(append(pkgs, advs...), imgs...), nil
}
