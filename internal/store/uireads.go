package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/the-it-dept/ffs/internal/model"
)

// The web UI's other reads: namespace and owner rollups for the rail, exposure edges for the home
// table, the best fix per owner, coverage figures, the advisory page's match reads, the ⌘K jump,
// the live stream's change marks and an SBOM's tool descriptor.

// NamespaceStat is a workload namespace with its rollup counts and coverage.
type NamespaceStat struct {
	Namespace string
	Workloads int
	Exposed   int
	Stats     OwnerStats
	Coverage  CoverageFigure
}

// NamespaceStats returns every namespace that holds a workload, by name.
func (s *Store) NamespaceStats(ctx context.Context) ([]NamespaceStat, error) {
	return queryAll(ctx, s.rdb, func(r scanner) (NamespaceStat, error) {
		var n NamespaceStat
		st, err := scanOwnerStats(r, &n.Namespace, &n.Workloads, &n.Exposed, &n.Coverage.InUse, &n.Coverage.SeenInto, &n.Coverage.Full)
		n.Stats = st
		return n, err
	}, `WITH ns AS (SELECT namespace, count(*) AS workloads, sum(exposed) AS exposed FROM owners WHERE namespace != '' GROUP BY namespace),
		st(namespace, `+ownerStatsCols+`) AS (SELECT namespace, `+ownerStatsSums+` FROM owner_stats WHERE namespace != '' GROUP BY namespace),
		cov AS (SELECT o.namespace, count(DISTINCT oi.digest) AS in_use,
			count(DISTINCT CASE WHEN `+seenSQL("i", "oi.digest")+` THEN oi.digest END) AS seen_into,
			count(DISTINCT CASE WHEN `+fullSQL("i", "oi.digest")+` THEN oi.digest END) AS cov_full
			FROM owner_images oi JOIN owners o ON o.key = oi.owner_key LEFT JOIN images i ON i.digest = oi.digest
			WHERE o.namespace != '' AND `+containerDigest("oi.digest")+` GROUP BY o.namespace)
		SELECT ns.namespace, ns.workloads, ns.exposed, coalesce(cov.in_use, 0), coalesce(cov.seen_into, 0), coalesce(cov.cov_full, 0),
			`+prefixedCols("st.", ownerStatsCols, "")+`
		FROM ns LEFT JOIN cov ON cov.namespace = ns.namespace LEFT JOIN st ON st.namespace = ns.namespace ORDER BY ns.namespace`)
}

// OwnerEntities returns the workloads of a cluster or namespace scope, by namespace, name and key.
func (s *Store) OwnerEntities(ctx context.Context, sc model.Scope) ([]OwnerEntity, error) {
	var w where
	w.add(`e.namespace != ''`)
	switch sc.Kind {
	case model.ScopeCluster, "":
	case model.ScopeNamespace:
		w.add(`e.namespace = ?`, sc.Value)
	default:
		return nil, scopeErr(sc)
	}
	return queryAll(ctx, s.rdb, scanOwnerEntity, `SELECT `+ownerEntityCols+` FROM `+ownerEntityFrom+w.String()+
		` ORDER BY e.namespace, e.name, e.key`, w.args...)
}

// OwnerEntityOf returns the owner stored under key, of any kind.
func (s *Store) OwnerEntityOf(ctx context.Context, key string) (OwnerEntity, bool, error) {
	e, err := scanOwnerEntity(s.rdb.QueryRowContext(ctx, `SELECT `+ownerEntityCols+` FROM `+ownerEntityFrom+` WHERE e.key = ?`, key))
	if errors.Is(err, sql.ErrNoRows) {
		return OwnerEntity{}, false, nil
	}
	return e, err == nil, err
}

// ExposureEdgeRow is one exposure edge of an owner. Edge.Path is "": the exposure_edges view does
// not carry it.
type ExposureEdgeRow struct {
	OwnerKey, Namespace string
	Edge                model.ExposureEdge
}

// ExposureEdges returns the exposure edges of the owners in a cluster, namespace or workload
// scope, internal ones included, by owner key and then in edge order.
func (s *Store) ExposureEdges(ctx context.Context, sc model.Scope) ([]ExposureEdgeRow, error) {
	var w where
	switch sc.Kind {
	case model.ScopeCluster, "":
	case model.ScopeNamespace:
		w.add(`namespace = ?`, sc.Value)
	case model.ScopeWorkload:
		w.add(`owner_key = ?`, sc.Value)
	default:
		return nil, scopeErr(sc)
	}
	return queryAll(ctx, s.rdb, func(r scanner) (ExposureEdgeRow, error) {
		var (
			e     ExposureEdgeRow
			entry string
		)
		err := r.Scan(&e.OwnerKey, &e.Namespace, &entry, &e.Edge.EntryName, &e.Edge.Listener, &e.Edge.Hostname, &e.Edge.Route,
			&e.Edge.Service, &e.Edge.Internal)
		e.Edge.Entry = model.EntryKind(entry)
		return e, err
	}, `SELECT owner_key, namespace, entry, coalesce(entry_name, ''), coalesce(listener, ''), coalesce(hostname, ''), coalesce(route, ''),
		coalesce(service, ''), coalesce(internal, 0) FROM exposure_edges`+w.String()+
		` ORDER BY owner_key, entry, entry_name, listener, hostname, route, service, internal`, w.args...)
}

// FixSummary is an owner's best fix: the action, the open findings it clears by priority, and its
// highest-priority finding.
type FixSummary struct {
	Key      string
	Kind     model.FixKind
	Clears   PriorityCounts
	Findings int
	Sample   model.Finding
}

// bestFixesQuery groups the open findings of the owners in the JSON key list by fix action and
// picks each owner's best group. It reads only the findings_fix index: a fix_key other than none
// and wontfix is an upgrade or a rebuild or package action, which Build sets only with a fixed
// version, so it needs no fix_class test (fix_class is not in the index and reads the row).
const bestFixesQuery = `WITH g AS (SELECT owner_key, fix_key, sum(priority = 4) AS u, sum(priority = 3) AS h, sum(priority = 2) AS m,
		sum(priority = 1) AS l, count(*) AS n FROM findings WHERE state = 'open' AND owner_key IN (SELECT value FROM json_each(?))
		AND fix_key NOT IN ('none', 'wontfix') GROUP BY owner_key, fix_key),
	r AS (SELECT *, row_number() OVER (PARTITION BY owner_key ORDER BY u DESC, h DESC, n DESC, fix_key) AS rn FROM g)
	SELECT owner_key, fix_key, u, h, m, l, n FROM r WHERE rn = 1`

// BestFixes returns, per owner of keys, the fix clearing the most urgent, then high, then open
// findings, ties by key, among open findings with an upgrade or a fixed version. Owners with no
// such finding are absent.
func (s *Store) BestFixes(ctx context.Context, keys []string) (map[string]FixSummary, error) {
	out := map[string]FixSummary{}
	if len(keys) == 0 {
		return out, nil
	}
	type pick struct {
		owner string
		fix   FixSummary
	}
	best, err := queryAll(ctx, s.rdb, func(r scanner) (pick, error) {
		var p pick
		f := &p.fix
		err := r.Scan(&p.owner, &f.Key, &f.Clears.Urgent, &f.Clears.High, &f.Clears.Medium, &f.Clears.Low, &f.Findings)
		return p, err
	}, bestFixesQuery, idList(keys))
	if err != nil {
		return nil, fmt.Errorf("store: best fixes: %w", err)
	}
	if len(best) == 0 {
		return out, nil
	}
	pairs := make([][2]string, len(best))
	for i, p := range best {
		pairs[i] = [2]string{p.owner, p.fix.Key}
	}
	pairsJSON, err := json.Marshal(pairs)
	if err != nil {
		return nil, err
	}
	// Rank each pair's findings without their JSON, then read only the winners' rows.
	rows, err := s.rdb.QueryContext(ctx, `SELECT f.owner_key, f.fix_key, f.fingerprint, f.data FROM (SELECT rowid AS rid,
			row_number() OVER (PARTITION BY owner_key, fix_key ORDER BY priority DESC, fingerprint) AS rn FROM findings
			WHERE state = 'open' AND (owner_key, fix_key) IN (SELECT json_extract(value, '$[0]'), json_extract(value, '$[1]') FROM json_each(?))) r
		JOIN findings f ON f.rowid = r.rid WHERE r.rn = 1`, string(pairsJSON))
	if err != nil {
		return nil, fmt.Errorf("store: best fix samples: %w", err)
	}
	defer func() { _ = rows.Close() }()
	samples := map[[2]string]model.Finding{}
	for rows.Next() {
		var owner, key, fp, data string
		if err := rows.Scan(&owner, &key, &fp, &data); err != nil {
			return nil, err
		}
		var f model.Finding
		if err := json.Unmarshal([]byte(data), &f); err != nil {
			return nil, fmt.Errorf("store: finding %s: %w", fp, err)
		}
		samples[[2]string{owner, key}] = f
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i, p := range best {
		f := p.fix
		f.Sample = samples[pairs[i]]
		switch {
		case strings.HasPrefix(f.Key, "upgrade:"):
			f.Kind = model.FixKindUpgrade
		case f.Sample.Fix != nil:
			f.Kind = f.Sample.Fix.Kind
		default:
			f.Kind = f.Sample.EffectiveFix().Kind
		}
		out[p.owner] = f
	}
	return out, nil
}

// CoverageOf returns the coverage figure of a cluster, namespace or workload scope (its owners'
// distinct in-use container digests; no images row counts as in use only), or of one image, whose
// figure is its own: in use when an owner runs it. An image is seen into once it is catalogued and
// its first match has run.
func (s *Store) CoverageOf(ctx context.Context, sc model.Scope) (CoverageFigure, error) {
	var c CoverageFigure
	if sc.Kind == model.ScopeImage {
		err := s.rdb.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM owner_images WHERE digest = ?),
			coalesce((SELECT `+seenSQL("i", "i.digest")+` FROM images i WHERE i.digest = ?), 0),
			coalesce((SELECT `+fullSQL("i", "i.digest")+` FROM images i WHERE i.digest = ?), 0)`,
			sc.Value, sc.Value, sc.Value).Scan(&c.InUse, &c.SeenInto, &c.Full)
		if err != nil {
			return CoverageFigure{}, fmt.Errorf("store: coverage of %s: %w", sc, err)
		}
		return c, nil
	}
	var w where
	w.add(containerDigest("oi.digest"))
	switch sc.Kind {
	case model.ScopeCluster, "":
	case model.ScopeNamespace:
		w.add(`oi.owner_key IN (SELECT key FROM owners WHERE namespace = ?)`, sc.Value)
	case model.ScopeWorkload:
		w.add(`oi.owner_key = ?`, sc.Value)
	default:
		return CoverageFigure{}, scopeErr(sc)
	}
	err := s.rdb.QueryRowContext(ctx, `SELECT count(DISTINCT oi.digest), count(DISTINCT CASE WHEN `+seenSQL("i", "oi.digest")+` THEN oi.digest END),
		count(DISTINCT CASE WHEN `+fullSQL("i", "oi.digest")+` THEN oi.digest END)
		FROM owner_images oi LEFT JOIN images i ON i.digest = oi.digest`+w.String(), w.args...).Scan(&c.InUse, &c.SeenInto, &c.Full)
	if err != nil {
		return CoverageFigure{}, fmt.Errorf("store: coverage of %s: %w", sc, err)
	}
	return c, nil
}

// OwnerCoverage returns the coverage figure of each owner of keys that runs a container image;
// the others are absent, so they read as zero.
func (s *Store) OwnerCoverage(ctx context.Context, keys []string) (map[string]CoverageFigure, error) {
	out := map[string]CoverageFigure{}
	if len(keys) == 0 {
		return out, nil
	}
	rows, err := s.rdb.QueryContext(ctx, `WITH `+ownerCoverageCTE+` SELECT owner_key, in_use, seen_into, cov_full FROM owner_cov
		WHERE owner_key IN (SELECT value FROM json_each(?))`, idList(keys))
	if err != nil {
		return nil, fmt.Errorf("store: owner coverage: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			key string
			c   CoverageFigure
		)
		if err := rows.Scan(&key, &c.InUse, &c.SeenInto, &c.Full); err != nil {
			return nil, err
		}
		out[key] = c
	}
	return out, rows.Err()
}

// CoverageImage is an in-use container image not seen into in full detail, or one holding packages
// a binary classifier found, with the owners in scope that run it. Without an images row, HasRow is
// false and the image is pending, with its repository and platform from the container. A
// catalogued image whose first match has not run is pending.
type CoverageImage struct {
	Image  model.Image
	Owners []string
	HasRow bool
}

// CoverageImages returns the in-use container images of a cluster, namespace or workload scope
// that are not seen into in full detail, and those that are but hold classifier-found packages
// (which may be matched against CPE data only), by repository and digest.
func (s *Store) CoverageImages(ctx context.Context, sc model.Scope) ([]CoverageImage, error) {
	switch sc.Kind {
	case model.ScopeCluster, "", model.ScopeNamespace, model.ScopeWorkload:
	default:
		return nil, scopeErr(sc)
	}
	cte, args, err := imagesCTE(ImageQuery{Scope: sc})
	if err != nil {
		return nil, err
	}
	return queryAll(ctx, s.rdb, func(r scanner) (CoverageImage, error) {
		var (
			c      CoverageImage
			owners string
		)
		img := &imageScan{}
		if err := r.Scan(append(img.dest(), &c.HasRow, &owners)...); err != nil {
			return CoverageImage{}, err
		}
		var err error
		if c.Image, err = img.image(); err != nil {
			return CoverageImage{}, err
		}
		c.Owners = strings.Split(owners, "\x1f")
		slices.Sort(c.Owners)
		return c, nil
	}, cte+` SELECT `+imageCols+`, EXISTS (SELECT 1 FROM images x WHERE x.digest = im.digest),
		(SELECT group_concat(u.owner_key, char(31)) FROM inuse u WHERE u.digest = im.digest)
		FROM im WHERE cov != 'full' OR EXISTS (SELECT 1 FROM packages p WHERE p.digest = im.digest AND p.classifier != '')
		ORDER BY repo, digest`, args...)
}

// DigestCoverage is how far ffs sees into one in-use container image.
type DigestCoverage struct {
	Digest         string
	SeenInto, Full bool
}

// ownerImageCoverageQuery reads the distinct container images of the owners in the JSON key list,
// with whether each is seen into and in full detail.
//
//nolint:gosec // G202: joins this package's SQL fragments; every value is a bound parameter
var ownerImageCoverageQuery = `SELECT DISTINCT oi.owner_key, oi.digest, coalesce(` + seenSQL("i", "oi.digest") + `, 0),
	coalesce(` + fullSQL("i", "oi.digest") + `, 0)
	FROM owner_images oi LEFT JOIN images i ON i.digest = oi.digest
	WHERE oi.owner_key IN (SELECT value FROM json_each(?)) AND ` + containerDigest("oi.digest") + ` ORDER BY oi.owner_key, oi.digest`

// OwnerImageCoverage returns, per owner of keys, the distinct container images it runs and how far
// ffs sees into each, by digest, so a group of owners can count shared images once.
func (s *Store) OwnerImageCoverage(ctx context.Context, keys []string) (map[string][]DigestCoverage, error) {
	out := map[string][]DigestCoverage{}
	if len(keys) == 0 {
		return out, nil
	}
	rows, err := s.rdb.QueryContext(ctx, ownerImageCoverageQuery, idList(keys))
	if err != nil {
		return nil, fmt.Errorf("store: owner image coverage: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			key string
			c   DigestCoverage
		)
		if err := rows.Scan(&key, &c.Digest, &c.SeenInto, &c.Full); err != nil {
			return nil, err
		}
		out[key] = append(out[key], c)
	}
	return out, rows.Err()
}

// DigestsOfOwners returns every digest each owner of keys runs, synthetic ones included, sorted.
func (s *Store) DigestsOfOwners(ctx context.Context, keys []string) (map[string][]string, error) {
	out := map[string][]string{}
	if len(keys) == 0 {
		return out, nil
	}
	rows, err := s.rdb.QueryContext(ctx, `SELECT DISTINCT owner_key, digest FROM owner_images
		WHERE owner_key IN (SELECT value FROM json_each(?)) ORDER BY owner_key, digest`, idList(keys))
	if err != nil {
		return nil, fmt.Errorf("store: digests of owners: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var key, digest string
		if err := rows.Scan(&key, &digest); err != nil {
			return nil, err
		}
		out[key] = append(out[key], digest)
	}
	return out, rows.Err()
}

// TagsOf returns the "repo:tag" references last resolved to digest, sorted.
func (s *Store) TagsOf(ctx context.Context, digest string) ([]string, error) {
	return queryAll(ctx, s.rdb, scanString, `SELECT repo || ':' || tag FROM image_tags WHERE digest = ? ORDER BY 1`, digest)
}

// canonicalArg resolves an advisory id, or any alias, to its canonical id, as GetAdvisory does.
const canonicalArg = `COALESCE((SELECT canonical FROM advisory_aliases WHERE alias = ?), ?)`

// SourceSeverity is the highest vendor severity one source gives an advisory.
type SourceSeverity struct {
	Source   string
	Severity model.Severity
}

// AdvisorySeverities returns, per vendor severity source, the highest severity the matches of the
// advisory id (or alias) carry, by source.
func (s *Store) AdvisorySeverities(ctx context.Context, id string) ([]SourceSeverity, error) {
	return queryAll(ctx, s.rdb, func(r scanner) (SourceSeverity, error) {
		var (
			v   SourceSeverity
			sev int
		)
		err := r.Scan(&v.Source, &sev)
		v.Severity = model.Severity(sev)
		return v, err
	}, `SELECT vendor_severity_source, max(vendor_severity) FROM matches WHERE advisory_id = `+canonicalArg+`
		AND vendor_severity_source != '' AND vendor_severity > 0 GROUP BY vendor_severity_source ORDER BY vendor_severity_source`, id, id)
}

// AdvisoryFirstMatched returns when ffs first matched the advisory id (or alias), or the zero time.
func (s *Store) AdvisoryFirstMatched(ctx context.Context, id string) (time.Time, error) {
	var at sql.NullInt64
	if err := s.rdb.QueryRowContext(ctx, `SELECT min(observed_at) FROM matches WHERE advisory_id = `+canonicalArg, id, id).Scan(&at); err != nil {
		return time.Time{}, fmt.Errorf("store: advisory first matched: %w", err)
	}
	return fromNanos(at), nil
}

// AdvisorySeverityUsed returns the severity source most of the advisory's open findings were
// ranked with, ties by source; "" when it has none.
func (s *Store) AdvisorySeverityUsed(ctx context.Context, id string) (string, error) {
	var src string
	err := s.rdb.QueryRowContext(ctx, `SELECT coalesce(json_extract(data, '$.SeveritySource'), '') AS src FROM findings
		WHERE state = 'open' AND advisory_id = `+canonicalArg+` GROUP BY src ORDER BY count(*) DESC, src LIMIT 1`, id, id).Scan(&src)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return src, err
}

// JumpHit is one ⌘K result. Kind is workload (ID the owner key), namespace, image (ID the digest),
// advisory (the canonical ID), package (ID "<ecosystem>/<name>"), node, or hostpackage: a package
// held only by a node group's host packages (ID the group's "nodegroup:<id>" digest, Label the
// package name, Detail its version), which the API turns into a node group hit. Prefix is set when
// the label (for an advisory, its ID or an alias) starts with the query.
type JumpHit struct {
	Kind, ID, Label, Detail string
	Worst                   model.Priority
	Prefix                  bool
}

const defaultJumpLimit = 5

// countNoun is "1 <one>" or "<n> <one>s".
func countNoun(n int, one string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %ss", n, one)
}

// Jump finds workloads, namespaces, images, advisories, packages, host-only packages and nodes for
// q, at most limit of each kind (5 when limit <= 0), in that order; more reports that some kind had
// more. Within a kind, labels starting with q come first, then labels containing it, each by label
// and ID: the rank is taken before the cut, so a prefix hit is never lost to an alphabetical one.
// Images and packages are those of in-use container images; synthetic digests are never image hits.
func (s *Store) Jump(ctx context.Context, q string, limit int) (hits []JumpHit, more bool, err error) {
	if limit <= 0 {
		limit = defaultJumpLimit
	}
	n := limit + 1 // one more tells that the kind has more
	pat, pre := likePattern(q), likePrefix(q)
	inUse := `SELECT digest FROM owner_images WHERE ` + containerDigest("digest")
	kinds := []struct {
		name string
		scan func(scanner) (JumpHit, error)
		// query selects the hit's columns and then whether its label starts with q (pre).
		query string
		args  []any
	}{
		{"workloads", func(r scanner) (JumpHit, error) {
			h := JumpHit{Kind: "workload"}
			var kind, ns string
			var worst int
			err := r.Scan(&h.ID, &h.Label, &kind, &ns, &worst, &h.Prefix)
			h.Detail, h.Worst = kind+" · "+ns, model.Priority(worst)
			return h, err
		}, `SELECT o.key, o.name, o.kind, o.namespace, coalesce(` + worstOf("st.") + `, 0), o.name LIKE ? ESCAPE '\' AS pre FROM owners o
			LEFT JOIN owner_stats st ON st.owner_key = o.key WHERE o.namespace != '' AND o.name LIKE ? ESCAPE '\'
			ORDER BY pre DESC, o.name, o.key LIMIT ?`, []any{pre, pat, n}},
		{"namespaces", func(r scanner) (JumpHit, error) {
			h := JumpHit{Kind: "namespace"}
			var count, worst int
			err := r.Scan(&h.ID, &count, &worst, &h.Prefix)
			h.Label, h.Detail, h.Worst = h.ID, countNoun(count, "workload"), model.Priority(worst)
			return h, err
		}, `SELECT o.namespace, count(*), coalesce(max(` + worstOf("st.") + `), 0), o.namespace LIKE ? ESCAPE '\' AS pre FROM owners o
			LEFT JOIN owner_stats st ON st.owner_key = o.key WHERE o.namespace != '' AND o.namespace LIKE ? ESCAPE '\'
			GROUP BY o.namespace ORDER BY pre DESC, o.namespace LIMIT ?`, []any{pre, pat, n}},
		{"images", func(r scanner) (JumpHit, error) {
			h := JumpHit{Kind: "image"}
			err := r.Scan(&h.ID, &h.Label, &h.Prefix)
			h.Detail = h.ID
			return h, err
		}, `SELECT i.digest, i.repo, i.repo LIKE ? ESCAPE '\' AS pre FROM images i WHERE i.repo LIKE ? ESCAPE '\'
			AND ` + containerDigest("i.digest") + ` AND i.digest IN (` + inUse + `) ORDER BY pre DESC, i.repo, i.digest LIMIT ?`,
			[]any{pre, pat, n}},
		{"advisories", func(r scanner) (JumpHit, error) {
			h := JumpHit{Kind: "advisory"}
			err := r.Scan(&h.ID, &h.Detail, &h.Prefix)
			h.Label = h.ID
			return h, err
		}, `WITH m(id, pre) AS (SELECT canonical, alias LIKE ? ESCAPE '\' FROM advisory_aliases WHERE alias LIKE ? ESCAPE '\'
				UNION ALL SELECT id, id LIKE ? ESCAPE '\' FROM advisories WHERE id LIKE ? ESCAPE '\'),
			b AS (SELECT id, max(pre) AS pre FROM m GROUP BY id)
			SELECT a.id, coalesce(json_extract(a.data, '$.Title'), ''), b.pre FROM b JOIN advisories a ON a.id = b.id
			ORDER BY b.pre DESC, a.id LIMIT ?`, []any{pre, pat, pre, pat, n}},
		{"packages", func(r scanner) (JumpHit, error) {
			h := JumpHit{Kind: "package"}
			var eco string
			err := r.Scan(&eco, &h.Label, &h.Prefix)
			h.ID, h.Detail = eco+"/"+h.Label, eco
			return h, err
		}, `SELECT p.ecosystem, p.name, p.name LIKE ? ESCAPE '\' AS pre FROM packages p WHERE p.name LIKE ? ESCAPE '\'
			AND p.digest IN (` + inUse + `) GROUP BY p.ecosystem, p.name ORDER BY pre DESC, p.name, p.ecosystem LIMIT ?`, []any{pre, pat, n}},
		{"host packages", func(r scanner) (JumpHit, error) {
			h := JumpHit{Kind: "hostpackage"}
			err := r.Scan(&h.ID, &h.Label, &h.Detail, &h.Prefix)
			return h, err
		}, `SELECT p.digest, p.name, ` + installedExpr("p") + `, p.name LIKE ? ESCAPE '\' AS pre FROM packages p
			WHERE p.digest IN (SELECT digest FROM owner_images WHERE digest LIKE 'nodegroup:%') AND p.name LIKE ? ESCAPE '\'
			AND NOT EXISTS (SELECT 1 FROM packages c WHERE c.ecosystem = p.ecosystem AND c.name = p.name AND c.digest IN (` + inUse + `))
			GROUP BY p.digest, p.name ORDER BY pre DESC, p.name, p.digest LIMIT ?`, []any{pre, pat, n}},
		{"nodes", func(r scanner) (JumpHit, error) {
			h := JumpHit{Kind: "node"}
			err := r.Scan(&h.ID, &h.Prefix)
			h.Label = h.ID
			return h, err
		}, `SELECT name, name LIKE ? ESCAPE '\' AS pre FROM nodes WHERE name LIKE ? ESCAPE '\' ORDER BY pre DESC, name LIMIT ?`,
			[]any{pre, pat, n}},
	}
	for _, k := range kinds {
		got, err := queryAll(ctx, s.rdb, k.scan, k.query, k.args...)
		if err != nil {
			return nil, false, fmt.Errorf("store: jump %s: %w", k.name, err)
		}
		if len(got) > limit {
			got, more = got[:limit], true
		}
		hits = append(hits, got...)
	}
	for _, w := range []struct {
		kind, query string
	}{
		{"image", `SELECT digest, max(priority) FROM finding_digests WHERE state = 'open'
			AND digest IN (SELECT value FROM json_each(?)) GROUP BY digest`},
		{"advisory", `SELECT advisory_id, max(priority) FROM findings WHERE state = 'open'
			AND advisory_id IN (SELECT value FROM json_each(?)) GROUP BY advisory_id`},
		{"package", `SELECT ecosystem || '/' || name, max(priority) FROM finding_packages WHERE state = 'open'
			AND ecosystem || '/' || name IN (SELECT value FROM json_each(?)) GROUP BY ecosystem, name`},
	} {
		if err := s.jumpWorst(ctx, hits, w.kind, w.query); err != nil {
			return nil, false, err
		}
	}
	return hits, more, nil
}

// worstOf is the worst open priority of the owner_stats columns prefixed p.
func worstOf(p string) string {
	return `CASE WHEN ` + p + `urgent > 0 THEN 4 WHEN ` + p + `high > 0 THEN 3 WHEN ` + p + `medium > 0 THEN 2 WHEN ` + p + `low > 0 THEN 1 END`
}

// jumpWorst sets the Worst of the hits of kind from a (ID, max priority) statement over the JSON
// list of their IDs.
func (s *Store) jumpWorst(ctx context.Context, hits []JumpHit, kind, query string) error {
	var ids []string
	for _, h := range hits {
		if h.Kind == kind {
			ids = append(ids, h.ID)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	rows, err := s.rdb.QueryContext(ctx, query, idList(ids))
	if err != nil {
		return fmt.Errorf("store: jump worst: %w", err)
	}
	defer func() { _ = rows.Close() }()
	worst := map[string]model.Priority{}
	for rows.Next() {
		var (
			k string
			p int
		)
		if err := rows.Scan(&k, &p); err != nil {
			return err
		}
		worst[k] = model.Priority(p)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range hits {
		if hits[i].Kind == kind {
			hits[i].Worst = worst[hits[i].ID]
		}
	}
	return nil
}

// ChangeMarks are opaque marks of the store's slowly changing kinds: equal marks mean no change of
// that kind. The live stream polls them.
type ChangeMarks struct{ Images, Feeds, Exceptions, Suggestions, Nodes string }

// ChangeMarks reads the current marks through the read-only pool; it never writes.
func (s *Store) ChangeMarks(ctx context.Context) (ChangeMarks, error) {
	var m ChangeMarks
	for _, x := range []struct {
		dst   *string
		hash  bool
		query string
	}{
		{&m.Images, false, `SELECT count(*), (SELECT group_concat(status || '=' || n) FROM (SELECT status, count(*) AS n FROM images
			GROUP BY status ORDER BY status)), sum(attempts), max(catalogued_at) FROM images`},
		{&m.Feeds, false, `SELECT max(last_attempt), max(last_success), (SELECT group_concat(last_error, char(31))
			FROM (SELECT last_error FROM feeds ORDER BY name)) FROM feeds`},
		{&m.Suggestions, false, `SELECT count(*), max(computed_at) FROM suggestions`},
		{&m.Exceptions, true, `SELECT group_concat(namespace || char(31) || name || char(31) || rule, char(30))
			FROM (SELECT namespace, name, rule FROM exceptions ORDER BY namespace, name)`},
		{&m.Nodes, true, `SELECT group_concat(name || char(31) || os || char(31) || arch || char(31) || os_image || char(31) ||
			kernel_version || char(31) || kubelet_version || char(31) || container_runtime_version || char(31) || ready, char(30))
			FROM (SELECT * FROM nodes ORDER BY name)`},
	} {
		rows, err := s.rdb.QueryContext(ctx, x.query)
		if err != nil {
			return ChangeMarks{}, fmt.Errorf("store: change marks: %w", err)
		}
		mark, err := markOf(rows, x.hash)
		if err != nil {
			return ChangeMarks{}, fmt.Errorf("store: change marks: %w", err)
		}
		*x.dst = mark
	}
	return m, nil
}

// markOf reads the single row of rows: fmt.Sprint of its values, or the first 16 hex digits of the
// sha256 of its one text value when hash is set.
func markOf(rows *sql.Rows, hash bool) (string, error) {
	defer func() { _ = rows.Close() }()
	cols, err := rows.Columns()
	if err != nil {
		return "", err
	}
	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	if rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return "", err
		}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	for i, v := range vals {
		if b, ok := v.([]byte); ok {
			vals[i] = string(b)
		}
	}
	if !hash {
		return fmt.Sprint(vals...), nil
	}
	sum := sha256.Sum256([]byte(fmt.Sprint(vals[0])))
	return hex.EncodeToString(sum[:])[:16], nil
}

// SBOMDescriptor returns the tool name and version from the "descriptor" object of digest's
// stored Syft JSON, reading tokens up to it without buffering the artefacts before it. ok is false
// for synthetic and node group digests, and when no SBOM or descriptor is stored.
func (s *Store) SBOMDescriptor(ctx context.Context, digest string) (name, version string, ok bool, err error) {
	if strings.HasPrefix(digest, "k8s:") || strings.HasPrefix(digest, "runtime:") || strings.HasPrefix(digest, nodeGroupDigestPrefix) {
		return "", "", false, nil
	}
	var zst []byte
	err = s.rdb.QueryRowContext(ctx, `SELECT syft_zst FROM sboms WHERE digest = ?`, digest).Scan(&zst)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, fmt.Errorf("store: sbom %s: %w", digest, err)
	}
	raw, err := zstdDecode(zst)
	if err != nil {
		return "", "", false, fmt.Errorf("store: sbom %s: %w", digest, err)
	}
	d, found, err := syftDescriptor(json.NewDecoder(bytes.NewReader(raw)))
	if err != nil {
		return "", "", false, fmt.Errorf("store: sbom %s descriptor: %w", digest, err)
	}
	return d.Name, d.Version, found, nil
}

// syftDescriptor walks the top-level object of a Syft document to its "descriptor" member,
// skipping every other member's value token by token.
func syftDescriptor(dec *json.Decoder) (struct{ Name, Version string }, bool, error) {
	var d struct{ Name, Version string }
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return d, false, errors.Join(errors.New("not a JSON object"), err)
	}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return d, false, err
		}
		if key, _ := t.(string); key == "descriptor" {
			if err := dec.Decode(&d); err != nil {
				return d, false, err
			}
			return d, true, nil
		}
		if err := skipValue(dec); err != nil {
			return d, false, err
		}
	}
	return d, false, nil
}

// skipValue reads one JSON value's tokens, counting delimiter depth.
func skipValue(dec *json.Decoder) error {
	depth := 0
	for {
		t, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return io.ErrUnexpectedEOF
			}
			return err
		}
		if d, ok := t.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
			default:
				depth--
			}
		}
		if depth == 0 {
			return nil
		}
	}
}

// OwnerExists reports whether an owner is stored under key.
func (s *Store) OwnerExists(ctx context.Context, key string) (bool, error) {
	var ok bool
	if err := s.rdb.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM owners WHERE key = ?)`, key).Scan(&ok); err != nil {
		return false, fmt.Errorf("store: owner %s: %w", key, err)
	}
	return ok, nil
}

// ImageGapTally is what a scope's image coverage gaps number, read without listing them: Codes
// counts the gap codes of its in-use container images other than cpe_only_classifier (one for an
// image not seen into, one per partial-coverage reason of a catalogued one), and Classified holds
// the classifier-found packages of its catalogued images, by digest, from which the caller counts
// the cpe_only_classifier gaps.
type ImageGapTally struct {
	Codes      int
	Classified map[string][]model.Package
}

// ImageGapTally tallies the image coverage gaps of a cluster, namespace or workload scope, as
// CoverageImages lists them, with an image whose first match has not run counted as pending.
func (s *Store) ImageGapTally(ctx context.Context, sc model.Scope) (ImageGapTally, error) {
	var w where
	w.add(containerDigest("oi.digest"))
	switch sc.Kind {
	case model.ScopeCluster, "":
	case model.ScopeNamespace:
		w.add(`o.namespace = ?`, sc.Value)
	case model.ScopeWorkload:
		w.add(`oi.owner_key = ?`, sc.Value)
	default:
		return ImageGapTally{}, scopeErr(sc)
	}
	inuse := `WITH inuse AS (SELECT DISTINCT oi.digest FROM owner_images oi JOIN owners o ON o.key = oi.owner_key` + w.String() + `)`
	t := ImageGapTally{Classified: map[string][]model.Package{}}
	err := s.rdb.QueryRowContext(ctx, inuse+` SELECT coalesce(sum(CASE WHEN i.digest IS NULL OR NOT `+seenSQL("i", "u.digest")+` THEN 1
		ELSE (i.source = 'attestation') + (i.cov_unattributed > 0) + (i.cov_rust > 0) END), 0)
		FROM inuse u LEFT JOIN images i ON i.digest = u.digest`, w.args...).Scan(&t.Codes)
	if err != nil {
		return ImageGapTally{}, fmt.Errorf("store: image gaps of %s: %w", sc, err)
	}
	pkgs, err := queryAll(ctx, s.rdb, scanPackage, inuse+` SELECT `+prefixedCols("p.", packageCols, "")+` FROM inuse u
		JOIN images i ON i.digest = u.digest CROSS JOIN packages p ON p.digest = u.digest
		WHERE p.classifier != '' AND `+seenSQL("i", "u.digest")+` ORDER BY p.digest, p.name, p.version, p.id`, w.args...)
	if err != nil {
		return ImageGapTally{}, fmt.Errorf("store: classified packages of %s: %w", sc, err)
	}
	for _, p := range pkgs {
		t.Classified[p.ImageDigest] = append(t.Classified[p.ImageDigest], p)
	}
	return t, nil
}
