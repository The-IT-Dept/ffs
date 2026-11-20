package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/the-it-dept/ffs/internal/model"
)

// ImageFilter selects images; empty fields match everything. Results are ordered by digest.
type ImageFilter struct {
	Statuses []model.ImageStatus
	Repo     string
	Limit    int // 0 = no limit
}

// EcosystemKey is a distinct (ecosystem, distro id, distro version) tuple present in stored packages.
type EcosystemKey struct{ Ecosystem, DistroID, DistroVersion string }

const imageCols = `digest, index_digest, repo, platform, status, status_reason, source, version_annotation,
	config_user, coverage, catalogued_at, attempts, quarantined_until`

// UpsertImage writes every column, except that an incoming pending status never overwrites a
// stored non-pending one: the stored status and catalogue fields are kept and only non-empty
// IndexDigest, Repo and Platform are updated.
func (s *Store) UpsertImage(ctx context.Context, img model.Image) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if img.Status == model.ImagePending {
			stored, ok, err := getImage(ctx, tx, img.Digest)
			if err != nil {
				return err
			}
			if ok && stored.Status != model.ImagePending {
				if img.IndexDigest != "" {
					stored.IndexDigest = img.IndexDigest
				}
				if img.Repo != "" {
					stored.Repo = img.Repo
				}
				if img.Platform != "" {
					stored.Platform = img.Platform
				}
				img = stored
			}
		}
		coverage, err := jsonText(img.Coverage)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT OR REPLACE INTO images(`+imageCols+`) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			img.Digest, img.IndexDigest, img.Repo, img.Platform, string(img.Status), img.StatusReason, img.Source,
			img.VersionAnnotation, img.ConfigUser, coverage, nanos(img.CataloguedAt), img.Attempts, nanos(img.QuarantinedUntil))
		return err
	})
}

// GetImage returns the image with the given platform-manifest digest.
func (s *Store) GetImage(ctx context.Context, digest string) (model.Image, bool, error) {
	return getImage(ctx, s.rdb, digest)
}

func getImage(ctx context.Context, q querier, digest string) (model.Image, bool, error) {
	img, err := scanImage(q.QueryRowContext(ctx, `SELECT `+imageCols+` FROM images WHERE digest = ?`, digest))
	if errors.Is(err, sql.ErrNoRows) {
		return model.Image{}, false, nil
	}
	return img, err == nil, err
}

// ListImages returns the images matching f, ordered by digest.
func (s *Store) ListImages(ctx context.Context, f ImageFilter) ([]model.Image, error) {
	var w where
	if len(f.Statuses) > 0 {
		statuses := make([]string, len(f.Statuses))
		for i, st := range f.Statuses {
			statuses[i] = string(st)
		}
		w.add(`status IN (SELECT value FROM json_each(?))`, idList(statuses))
	}
	if f.Repo != "" {
		w.add(`repo = ?`, f.Repo)
	}
	return queryAll(ctx, s.rdb, scanImage,
		`SELECT `+imageCols+` FROM images`+w.String()+` ORDER BY digest`+limitOffset(f.Limit, 0), w.args...)
}

// PruneImages tracks unused images and deletes those unused for longer than unusedFor, in one
// transaction. An image is unused when no owner runs it and no upgrade suggestion holds it as a
// candidate: a superseded rollout digest or a stale candidate. Each unused image is marked unused
// from now the first time PruneImages sees it so (UpsertImage clears the mark too), an image used
// again loses its mark, and an image marked before now-unusedFor is deleted with its packages, SBOM,
// matches, grype keys, acquisition records (images_unmatched, acquisitions_inflight) and node agent
// records (agent_sboms, agent_jobs), so a digest that comes back starts clean. Synthetic digests are
// kept. It returns the number of images deleted.
func (s *Store) PruneImages(ctx context.Context, now time.Time, unusedFor time.Duration) (int, error) {
	if now.IsZero() {
		return 0, errors.New("store: prune images without a time")
	}
	const unused = `digest NOT LIKE 'k8s:%' AND digest NOT LIKE 'runtime:%'
		AND NOT EXISTS (SELECT 1 FROM owner_images o WHERE o.digest = images.digest)
		AND NOT EXISTS (SELECT 1 FROM candidates c WHERE c.digest = images.digest)`
	var n int
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE images SET unused_since = NULL WHERE unused_since IS NOT NULL AND NOT (`+unused+`)`); err != nil {
			return fmt.Errorf("store: prune images: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE images SET unused_since = ? WHERE unused_since IS NULL AND `+unused,
			now.UTC().UnixNano()); err != nil {
			return fmt.Errorf("store: prune images: %w", err)
		}
		digests, err := queryAll(ctx, tx, scanString, `SELECT digest FROM images WHERE unused_since < ? AND `+unused,
			now.Add(-unusedFor).UTC().UnixNano())
		if err != nil || len(digests) == 0 {
			return err
		}
		list := idList(digests)
		for _, q := range []string{
			`DELETE FROM packages WHERE digest IN (SELECT value FROM json_each(?))`,
			`DELETE FROM sboms WHERE digest IN (SELECT value FROM json_each(?))`,
			`DELETE FROM matches WHERE digest IN (SELECT value FROM json_each(?))`,
			`DELETE FROM grype_keys WHERE digest IN (SELECT value FROM json_each(?))`,
			`DELETE FROM images_unmatched WHERE digest IN (SELECT value FROM json_each(?))`,
			`DELETE FROM acquisitions_inflight WHERE digest IN (SELECT value FROM json_each(?))`,
			`DELETE FROM agent_sboms WHERE digest IN (SELECT value FROM json_each(?))`,
			`DELETE FROM agent_jobs WHERE digest IN (SELECT value FROM json_each(?))`,
			`DELETE FROM images WHERE digest IN (SELECT value FROM json_each(?))`,
		} {
			if _, err := tx.ExecContext(ctx, q, list); err != nil {
				return fmt.Errorf("store: prune images: %w", err)
			}
		}
		n = len(digests)
		return nil
	})
	return n, err
}

// scanImage reads a row of the imageCols columns alone.
func scanImage(r scanner) (model.Image, error) {
	x := &imageScan{}
	if err := r.Scan(x.dest()...); err != nil {
		return model.Image{}, err
	}
	return x.image()
}

// imageScan is the scan destination of the imageCols columns, in their order. A reader that selects
// further columns after them appends their destinations to dest().
type imageScan struct {
	digest, index, repo, platform, status, reason, source, version, user, coverage string
	catalogued, quarantined                                                        sql.NullInt64
	attempts                                                                       int
}

func (x *imageScan) dest() []any {
	return []any{&x.digest, &x.index, &x.repo, &x.platform, &x.status, &x.reason, &x.source, &x.version, &x.user, &x.coverage,
		&x.catalogued, &x.attempts, &x.quarantined}
}

func (x *imageScan) image() (model.Image, error) {
	img := model.Image{Digest: x.digest, IndexDigest: x.index, Repo: x.repo, Platform: x.platform, Status: model.ImageStatus(x.status),
		StatusReason: x.reason, Source: x.source, VersionAnnotation: x.version, ConfigUser: x.user, CataloguedAt: fromNanos(x.catalogued),
		Attempts: x.attempts, QuarantinedUntil: fromNanos(x.quarantined)}
	if err := json.Unmarshal([]byte(x.coverage), &img.Coverage); err != nil {
		return model.Image{}, fmt.Errorf("image %s coverage: %w", x.digest, err)
	}
	return img, nil
}

const packageCols = `id, digest, ecosystem, distro_id, distro_version, distro_codename, name, version, epoch, arch,
	source_name, source_version, purl, cpes, path, layer, classifier, go_stdlib, syft_id`

// PutSBOM replaces every package of digest and stores the zstd-compressed syft JSON. Each package
// gets ImageDigest = digest, and ID = model.PackageID(digest, p) when ID is empty. A nil syftJSON
// (synthetic digests) deletes any stored SBOM.
func (s *Store) PutSBOM(ctx context.Context, digest string, syftJSON []byte, pkgs []model.Package) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		var err error
		if syftJSON == nil {
			_, err = tx.ExecContext(ctx, `DELETE FROM sboms WHERE digest = ?`, digest)
		} else {
			_, err = tx.ExecContext(ctx, `INSERT OR REPLACE INTO sboms(digest, syft_zst, raw_size) VALUES(?, ?, ?)`,
				digest, zstdEncode(syftJSON), len(syftJSON))
		}
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM packages WHERE digest = ?`, digest); err != nil {
			return err
		}
		ins, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO packages(`+packageCols+`) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
		if err != nil {
			return err
		}
		defer func() { _ = ins.Close() }()
		for _, p := range pkgs {
			p.ImageDigest = digest
			if p.ID == "" {
				p.ID = model.PackageID(digest, p)
			}
			var d model.Distro
			if p.Distro != nil {
				d = *p.Distro
			}
			// OR IGNORE: an identical package listed twice (same PackageID) is stored once.
			if _, err := ins.ExecContext(ctx, p.ID, p.ImageDigest, p.Ecosystem, d.ID, d.VersionID, d.Codename, p.Name, p.Version,
				p.Epoch, p.Arch, p.SourceName, p.SourceVersion, p.PURL, stringsText(p.CPEs), p.Path, p.Layer, p.Classifier,
				p.GoStdlib, p.SyftID); err != nil {
				return err
			}
		}
		return nil
	})
}

// GetSBOM returns the decompressed syft JSON for digest.
func (s *Store) GetSBOM(ctx context.Context, digest string) ([]byte, bool, error) {
	var zst []byte
	err := s.rdb.QueryRowContext(ctx, `SELECT syft_zst FROM sboms WHERE digest = ?`, digest).Scan(&zst)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	b, err := zstdDecode(zst)
	if err != nil {
		return nil, false, fmt.Errorf("store: sbom %s: %w", digest, err)
	}
	return b, true, nil
}

// PackagesForImage returns the packages stored for digest.
func (s *Store) PackagesForImage(ctx context.Context, digest string) ([]model.Package, error) {
	return queryAll(ctx, s.rdb, scanPackage,
		`SELECT `+packageCols+` FROM packages WHERE digest = ? ORDER BY name, version, id`, digest)
}

// PackagesByName is the inverted index. A nil distro matches any distro; otherwise distro id and
// version must match and the codename is ignored. With bySource it matches the source package
// name, treating an empty source name as equal to the binary name (dpkg omits Source then).
func (s *Store) PackagesByName(ctx context.Context, ecosystem string, distro *model.Distro, name string, bySource bool) ([]model.Package, error) {
	q, args := packagesByNameQuery(ecosystem, distro, []string{name}, bySource)
	return queryAll(ctx, s.rdb, scanPackage, q, args...)
}

// PackagesByNames is PackagesByName in any distro for several names at once: the packages that
// match any of them, each once.
func (s *Store) PackagesByNames(ctx context.Context, ecosystem string, names []string, bySource bool) ([]model.Package, error) {
	if len(names) == 0 {
		return nil, nil
	}
	q, args := packagesByNameQuery(ecosystem, nil, names, bySource)
	return queryAll(ctx, s.rdb, scanPackage, q, args...)
}

// packagesByNameQuery is the SQL of PackagesByNames. The source-name lookup is two indexed SELECTs
// joined by UNION ALL, not one OR: SQLite serves the OR form by reading every package of the
// ecosystem, which made the OSV fast path's lookups for a large record take seconds.
func packagesByNameQuery(ecosystem string, distro *model.Distro, names []string, bySource bool) (string, []any) {
	sel := func(cond string, args ...any) (string, []any) {
		var w where
		w.add(`ecosystem = ?`, ecosystem)
		if distro != nil {
			w.add(`distro_id = ? AND distro_version = ?`, distro.ID, distro.VersionID)
		}
		w.add(cond, args...)
		return `SELECT ` + packageCols + ` FROM packages` + w.String(), w.args
	}
	const order = ` ORDER BY digest, name, version, id`
	if !bySource {
		q, args := sel(`name IN (SELECT value FROM json_each(?))`, idList(names))
		return q + order, args
	}
	q, args := sel(`source_name IN (SELECT value FROM json_each(?))`, idList(names))
	// An empty name already has the first SELECT return every package with an empty source name.
	if !slices.Contains(names, "") {
		q2, args2 := sel(`source_name = '' AND name IN (SELECT value FROM json_each(?))`, idList(names))
		q, args = q+` UNION ALL `+q2, append(args, args2...)
	}
	return q + order, args
}

// foldedEcosystems are the package ecosystems whose packages have a folded name.
var foldedEcosystems = map[string]bool{"python": true, "java-archive": true}

// PackagesByFoldedName returns the stored packages of ecosystem, in any distro, whose folded name
// equals the folded name. Folding lowercases a name, reads '_' and '.' as '-' and collapses runs of
// '-': PEP 503 normalisation, the way PyPI compares names, so a record for "jinja2" finds a stored
// "Jinja2". Only python and java-archive packages have folded names; other ecosystems are an error.
func (s *Store) PackagesByFoldedName(ctx context.Context, ecosystem, name string) ([]model.Package, error) {
	return s.PackagesByFoldedNames(ctx, ecosystem, []string{name})
}

// PackagesByFoldedNames is PackagesByFoldedName for several names at once: the packages whose
// folded name equals the folded form of any of them, each once.
func (s *Store) PackagesByFoldedNames(ctx context.Context, ecosystem string, names []string) ([]model.Package, error) {
	if !foldedEcosystems[ecosystem] {
		return nil, fmt.Errorf("store: %q packages have no folded names", ecosystem)
	}
	if len(names) == 0 {
		return nil, nil
	}
	folded := make([]string, len(names))
	for i, n := range names {
		folded[i] = foldName(n)
	}
	return queryAll(ctx, s.rdb, scanPackage, `SELECT `+packageCols+` FROM packages
		WHERE ecosystem = ? AND folded_name IN (SELECT value FROM json_each(?)) ORDER BY digest, name, version, id`,
		ecosystem, idList(folded))
}

// foldName computes the folded_name column of 010_package_folded_names.sql for name: '_' and '.'
// become '-', runs of '-' are halved five times (so runs of up to 32 collapse to one) and ASCII
// letters are lowercased, as SQLite's replace and lower do.
func foldName(name string) string {
	s := strings.NewReplacer("_", "-", ".", "-").Replace(name)
	for range 5 {
		s = strings.ReplaceAll(s, "--", "-")
	}
	return strings.Map(func(r rune) rune {
		if 'A' <= r && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, s)
}

// EcosystemsInUse returns the sorted distinct (ecosystem, distro id, distro version) tuples over
// every stored package, upgrade candidates included.
func (s *Store) EcosystemsInUse(ctx context.Context) ([]EcosystemKey, error) {
	return queryAll(ctx, s.rdb, func(r scanner) (EcosystemKey, error) {
		var k EcosystemKey
		err := r.Scan(&k.Ecosystem, &k.DistroID, &k.DistroVersion)
		return k, err
	}, `SELECT DISTINCT ecosystem, distro_id, distro_version FROM packages ORDER BY 1, 2, 3`)
}

// scanPackage reads a row of the packageCols columns alone.
func scanPackage(r scanner) (model.Package, error) {
	x := &packageScan{}
	if err := r.Scan(x.dest()...); err != nil {
		return model.Package{}, err
	}
	return x.pkg()
}

// packageScan is the scan destination of the packageCols columns, in their order. A reader that
// selects further columns after them appends their destinations to dest().
type packageScan struct {
	p    model.Package
	d    model.Distro
	cpes string
}

func (x *packageScan) dest() []any {
	p := &x.p
	return []any{&p.ID, &p.ImageDigest, &p.Ecosystem, &x.d.ID, &x.d.VersionID, &x.d.Codename, &p.Name, &p.Version, &p.Epoch,
		&p.Arch, &p.SourceName, &p.SourceVersion, &p.PURL, &x.cpes, &p.Path, &p.Layer, &p.Classifier, &p.GoStdlib, &p.SyftID}
}

func (x *packageScan) pkg() (model.Package, error) {
	p := x.p
	if x.d != (model.Distro{}) {
		d := x.d
		p.Distro = &d
	}
	var err error
	if p.CPEs, err = textStrings(x.cpes); err != nil {
		return model.Package{}, fmt.Errorf("package %s cpes: %w", p.ID, err)
	}
	return p, nil
}

// PutTagDigest records that repo:tag resolved to digest at the given time.
func (s *Store) PutTagDigest(ctx context.Context, repo, tag, digest string, at time.Time) error {
	_, err := s.wdb.ExecContext(ctx, `INSERT OR REPLACE INTO image_tags(repo, tag, digest, resolved_at) VALUES(?, ?, ?, ?)`,
		repo, tag, digest, nanos(orNow(at)))
	return err
}

// TagDigest returns the last recorded resolution of repo:tag.
func (s *Store) TagDigest(ctx context.Context, repo, tag string) (string, time.Time, bool, error) {
	var (
		digest string
		at     sql.NullInt64
	)
	err := s.rdb.QueryRowContext(ctx, `SELECT digest, resolved_at FROM image_tags WHERE repo = ? AND tag = ?`, repo, tag).Scan(&digest, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return "", time.Time{}, false, nil
	}
	if err != nil {
		return "", time.Time{}, false, err
	}
	return digest, fromNanos(at), true, nil
}
