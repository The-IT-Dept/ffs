package engine_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/linux"
	syftpkg "github.com/anchore/syft/syft/pkg"
	syftsbom "github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/engine"
	"github.com/the-it-dept/ffs/internal/feeds/grypedb"
	"github.com/the-it-dept/ffs/internal/feeds/grypedb/grypedbtest"
	"github.com/the-it-dept/ffs/internal/feeds/osv"
	"github.com/the-it-dept/ffs/internal/match"
	"github.com/the-it-dept/ffs/internal/match/grype"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/sbom"
	"github.com/the-it-dept/ffs/internal/store"
)

// firefoxCVE is in the debian 12 fixture DB: firefox-esr fixed in 140.5.0esr-1~deb12u1.
const firefoxCVE = "CVE-2025-13012"

var dbBuilt = time.Date(2026, 11, 18, 13, 44, 25, 0, time.UTC)

// debianImage stores a catalogued debian 12 image holding firefox-esr at version, run by a
// Deployment of its own, and returns its package.
func debianImage(t *testing.T, st *store.Store, digest, name, version string) model.Package {
	t.Helper()
	p := syftpkg.Package{Name: "firefox-esr", Version: version, Type: syftpkg.DebPkg,
		Locations: file.NewLocationSet(file.NewLocation("/var/lib/dpkg/status")),
		Metadata:  syftpkg.DpkgDBEntry{Package: "firefox-esr", Version: version, Architecture: "amd64"}}
	p.SetID()
	doc := syftsbom.SBOM{
		Artifacts:  syftsbom.Artifacts{Packages: syftpkg.NewCollection(p), LinuxDistribution: &linux.Release{ID: "debian", VersionID: "12"}},
		Source:     source.Description{ID: "src", Name: name, Metadata: source.ImageMetadata{UserInput: name}},
		Descriptor: syftsbom.Descriptor{Name: "syft", Version: "1.57.2"},
	}
	raw, err := format.Encode(doc, syftjson.NewFormatEncoder())
	require.NoError(t, err)
	decoded, err := sbom.DecodeSyftJSON(raw)
	require.NoError(t, err)
	pkgs, _ := sbom.Normalize(digest, decoded)
	require.Len(t, pkgs, 1)
	storeImage(t, st, digest, name, raw, pkgs)
	return pkgs[0]
}

// storeImage stores digest as a catalogued image with sbom and pkgs, run by Deployment apps/name.
func storeImage(t *testing.T, st *store.Store, digest, name string, sbomJSON []byte, pkgs []model.Package) {
	t.Helper()
	repo := "registry.example.com/apps/" + name
	require.NoError(t, st.PutSBOM(ctx, digest, sbomJSON, pkgs))
	require.NoError(t, st.UpsertImage(ctx, model.Image{Digest: digest, Repo: repo, Platform: "linux/amd64",
		Status: model.ImageCatalogued, CataloguedAt: dbBuilt}))
	require.NoError(t, st.UpsertOwner(ctx, model.Owner{Ref: model.OwnerRef{Kind: "Deployment", Namespace: "apps", Name: name},
		Containers: []model.ContainerUse{{Name: name, Kind: model.ContainerRegular, Repo: repo, Digest: digest}}}))
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "ffs.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	return st
}

func storedMatches(t *testing.T, st *store.Store, digest string, src model.MatchSource) []model.Match {
	t.Helper()
	ms, err := st.MatchesForDigests(ctx, []string{digest})
	require.NoError(t, err)
	var out []model.Match
	for _, m := range ms {
		if m.Source == src {
			out = append(out, m)
		}
	}
	return out
}

// TestEngine_GrypeDBSkipsFailingDigest is the F23 regression: one digest whose stored SBOM grype
// cannot read no longer aborts the re-match of every other digest, and the build is recorded only
// after the re-match, never when it failed everywhere.
func TestEngine_GrypeDBSkipsFailingDigest(t *testing.T) {
	st := openStore(t)
	const good, bad = "sha256:good", "sha256:bad"
	debianImage(t, st, good, "web", "140.4.0esr-1~deb12u1")
	storeImage(t, st, bad, "broken", []byte("{not a syft document"), []model.Package{{ImageDigest: bad, ID: "bad-pkg",
		Ecosystem: "deb", Name: "firefox-esr", Version: "140.4.0esr-1~deb12u1"}})
	e := engine.New(engine.Options{Config: config.Default(), Store: st, Grype: grype.New(st),
		Now: func() time.Time { return dbBuilt.Add(time.Hour) }})

	require.NoError(t, e.OnGrypeDB(ctx, grypedb.Update{Path: grypedbtest.BuildDB(t, dbBuilt, "**/debian-12/*.json"),
		Built: dbBuilt, Full: true}))
	got := storedMatches(t, st, good, model.SourceGrype)
	require.Len(t, got, 1, "the readable image is re-matched despite the broken one")
	require.Equal(t, firefoxCVE, got[0].AdvisoryID)
	builds, err := st.GrypeDBBuilds(ctx)
	require.NoError(t, err)
	require.Equal(t, []time.Time{dbBuilt}, builds)

	// when every image fails the build is not counted, so the feed offers it again
	require.NoError(t, st.DeleteOwner(ctx, "Deployment/apps/web"))
	next := dbBuilt.Add(24 * time.Hour)
	require.Error(t, e.OnGrypeDB(ctx, grypedb.Update{Path: grypedbtest.BuildDB(t, next, "**/debian-12/*.json"),
		Built: next, Full: true}))
	builds, err = st.GrypeDBBuilds(ctx)
	require.NoError(t, err)
	require.Equal(t, []time.Time{dbBuilt}, builds)
}

// TestEngine_GrypeDBRematchesOSVRuledDigests is the F24 regression. grype matched the image with DB
// one before the OSV fast path saw the advisory, so it had no hint to form its not-affected opinion
// from. DB two does not change firefox-esr, yet it must re-match the image so that its opinion forms.
func TestEngine_GrypeDBRematchesOSVRuledDigests(t *testing.T) {
	st := openStore(t)
	const d = "sha256:fixed"
	pkg := debianImage(t, st, d, "web", "140.5.0esr-1~deb12u1")
	now := dbBuilt
	e := engine.New(engine.Options{Config: config.Default(), Store: st, Grype: grype.New(st), Now: func() time.Time { return now }})
	require.NoError(t, e.OnGrypeDB(ctx, grypedb.Update{Path: grypedbtest.BuildDB(t, dbBuilt, "**/debian-12/*.json"),
		Built: dbBuilt, Full: true}))
	require.Empty(t, storedMatches(t, st, d, model.SourceGrype), "the fixed version has no grype match")

	// an hour later the OSV fast path matches the package with a less precise range
	now = dbBuilt.Add(time.Hour)
	require.NoError(t, e.OnMatchDelta(ctx, match.Delta{
		Scope: store.MatchScope{Source: model.SourceOSV, AdvisoryIDs: []string{firefoxCVE}},
		Matches: []model.Match{{ImageDigest: d, PackageID: pkg.ID, AdvisoryID: firefoxCVE, Source: model.SourceOSV,
			FixState: model.FixNotFixed, ObservedAt: now}},
	}, model.TriggerNewAdvisory))

	next := dbBuilt.Add(24 * time.Hour)
	now = next.Add(time.Hour)
	require.NoError(t, e.OnGrypeDB(ctx, grypedb.Update{Path: grypedbtest.BuildDB(t, next, "**/debian-12/*.json"),
		Built: next, Changed: []grypedb.PackageKey{{Ecosystem: "deb", Name: "unrelated"}}}))
	got := storedMatches(t, st, d, model.SourceGrype)
	require.Len(t, got, 1, "grype re-matched the OSV-ruled image with the new DB")
	require.Equal(t, model.FixNotAffected, got[0].FixState)
	require.Equal(t, next, got[0].DBBuilt)
}

// blockingRecords is a record matcher that evaluates its delta from the matches stored when it is
// called, then waits for release before returning it.
type blockingRecords struct {
	st        *store.Store
	adv       string
	evaluated chan struct{}
	release   chan struct{}
}

func (b *blockingRecords) ApplyOSV(ctx context.Context, _ []osv.Changed) ([]match.Delta, error) {
	ms, err := b.st.MatchesForDigests(ctx, []string{d1})
	if err != nil {
		return nil, err
	}
	close(b.evaluated)
	<-b.release
	return []match.Delta{{Scope: store.MatchScope{Source: model.SourceOSV, AdvisoryIDs: []string{b.adv}}, Matches: ms}}, nil
}

// TestEngine_MatchWritesSerialised is the F22 regression: an image catalogued while an OSV delta is
// being evaluated keeps its OSV match. The delta was computed before the image's packages existed;
// written after the image's matches, it would replace the advisory's matches without them.
func TestEngine_MatchWritesSerialised(t *testing.T) {
	h := newHarness(t)
	h.osv.fn = matchOn(nil, d1, newMatch(h.libssl3, cve, model.SourceOSV, "3.0.15-1"))
	require.NoError(t, h.e.OnImageCatalogued(ctx, d1))

	const d3 = "sha256:d3"
	p3 := h.libssl3
	p3.ImageDigest = d3
	p3.ID = model.PackageID(d3, p3)
	require.NoError(t, h.st.PutSBOM(ctx, d3, []byte(`{"artifacts":[]}`), []model.Package{p3}))
	require.NoError(t, h.st.UpsertImage(ctx, model.Image{Digest: d3, Repo: apiRepo, Status: model.ImageCatalogued, CataloguedAt: t0}))
	h.osv.fn = matchOn(h.osv.fn, d3, newMatch(p3, cve, model.SourceOSV, "3.0.15-1"))

	rec := &blockingRecords{st: h.st.Store, adv: cve, evaluated: make(chan struct{}), release: make(chan struct{})}
	e := engine.New(engine.Options{Config: config.Default(), Store: h.st, Grype: h.grype,
		Matchers: []match.Matcher{h.osv}, Records: []match.RecordMatcher{rec}, Now: h.clock.Now})
	deltaDone := make(chan error, 1)
	go func() { deltaDone <- e.OnOSVRecords(ctx, []osv.Changed{{Ecosystem: "Debian", ID: "DEBIAN-" + cve}}) }()
	<-rec.evaluated

	catDone := make(chan error, 1)
	go func() { catDone <- e.OnImageCatalogued(ctx, d3) }()
	select {
	case err := <-catDone: // unserialised: the image's matches land before the stale delta
		catDone <- err
	case <-time.After(300 * time.Millisecond): // serialised: it waits for the delta
	}
	close(rec.release)
	require.NoError(t, <-deltaDone)
	require.NoError(t, <-catDone)
	require.Len(t, storedMatches(t, h.st.Store, d3, model.SourceOSV), 1, "the new image's OSV match survives the delta")
}
