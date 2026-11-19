package grype

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	grypematch "github.com/anchore/grype/grype/match"
	grypepkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/linux"
	syftpkg "github.com/anchore/syft/syft/pkg"
	syftsbom "github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/feeds/grypedb"
	"github.com/the-it-dept/ffs/internal/feeds/grypedb/grypedbtest"
	"github.com/the-it-dept/ffs/internal/match"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/sbom"
	"github.com/the-it-dept/ffs/internal/store"
)

var (
	ctx   = context.Background()
	built = time.Date(2026, 11, 18, 13, 44, 25, 0, time.UTC)
	d0    = "sha256:" + strings.Repeat("0", 64)
	d1    = "sha256:" + strings.Repeat("1", 64)
	d2    = "sha256:" + strings.Repeat("2", 64)
)

const cve = "CVE-2025-13012" // firefox-esr in debian 12, fixed in 140.5.0esr-1~deb12u1

func newStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "ffs.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	return st
}

// loaded returns a matcher over a fresh store with the debian 12 fixture DB loaded.
func loaded(t *testing.T) (*Matcher, *store.Store) {
	t.Helper()
	st := newStore(t)
	m := New(st)
	require.NoError(t, m.Load(grypedbtest.BuildDB(t, built, "**/debian-12/*.json"), built))
	return m, st
}

type deb struct{ name, version, source string }

// debImage builds a debian 12 image SBOM holding debs, as stored syft-json, and its ffs packages.
func debImage(t *testing.T, digest string, debs ...deb) ([]byte, []model.Package) {
	t.Helper()
	pkgs := make([]syftpkg.Package, len(debs))
	for i, d := range debs {
		pkgs[i] = syftpkg.Package{Name: d.name, Version: d.version, Type: syftpkg.DebPkg,
			Locations: file.NewLocationSet(file.NewLocation("/var/lib/dpkg/status")),
			Metadata:  syftpkg.DpkgDBEntry{Package: d.name, Source: d.source, Version: d.version, Architecture: "amd64"}}
		pkgs[i].SetID()
	}
	doc := syftsbom.SBOM{
		Artifacts: syftsbom.Artifacts{
			Packages:          syftpkg.NewCollection(pkgs...),
			LinuxDistribution: &linux.Release{ID: "debian", VersionID: "12"},
		},
		Source:     source.Description{ID: "src", Name: "app", Metadata: source.ImageMetadata{UserInput: "app"}},
		Descriptor: syftsbom.Descriptor{Name: "syft", Version: "1.57.2"},
	}
	b, err := format.Encode(doc, syftjson.NewFormatEncoder())
	require.NoError(t, err)
	decoded, err := sbom.DecodeSyftJSON(b)
	require.NoError(t, err)
	out, _ := sbom.Normalize(digest, decoded)
	require.Len(t, out, len(debs))
	return b, out
}

func TestMatcherConfig_MirrorsCLIDefaults(t *testing.T) {
	cfg := matcherConfig()
	require.True(t, cfg.Stock.UseCPEs)
	for name, useCPEs := range map[string]bool{
		"java": cfg.Java.UseCPEs, "python": cfg.Python.UseCPEs, "javascript": cfg.Javascript.UseCPEs,
		"ruby": cfg.Ruby.UseCPEs, "dotnet": cfg.Dotnet.UseCPEs, "rust": cfg.Rust.UseCPEs, "hex": cfg.Hex.UseCPEs,
		"golang": cfg.Golang.UseCPEs, "dpkg": cfg.Dpkg.UseCPEs, "rpm": cfg.Rpm.UseCPEs,
	} {
		require.False(t, useCPEs, name)
	}
	require.False(t, cfg.Golang.AlwaysUseCPEForStdlib)
	require.False(t, cfg.Java.SearchMavenUpstream)
	require.Equal(t, version.MissingEpochStrategy("zero"), cfg.Dpkg.MissingEpochStrategy)
	require.Equal(t, version.MissingEpochStrategy("auto"), cfg.Rpm.MissingEpochStrategy)
	require.Len(t, ignoreRules(), 4)

	vm := newVulnerabilityMatcher(nil)
	require.True(t, vm.NormalizeByCVE && vm.IncludeMatcherSuppressions)
	require.Nil(t, vm.FailSeverity)
	require.Nil(t, vm.VexProcessor)
	require.Nil(t, vm.ExclusionProvider)

	pc := providerConfig()
	require.False(t, pc.GenerateMissingCPEs)
	require.Len(t, pc.Distro.FixChannels, 2)

	searches := cpeSearchTypes()
	require.True(t, searches(syftpkg.BinaryPkg))
	require.True(t, searches(syftpkg.ApkPkg))
	require.False(t, searches(syftpkg.DebPkg))
	require.False(t, searches(syftpkg.PythonPkg))
}

func TestGrypeMatcher_DebianFixedMatch(t *testing.T) {
	m, st := loaded(t)
	sj, pkgs := debImage(t, d1, deb{"firefox-esr", "140.4.0esr-1~deb12u1", ""})
	got, err := m.MatchImage(ctx, match.ImageInput{Digest: d1, SyftJSON: sj, Packages: pkgs})
	require.NoError(t, err)
	require.Equal(t, []model.Match{{
		ImageDigest: d1, PackageID: pkgs[0].ID, AdvisoryID: cve, Source: model.SourceGrype,
		FixState: model.FixFixed, FixedVersions: []string{"140.5.0esr-1~deb12u1"},
		VendorSeverity: model.SeverityUnknown, VendorSeveritySource: "debian",
		Namespace: "debian:distro:debian:12", DBBuilt: built,
	}}, got)

	_, ok, err := st.GetAdvisory(ctx, cve)
	require.NoError(t, err)
	require.True(t, ok)
	digests, err := st.DigestsForGrypeKeys(ctx, []string{"firefox-esr"}, nil)
	require.NoError(t, err)
	require.Equal(t, []string{d1}, digests)
}

func TestGrypeMatcher_OpinionNotAffected(t *testing.T) {
	m, _ := loaded(t)
	sj, pkgs := debImage(t, d1, deb{"firefox-esr", "140.5.0esr-1~deb12u1", ""})
	hints := []model.Match{{ImageDigest: d1, PackageID: pkgs[0].ID, AdvisoryID: cve, Source: model.SourceOSV, FixState: model.FixFixed}}
	got, err := m.MatchImage(ctx, match.ImageInput{Digest: d1, SyftJSON: sj, Packages: pkgs, Hints: hints})
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, model.SourceGrype, got[0].Source)
	require.Equal(t, model.FixNotAffected, got[0].FixState)
	require.Equal(t, cve, got[0].AdvisoryID)
	require.Equal(t, pkgs[0].ID, got[0].PackageID)
	require.Equal(t, "debian:distro:debian:12", got[0].Namespace)
	require.Equal(t, built, got[0].DBBuilt)

	// a hint from another source is not an OSV observation
	hints[0].Source = model.SourceUpstream
	got, err = m.MatchImage(ctx, match.ImageInput{Digest: d1, SyftJSON: sj, Packages: pkgs, Hints: hints})
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestGrypeMatcher_NoOpinionWithoutRecord(t *testing.T) {
	m, _ := loaded(t)
	sj, pkgs := debImage(t, d1, deb{"firefox-esr", "140.5.0esr-1~deb12u1", ""})
	hints := []model.Match{{ImageDigest: d1, PackageID: pkgs[0].ID, AdvisoryID: "CVE-2099-0001", Source: model.SourceOSV}}
	got, err := m.MatchImage(ctx, match.ImageInput{Digest: d1, SyftJSON: sj, Packages: pkgs, Hints: hints})
	require.NoError(t, err)
	require.Empty(t, got)

	has, err := m.HasRecord(ctx, pkgs[0], []string{"CVE-2099-0001"})
	require.NoError(t, err)
	require.False(t, has)
	has, err = m.HasRecord(ctx, pkgs[0], []string{"CVE-2099-0001", cve})
	require.NoError(t, err)
	require.True(t, has)
}

func TestToModel_DropsGoStdlib(t *testing.T) {
	v := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{ID: "CVE-2024-24790", Namespace: "nvd:cpe"},
		Fix:       vulnerability.Fix{State: vulnerability.FixStateFixed, Versions: []string{"1.22.4"}},
	}
	goPkg := func(name string) (grypepkg.Package, model.Package) {
		gp := grypepkg.Package{ID: grypepkg.ID("syft-" + name), Name: name, Version: "v1.22.3", Type: syftpkg.GoModulePkg}
		return gp, model.Package{ID: "pkg-" + name, SyftID: string(gp.ID), Ecosystem: "go-module", Name: name, Version: "v1.22.3",
			GoStdlib: name == "stdlib"}
	}
	stdlib, stdlibPkg := goPkg("stdlib")
	r := toModel(d1, []model.Package{stdlibPkg}, built,
		[]grypematch.Match{{Vulnerability: v, Package: stdlib}},
		[]grypematch.IgnoredMatch{{Match: grypematch.Match{Vulnerability: v, Package: stdlib},
			AppliedIgnoreRules: []grypematch.IgnoreRule{{Vulnerability: v.ID, Reason: "explicit"}}}})
	require.Empty(t, r.list())
	require.Empty(t, r.advisoryList())

	// any other Go module is converted
	module, modulePkg := goPkg("golang.org/x/net")
	r = toModel(d1, []model.Package{modulePkg}, built, []grypematch.Match{{Vulnerability: v, Package: module}}, nil)
	require.Equal(t, []model.Match{{ImageDigest: d1, PackageID: modulePkg.ID, AdvisoryID: v.ID, Source: model.SourceGrype,
		FixState: model.FixFixed, FixedVersions: []string{"1.22.4"}, VendorSeveritySource: "nvd", Namespace: "nvd:cpe", DBBuilt: built}}, r.list())
}

func TestToModel_SuppressionsBecomeNotAffected(t *testing.T) {
	owner := &grypepkg.Package{ID: "owner", Name: "python3.11", Type: syftpkg.DebPkg}
	gp := grypepkg.Package{ID: "binary", Name: "python", Version: "3.11.2", Type: syftpkg.BinaryPkg,
		RelatedPackages: map[artifact.RelationshipType][]*grypepkg.Package{artifact.OwnershipByFileOverlapRelationship: {owner}}}
	p := model.Package{ID: "pkg-python", SyftID: "binary", Ecosystem: "binary", Name: "python", Version: "3.11.2"}
	v := vulnerability.Vulnerability{
		Reference: vulnerability.Reference{ID: "CVE-2025-0001", Namespace: "nvd:cpe"},
		Fix:       vulnerability.Fix{State: vulnerability.FixStateFixed, Versions: []string{"3.11.9"}},
	}
	gm := grypematch.Match{Vulnerability: v, Package: gp}
	related := grypematch.IgnoreRelatedPackage{Reason: "DistroPackageFixed", RelationshipType: artifact.OwnershipByFileOverlapRelationship,
		VulnerabilityID: v.ID, RelatedPackageID: owner.ID}
	rules := related.IgnoreMatch(gm)
	require.NotEmpty(t, rules)

	r := toModel(d1, []model.Package{p}, built, nil, []grypematch.IgnoredMatch{{Match: gm, AppliedIgnoreRules: rules}})
	got := r.list()
	require.Len(t, got, 1)
	require.Equal(t, model.FixNotAffected, got[0].FixState)
	require.Equal(t, model.SourceGrype, got[0].Source)
	require.Equal(t, v.ID, got[0].AdvisoryID)
	require.Equal(t, p.ID, got[0].PackageID)

	// a match ignored by a kernel-header rule is dropped, not recorded as not affected
	header := grypepkg.Package{ID: "header", Name: "linux-libc-dev", Version: "6.1.0", Type: syftpkg.DebPkg,
		Upstreams: []grypepkg.UpstreamPackage{{Name: "linux"}}}
	headerPkg := model.Package{ID: "pkg-header", SyftID: "header", Ecosystem: "deb", Name: "linux-libc-dev", Version: "6.1.0", SourceName: "linux"}
	r = toModel(d1, []model.Package{headerPkg}, built, nil, []grypematch.IgnoredMatch{{
		Match:              grypematch.Match{Vulnerability: v, Package: header},
		AppliedIgnoreRules: []grypematch.IgnoreRule{ignoreRules()[2]},
	}})
	require.Empty(t, r.list())
}

func TestGrypeMatcher_NotReadyAndSynthetic(t *testing.T) {
	st := newStore(t)
	m := New(st)
	const k8s = "k8s:1.35.2"
	sj, pkgs := debImage(t, d0, deb{"firefox-esr", "140.4.0esr-1~deb12u1", ""})
	require.NoError(t, st.PutSBOM(ctx, d0, sj, pkgs))
	require.NoError(t, st.UpsertOwner(ctx, model.Owner{Ref: model.OwnerRef{Kind: "Deployment", Namespace: "web", Name: "app"},
		Containers: []model.ContainerUse{{Name: "app", Kind: model.ContainerRegular, Digest: d0}}}))
	require.NoError(t, st.PutSBOM(ctx, k8s, nil, []model.Package{{Ecosystem: "kubernetes", Name: "kubernetes", Version: "1.35.2"}}))
	require.NoError(t, st.UpsertOwner(ctx, model.Owner{Ref: model.OwnerRef{Kind: "Cluster", Name: "default"},
		Containers: []model.ContainerUse{{Name: "control plane", Digest: k8s}}}))

	_, err := m.MatchImage(ctx, match.ImageInput{Digest: d0, SyftJSON: sj, Packages: pkgs})
	require.ErrorIs(t, err, match.ErrNotReady)
	_, err = m.Rematch(ctx, []grypedb.PackageKey{{Ecosystem: "deb", Name: "firefox-esr"}})
	require.ErrorIs(t, err, match.ErrNotReady)
	_, err = m.RematchAll(ctx)
	require.ErrorIs(t, err, match.ErrNotReady)
	_, err = m.HasRecord(ctx, pkgs[0], []string{cve})
	require.ErrorIs(t, err, match.ErrNotReady)
	require.True(t, m.Built().IsZero())

	synthetic, err := m.MatchImage(ctx, match.ImageInput{Digest: k8s, Packages: []model.Package{{Ecosystem: "kubernetes", Name: "kubernetes"}}})
	require.NoError(t, err)
	require.Nil(t, synthetic)

	require.NoError(t, m.Load(grypedbtest.BuildDB(t, built, "**/debian-12/*.json"), built))
	require.Equal(t, built, m.Built())
	delta, err := m.RematchAll(ctx)
	require.NoError(t, err)
	require.Equal(t, store.MatchScope{Source: model.SourceGrype, Digests: []string{d0}}, delta.Scope)
	require.Len(t, delta.Matches, 1)
	require.Equal(t, cve, delta.Matches[0].AdvisoryID)
	keyed, err := st.GrypeDigests(ctx)
	require.NoError(t, err)
	require.Equal(t, []string{d0}, keyed)
}

func TestGrypeMatcher_RematchSelectsAffectedDigests(t *testing.T) {
	m, st := loaded(t)
	sj1, pkgs1 := debImage(t, d1, deb{"firefox-esr", "140.5.0esr-1~deb12u1", ""})
	sj2, pkgs2 := debImage(t, d2, deb{"bind9", "1:9.18.0-1", ""})
	for _, img := range []struct {
		digest string
		sj     []byte
		pkgs   []model.Package
	}{{d1, sj1, pkgs1}, {d2, sj2, pkgs2}} {
		require.NoError(t, st.PutSBOM(ctx, img.digest, img.sj, img.pkgs))
		_, err := m.MatchImage(ctx, match.ImageInput{Digest: img.digest, SyftJSON: img.sj, Packages: img.pkgs})
		require.NoError(t, err)
	}
	// the OSV fast path matched d1; the re-match passes that on as a hint
	_, err := st.ReplaceMatches(ctx, store.MatchScope{Source: model.SourceOSV, Digests: []string{d1}}, []model.Match{
		{ImageDigest: d1, PackageID: pkgs1[0].ID, AdvisoryID: cve, Source: model.SourceOSV, FixState: model.FixFixed}})
	require.NoError(t, err)

	delta, err := m.Rematch(ctx, []grypedb.PackageKey{{Ecosystem: "deb", Name: "firefox-esr"}})
	require.NoError(t, err)
	require.Equal(t, store.MatchScope{Source: model.SourceGrype, Digests: []string{d1}}, delta.Scope)
	require.Len(t, delta.Matches, 1)
	require.Equal(t, model.FixNotAffected, delta.Matches[0].FixState)
	require.Equal(t, d1, delta.Matches[0].ImageDigest)

	delta, err = m.Rematch(ctx, []grypedb.PackageKey{{Ecosystem: "cpe", Name: "firefox-esr"}})
	require.NoError(t, err)
	require.Empty(t, delta.Scope.Digests, "a deb package is not searched by CPE")
}
