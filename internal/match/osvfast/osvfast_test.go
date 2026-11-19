package osvfast_test

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/semantic"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/feeds/osv"
	"github.com/the-it-dept/ffs/internal/match"
	"github.com/the-it-dept/ffs/internal/match/osvfast"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

var (
	ctx = context.Background()

	dDeb    = "sha256:" + strings.Repeat("d", 64)
	dDeb2   = "sha256:" + strings.Repeat("e", 64)
	dUbuntu = "sha256:" + strings.Repeat("u", 64)
	dAlpine = "sha256:" + strings.Repeat("a", 64)
	dPy     = "sha256:" + strings.Repeat("p", 64)
	dGo     = "sha256:" + strings.Repeat("6", 64)
	dGo2    = "sha256:" + strings.Repeat("7", 64)
	dNode   = "sha256:" + strings.Repeat("n", 64)
	dAlma   = "sha256:" + strings.Repeat("9", 64)
	dAlma2  = "sha256:" + strings.Repeat("8", 64)

	debian12   = &model.Distro{ID: "debian", VersionID: "12", Codename: "bookworm"}
	ubuntu2404 = &model.Distro{ID: "ubuntu", VersionID: "24.04", Codename: "noble"}
	alpine320  = &model.Distro{ID: "alpine", VersionID: "3.20.3"}
	alma9      = &model.Distro{ID: "almalinux", VersionID: "9.4"}

	libssl3 = model.Package{Ecosystem: "deb", Distro: debian12, Name: "libssl3", Version: "3.0.11-1~deb12u2",
		SourceName: "openssl", SourceVersion: "3.0.11-1~deb12u2", Arch: "amd64"}
	libssl3t64 = model.Package{Ecosystem: "deb", Distro: ubuntu2404, Name: "libssl3t64", Version: "3.0.13-0ubuntu3.1",
		SourceName: "openssl", SourceVersion: "3.0.13-0ubuntu3.1", Arch: "amd64"}
	libcrypto3 = model.Package{Ecosystem: "apk", Distro: alpine320, Name: "libcrypto3", Version: "3.3.0-r2",
		SourceName: "openssl", SourceVersion: "3.3.0-r2", Arch: "x86_64"}
	requests = model.Package{Ecosystem: "python", Name: "requests", Version: "2.31.0", PURL: "pkg:pypi/requests@2.31.0",
		Path: "/usr/lib/python3/site-packages/requests-2.31.0.dist-info/METADATA"}
)

const cve5535 = "CVE-2024-5535"

var testdata = os.DirFS("testdata")

func newStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "ffs.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	return st
}

// fixture returns a trimmed real OSV record from testdata.
func fixture(t *testing.T, id string) []byte {
	t.Helper()
	raw, err := fs.ReadFile(testdata, id+".json")
	require.NoError(t, err)
	return raw
}

// cache stores raw in the bucket's OSV cache under the index names the OSV feed writes.
func cache(t *testing.T, st *store.Store, bucket string, raw []byte) {
	t.Helper()
	v, err := match.ParseOSV(raw)
	require.NoError(t, err)
	hash, err := osv.AffectedHash(raw)
	require.NoError(t, err)
	_, err = st.PutOSVRecord(ctx, bucket, v.GetId(), v.GetModified().AsTime(), hash, raw)
	require.NoError(t, err)
	var names []string
	for _, a := range v.GetAffected() {
		if osv.BucketOf(a.GetPackage().GetEcosystem()) == bucket {
			names = append(names, osv.IndexName(bucket, a.GetPackage().GetName()))
		}
	}
	require.NoError(t, st.PutOSVRecordNames(ctx, bucket, v.GetId(), names))
}

// changed returns raw as the OSV feed hands it off.
func changed(t *testing.T, bucket string, raw []byte) osv.Changed {
	t.Helper()
	v, err := match.ParseOSV(raw)
	require.NoError(t, err)
	return osv.Changed{Ecosystem: bucket, ID: v.GetId(), Raw: raw}
}

// image stores pkgs as the packages of digest and returns them as stored, with their IDs.
func image(t *testing.T, st *store.Store, digest string, pkgs ...model.Package) []model.Package {
	t.Helper()
	require.NoError(t, st.PutSBOM(ctx, digest, []byte("{}"), pkgs))
	out, err := st.PackagesForImage(ctx, digest)
	require.NoError(t, err)
	require.Len(t, out, len(pkgs))
	return out
}

// apply caches each record in its bucket and hands them all to ApplyOSV, as the OSV feed does.
func apply(t *testing.T, m *osvfast.Matcher, st *store.Store, recs ...osv.Changed) []match.Delta {
	t.Helper()
	for _, r := range recs {
		cache(t, st, r.Ecosystem, r.Raw)
	}
	deltas, err := m.ApplyOSV(ctx, recs)
	require.NoError(t, err)
	return deltas
}

func scope(adv string) store.MatchScope {
	return store.MatchScope{Source: model.SourceOSV, AdvisoryIDs: []string{adv}}
}

// byPackage indexes the matches of deltas by package ID.
func byPackage(deltas []match.Delta) map[string]model.Match {
	out := map[string]model.Match{}
	for _, d := range deltas {
		for _, m := range d.Matches {
			out[m.PackageID] = m
		}
	}
	return out
}

func TestOSVFast_SourcePackageJoin(t *testing.T) {
	st := newStore(t)
	m := osvfast.New(st)
	vulnerable := image(t, st, dDeb, libssl3)
	patched := libssl3
	patched.Version, patched.SourceVersion = "3.0.15-1~deb12u1", "3.0.15-1~deb12u1"
	image(t, st, dDeb2, patched)

	deltas := apply(t, m, st, changed(t, "Debian", fixture(t, "DEBIAN-CVE-2024-5535")))
	want := model.Match{ImageDigest: dDeb, PackageID: vulnerable[0].ID, AdvisoryID: cve5535, Source: model.SourceOSV,
		FixState: model.FixFixed, FixedVersions: []string{"3.0.15-1~deb12u1"}, Namespace: "Debian:12"}
	require.Equal(t, []match.Delta{{Scope: scope(cve5535), Matches: []model.Match{want}}}, deltas)

	got, err := m.MatchImage(ctx, match.ImageInput{Digest: dDeb, Packages: vulnerable})
	require.NoError(t, err)
	require.Equal(t, []model.Match{want}, got)
}

func TestOSVFast_UbuntuAndAlpineJoin(t *testing.T) {
	st := newStore(t)
	m := osvfast.New(st)
	ub := image(t, st, dUbuntu, libssl3t64)
	al := image(t, st, dAlpine, libcrypto3)
	ubuntuRaw := fixture(t, "UBUNTU-CVE-2024-5535")

	deltas := apply(t, m, st, changed(t, "Ubuntu", ubuntuRaw), changed(t, "Alpine", fixture(t, "ALPINE-CVE-2024-5535")))
	alpineMatch := model.Match{ImageDigest: dAlpine, PackageID: al[0].ID, AdvisoryID: cve5535, Source: model.SourceOSV,
		FixState: model.FixFixed, FixedVersions: []string{"3.3.1-r1"}, Namespace: "Alpine:v3.20"}
	require.Len(t, deltas, 1)
	require.Equal(t, scope(cve5535), deltas[0].Scope)
	require.ElementsMatch(t, []model.Match{
		{ImageDigest: dUbuntu, PackageID: ub[0].ID, AdvisoryID: cve5535, Source: model.SourceOSV, FixState: model.FixFixed,
			FixedVersions: []string{"3.0.13-0ubuntu3.2"}, VendorSeverity: model.SeverityLow, VendorSeveritySource: "ubuntu",
			Namespace: "Ubuntu:24.04"},
		alpineMatch,
	}, deltas[0].Matches)

	// An Ubuntu Pro ecosystem never equals a package's.
	pro := bytes.ReplaceAll(ubuntuRaw, []byte(`"Ubuntu:24.04:LTS"`), []byte(`"Ubuntu:Pro:24.04:LTS"`))
	deltas = apply(t, m, st, changed(t, "Ubuntu", pro))
	require.Equal(t, []match.Delta{{Scope: scope(cve5535), Matches: []model.Match{alpineMatch}}}, deltas)
}

func TestEvaluate_Ranges(t *testing.T) {
	ranged := func(eco string, typ osvschema.Range_Type, events ...*osvschema.Event) *osvschema.Affected {
		return &osvschema.Affected{Package: &osvschema.Package{Ecosystem: eco, Name: "x"},
			Ranges: []*osvschema.Range{{Type: typ, Events: events}}}
	}
	intro := func(v string) *osvschema.Event { return &osvschema.Event{Introduced: v} }
	fixed := func(v string) *osvschema.Event { return &osvschema.Event{Fixed: v} }
	last := func(v string) *osvschema.Event { return &osvschema.Event{LastAffected: v} }

	type result struct {
		affected bool
		fs       model.FixState
		fixed    []string
	}
	npm := ranged("npm", osvschema.Range_SEMVER, intro("0"), fixed("1.2.3"))
	goRanges := ranged("Go", osvschema.Range_SEMVER, intro("0"), fixed("1.6.38"), intro("1.7.0-beta.0"), fixed("1.7.27"))
	lastAffected := ranged("npm", osvschema.Range_SEMVER, intro("0"), last("2.0.0"))
	listed := &osvschema.Affected{Package: &osvschema.Package{Ecosystem: "PyPI", Name: "x"}, Versions: []string{"9.9.9"}}
	gitOnly := ranged("npm", osvschema.Range_GIT, intro("0"), fixed("abc123"))
	for _, tc := range []struct {
		name    string
		a       *osvschema.Affected
		version string
		want    result
	}{
		{"npm below fix", npm, "1.2.2", result{true, model.FixFixed, []string{"1.2.3"}}},
		{"npm at fix", npm, "1.2.3", result{}},
		{"go second interval", goRanges, "1.7.26", result{true, model.FixFixed, []string{"1.7.27"}}},
		{"go first interval", goRanges, "1.6.37", result{true, model.FixFixed, []string{"1.6.38"}}},
		{"go between intervals", goRanges, "1.6.38", result{}},
		{"go after both", goRanges, "1.7.27", result{}},
		{"at last_affected", lastAffected, "2.0.0", result{true, model.FixNotFixed, nil}},
		{"above last_affected", lastAffected, "2.0.1", result{}},
		{"listed version", listed, "9.9.9", result{true, model.FixNotFixed, nil}},
		{"unlisted version", listed, "9.9.8", result{}},
		{"GIT ranges ignored", gitOnly, "1.0.0", result{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			affected, fs, fixed, err := osvfast.Evaluate(tc.a, tc.version)
			require.NoError(t, err)
			require.Equal(t, tc.want, result{affected, fs, fixed})
		})
	}

	_, _, _, err := osvfast.Evaluate(ranged("Linux", osvschema.Range_ECOSYSTEM, intro("0"), fixed("6.1")), "6.0")
	require.ErrorIs(t, err, semantic.ErrUnsupportedEcosystem)
}

func TestOSVFast_GoStdlib(t *testing.T) {
	st := newStore(t)
	m := osvfast.New(st)
	stdlib := model.Package{Ecosystem: "go-module", Name: "stdlib", Version: "go1.22.3", GoStdlib: true, Path: "/usr/local/bin/app"}
	old := image(t, st, dGo, stdlib)
	stdlib.Version = "go1.22.5"
	image(t, st, dGo2, stdlib)

	deltas := apply(t, m, st, changed(t, "Go", fixture(t, "GO-2024-2963")))
	require.Equal(t, []match.Delta{{Scope: scope("CVE-2024-24791"), Matches: []model.Match{{
		ImageDigest: dGo, PackageID: old[0].ID, AdvisoryID: "CVE-2024-24791", Source: model.SourceOSV,
		FixState: model.FixFixed, FixedVersions: []string{"1.22.5"}, Namespace: "Go",
	}}}}, deltas)
}

func TestInstalledVersion(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    model.Package
		want string
		ok   bool
	}{
		{"stdlib patch", model.Package{Ecosystem: "go-module", Name: "stdlib", Version: "go1.22.3", GoStdlib: true}, "1.22.3", true},
		{"stdlib minor", model.Package{Ecosystem: "go-module", Name: "stdlib", Version: "go1.22", GoStdlib: true}, "1.22.0", true},
		{"stdlib rc", model.Package{Ecosystem: "go-module", Name: "stdlib", Version: "go1.22rc1"}, "1.22.0-rc.1", true},
		{"stdlib beta", model.Package{Ecosystem: "go-module", Name: "stdlib", Version: "go1.21beta2", GoStdlib: true}, "1.21.0-beta.2", true},
		{"stdlib experiment suffix", model.Package{Ecosystem: "go-module", Name: "stdlib", Version: "go1.22.3 X:boringcrypto", GoStdlib: true}, "1.22.3", true},
		{"stdlib devel", model.Package{Ecosystem: "go-module", Name: "stdlib", Version: "devel go1.23-abc", GoStdlib: true}, "", false},
		{"go module", model.Package{Ecosystem: "go-module", Name: "golang.org/x/net", Version: "v1.2.3"}, "1.2.3", true},
		{"go module devel", model.Package{Ecosystem: "go-module", Name: "example.com/app", Version: "(devel)"}, "", false},
		{"go module empty", model.Package{Ecosystem: "go-module", Name: "example.com/app"}, "", false},
		{"rpm epoch", model.Package{Ecosystem: "rpm", Name: "foo", Epoch: "1", Version: "2.3-4"}, "1:2.3-4", true},
		{"rpm epoch already in version", model.Package{Ecosystem: "rpm", Name: "foo", Epoch: "1", Version: "1:2.3-4"}, "1:2.3-4", true},
		{"rpm without epoch", model.Package{Ecosystem: "rpm", Name: "foo", Version: "2.3-4"}, "2.3-4", true},
		{"deb source version", libssl3, "3.0.11-1~deb12u2", true},
		{"deb binNMU keeps source version", model.Package{Ecosystem: "deb", Distro: debian12, Name: "libfoo1",
			Version: "1.2-3+b1", SourceName: "foo", SourceVersion: "1.2-3"}, "1.2-3", true},
		{"deb without source version", model.Package{Ecosystem: "deb", Distro: debian12, Name: "foo", Version: "1.2-3"}, "1.2-3", true},
		{"pypi", requests, "2.31.0", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := osvfast.InstalledVersion(tc.p)
			require.Equal(t, tc.ok, ok)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestOSVFast_RPMEpochMismatchSkipped(t *testing.T) {
	st := newStore(t)
	m := osvfast.New(st)
	foo := model.Package{Ecosystem: "rpm", Distro: alma9, Name: "foo", Version: "1.0-1", SourceName: "foo", Arch: "x86_64"}
	image(t, st, dAlma, foo)
	foo.Epoch, foo.Version = "1", "1:1.0-1" // as syft reports an rpm with an epoch
	withEpoch := image(t, st, dAlma2, foo)
	rec := []byte(`{"id": "ALSA-2026:0001", "modified": "2026-11-01T00:00:00Z", "affected": [{
		"package": {"ecosystem": "AlmaLinux:9", "name": "foo"},
		"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1:2.0-1"}]}]}]}`)

	deltas := apply(t, m, st, changed(t, "AlmaLinux", rec))
	require.Equal(t, []match.Delta{{Scope: scope("ALSA-2026:0001"), Matches: []model.Match{{
		ImageDigest: dAlma2, PackageID: withEpoch[0].ID, AdvisoryID: "ALSA-2026:0001", Source: model.SourceOSV,
		FixState: model.FixFixed, FixedVersions: []string{"1:2.0-1"}, Namespace: "AlmaLinux:9",
	}}}}, deltas)
}

func TestOSVFast_SkippedEcosystems(t *testing.T) {
	st := newStore(t)
	m := osvfast.New(st)
	image(t, st, dDeb, libssl3)
	recs := []osv.Changed{
		{Ecosystem: "Azure Linux", ID: "AZL-1", Raw: []byte(`{"id": "AZL-1", "aliases": ["CVE-2026-100"], "affected": [{
			"package": {"ecosystem": "Azure Linux:3", "name": "openssl"},
			"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.3.2-1.azl3"}]}]}]}`)},
		{Ecosystem: "Linux", ID: "CVE-2026-101", Raw: []byte(`{"id": "CVE-2026-101", "affected": [{
			"package": {"ecosystem": "Linux", "name": "Kernel"},
			"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "6.1"}, {"fixed": "6.1.99"}]}]}]}`)},
		{Ecosystem: "Android", ID: "ASB-A-1", Raw: []byte(`{"id": "ASB-A-1", "aliases": ["CVE-2026-102"], "affected": [{
			"package": {"ecosystem": "Android", "name": "platform/external/boringssl"},
			"versions": ["14"]}]}`)},
		{Ecosystem: "GIT", ID: "CVE-2026-103", Raw: []byte(`{"id": "CVE-2026-103", "affected": [{
			"ranges": [{"type": "GIT", "repo": "https://github.com/openssl/openssl", "events": [{"introduced": "0"}, {"fixed": "abc123"}]}],
			"versions": ["openssl-3.0.11"]}]}`)},
	}
	deltas, err := m.ApplyOSV(ctx, recs)
	require.NoError(t, err)
	require.Empty(t, deltas)
	for _, id := range []string{"CVE-2026-100", "CVE-2026-101", "CVE-2026-102", "CVE-2026-103"} {
		_, ok, err := st.GetAdvisory(ctx, id)
		require.NoError(t, err)
		require.False(t, ok, id)
	}
}

func TestOSVFast_KernelHeadersSkipped(t *testing.T) {
	st := newStore(t)
	m := osvfast.New(st)
	pkgs := image(t, st, dDeb,
		model.Package{Ecosystem: "deb", Distro: debian12, Name: "linux-libc-dev", Version: "6.1.69-1",
			SourceName: "linux", SourceVersion: "6.1.69-1", Arch: "amd64"},
		model.Package{Ecosystem: "deb", Distro: debian12, Name: "linux-image-6.1.0-17-amd64", Version: "6.1.69-1",
			SourceName: "linux", SourceVersion: "6.1.69-1", Arch: "amd64"})
	kernel := pkgs[0]
	require.Equal(t, "linux-image-6.1.0-17-amd64", kernel.Name)
	want := []model.Match{{ImageDigest: dDeb, PackageID: kernel.ID, AdvisoryID: "CVE-2024-1086", Source: model.SourceOSV,
		FixState: model.FixFixed, FixedVersions: []string{"6.1.76-1"}, Namespace: "Debian:12"}}

	deltas := apply(t, m, st, changed(t, "Debian", fixture(t, "DEBIAN-CVE-2024-1086")))
	require.Equal(t, []match.Delta{{Scope: scope("CVE-2024-1086"), Matches: want}}, deltas)
	got, err := m.MatchImage(ctx, match.ImageInput{Digest: dDeb, Packages: pkgs})
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestOSVFast_SeveritySources(t *testing.T) {
	st := newStore(t)
	m := osvfast.New(st)
	py := image(t, st, dPy, requests)
	ub := image(t, st, dUbuntu, model.Package{Ecosystem: "deb", Distro: ubuntu2404, Name: "openssh-client",
		Version: "1:9.6p1-3ubuntu13", SourceName: "openssh", SourceVersion: "1:9.6p1-3ubuntu13", Arch: "amd64"})
	deb := image(t, st, dDeb, libssl3, model.Package{Ecosystem: "deb", Distro: debian12, Name: "libc6",
		Version: "2.36-9+deb12u4", SourceName: "glibc", SourceVersion: "2.36-9+deb12u4", Arch: "amd64"})
	libc6, ssl := deb[0], deb[1]
	require.Equal(t, "libc6", libc6.Name)

	got := byPackage(apply(t, m, st,
		changed(t, "PyPI", fixture(t, "GHSA-9wx4-h78v-vm56")),
		changed(t, "Ubuntu", fixture(t, "UBUNTU-CVE-2024-6387")),
		changed(t, "Debian", fixture(t, "DEBIAN-CVE-2019-1010022")),
		changed(t, "Debian", fixture(t, "DEBIAN-CVE-2024-5535"))))
	type severity struct {
		sev    model.Severity
		source string
	}
	sevOf := func(id string) severity {
		mt, ok := got[id]
		require.True(t, ok, "no match for %s", id)
		return severity{mt.VendorSeverity, mt.VendorSeveritySource}
	}
	require.Equal(t, severity{model.SeverityMedium, "ghsa"}, sevOf(py[0].ID))
	require.Equal(t, severity{model.SeverityHigh, "ubuntu"}, sevOf(ub[0].ID))
	require.Equal(t, severity{model.SeverityNegligible, "debian"}, sevOf(libc6.ID))
	require.Equal(t, severity{model.SeverityUnknown, ""}, sevOf(ssl.ID)) // urgency "not yet assigned"
	require.Equal(t, model.FixNotFixed, got[libc6.ID].FixState)
}

func TestOSVFast_ApplyOSVScopesByAdvisory(t *testing.T) {
	st := newStore(t)
	m := osvfast.New(st)
	deb := image(t, st, dDeb, libssl3)
	ub := image(t, st, dUbuntu, libssl3t64)
	debianRaw := fixture(t, "DEBIAN-CVE-2024-5535")
	cache(t, st, "Debian", debianRaw)
	apply(t, m, st, changed(t, "Ubuntu", fixture(t, "UBUNTU-CVE-2024-5535"))) // handed off earlier

	deltas, err := m.ApplyOSV(ctx, []osv.Changed{changed(t, "Debian", debianRaw)})
	require.NoError(t, err)
	require.Len(t, deltas, 1)
	require.Equal(t, scope(cve5535), deltas[0].Scope)
	got := byPackage(deltas)
	require.Len(t, got, 2)
	require.Equal(t, "Debian:12", got[deb[0].ID].Namespace)
	require.Equal(t, "Ubuntu:24.04", got[ub[0].ID].Namespace)
}

func TestOSVFast_WithdrawnRecordDropsMatches(t *testing.T) {
	st := newStore(t)
	m := osvfast.New(st)
	image(t, st, dDeb, libssl3)
	raw := fixture(t, "DEBIAN-CVE-2024-5535")
	deltas := apply(t, m, st, changed(t, "Debian", raw))
	require.Len(t, byPackage(deltas), 1)

	// The weekly set-diff hands off the cached record with a withdrawn time and no new cache write.
	withdrawn := bytes.Replace(raw, []byte("{"), []byte(`{"withdrawn": "2026-11-19T00:00:00Z",`), 1)
	deltas, err := m.ApplyOSV(ctx, []osv.Changed{changed(t, "Debian", withdrawn)})
	require.NoError(t, err)
	require.Len(t, deltas, 1)
	require.Equal(t, scope(cve5535), deltas[0].Scope)
	require.Empty(t, deltas[0].Matches)
}

func TestOSVFast_MatchImageUsesCache(t *testing.T) {
	st := newStore(t)
	m := osvfast.New(st)
	require.Empty(t, byPackage(apply(t, m, st, changed(t, "PyPI", fixture(t, "GHSA-9wx4-h78v-vm56")))))
	pkgs := image(t, st, dPy, requests)
	want := []model.Match{{ImageDigest: dPy, PackageID: pkgs[0].ID, AdvisoryID: "CVE-2024-35195", Source: model.SourceOSV,
		FixState: model.FixFixed, FixedVersions: []string{"2.32.0"}, VendorSeverity: model.SeverityMedium,
		VendorSeveritySource: "ghsa", Namespace: "PyPI"}}

	got, err := m.MatchImage(ctx, match.ImageInput{Digest: dPy, Packages: pkgs})
	require.NoError(t, err)
	require.Equal(t, want, got)

	synthetic := requests
	synthetic.ID, synthetic.ImageDigest = "synthetic", "runtime:containerd@2.0.3"
	got, err = m.MatchImage(ctx, match.ImageInput{Digest: dPy, Packages: append(pkgs, synthetic)})
	require.NoError(t, err)
	require.Equal(t, want, got)
	got, err = m.MatchImage(ctx, match.ImageInput{Digest: synthetic.ImageDigest, Packages: []model.Package{synthetic}})
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestOSVFast_MaliciousPackage(t *testing.T) {
	st := newStore(t)
	m := osvfast.New(st)
	pkgs := image(t, st, dNode, model.Package{Ecosystem: "npm", Name: "squaredev-next-online-payments-example",
		Version: "99.0.0", Path: "/app/node_modules/squaredev-next-online-payments-example/package.json"})

	deltas := apply(t, m, st, changed(t, "npm", fixture(t, "MAL-2024-1")))
	require.Equal(t, []match.Delta{{Scope: scope("MAL-2024-1"), Matches: []model.Match{{
		ImageDigest: dNode, PackageID: pkgs[0].ID, AdvisoryID: "MAL-2024-1", Source: model.SourceOSV,
		FixState: model.FixNotFixed, Namespace: "npm",
	}}}}, deltas)
	a, ok, err := st.GetAdvisory(ctx, "MAL-2024-1")
	require.NoError(t, err)
	require.True(t, ok)
	require.True(t, a.Malicious)
}
