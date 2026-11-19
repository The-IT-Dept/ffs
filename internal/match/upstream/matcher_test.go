package upstream_test

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/feeds/osv"
	"github.com/the-it-dept/ffs/internal/match"
	"github.com/the-it-dept/ffs/internal/match/upstream"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

var (
	ctx      = context.Background()
	testdata = os.DirFS("testdata")
)

const (
	cvePHP     = "CVE-2024-11236"
	cveNode    = "CVE-2024-27983"
	cveFixture = "CVE-2099-0001" // the advisory cna-php.json is stored under
	phpSrc     = "github.com/php/php-src"
	nodeRepo   = "github.com/nodejs/node"
)

func digest(c string) string { return "sha256:" + strings.Repeat(c, 64) }

func newStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "ffs.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	return st
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := fs.ReadFile(testdata, name)
	require.NoError(t, err)
	return raw
}

// cacheGit stores raw in the GIT bucket of the OSV cache, indexed under its range repositories as
// the OSV feed does.
func cacheGit(t *testing.T, st *store.Store, raw []byte) {
	t.Helper()
	v, err := match.ParseOSV(raw)
	require.NoError(t, err)
	hash, err := osv.AffectedHash(raw)
	require.NoError(t, err)
	_, err = st.PutOSVRecord(ctx, osv.BucketGIT, v.GetId(), v.GetModified().AsTime(), hash, raw)
	require.NoError(t, err)
	var names []string
	for _, a := range v.GetAffected() {
		for _, r := range a.GetRanges() {
			names = append(names, osv.NormalizeRepo(r.GetRepo()))
		}
	}
	require.NoError(t, st.PutOSVRecordNames(ctx, osv.BucketGIT, v.GetId(), names))
}

// image stores pkgs as the packages of d and returns them as stored, with their IDs.
func image(t *testing.T, st *store.Store, d string, pkgs ...model.Package) []model.Package {
	t.Helper()
	require.NoError(t, st.PutSBOM(ctx, d, []byte("{}"), pkgs))
	out, err := st.PackagesForImage(ctx, d)
	require.NoError(t, err)
	require.Len(t, out, len(pkgs))
	return out
}

func phpCLI(version string) model.Package {
	return model.Package{Ecosystem: "binary", Classifier: "php-cli-binary", Name: "php-cli", Version: version, Path: "/usr/local/bin/php"}
}

func matchImage(t *testing.T, m *upstream.Matcher, d string, pkgs []model.Package) []model.Match {
	t.Helper()
	ms, err := m.MatchImage(ctx, match.ImageInput{Digest: d, Packages: pkgs})
	require.NoError(t, err)
	return ms
}

func TestUpstream_PHPMatchesFixtureCVE(t *testing.T) {
	st := newStore(t)
	raw := fixture(t, "cna-php.json")
	require.NoError(t, st.PutUpstreamRanges(ctx, cveFixture, "php", raw))
	stored, err := st.UpstreamRanges(ctx, "php")
	require.NoError(t, err)
	var r upstream.CNARanges
	require.NoError(t, json.Unmarshal(stored[cveFixture], &r))
	require.Equal(t, "8.3.15", r.Versions[2].LessThan)

	m := upstream.New(st)
	require.Equal(t, model.SourceUpstream, m.Source())

	vulnerable := image(t, st, digest("a"), phpCLI("8.3.14"))
	require.Equal(t, []model.Match{{
		ImageDigest:   digest("a"),
		PackageID:     vulnerable[0].ID,
		AdvisoryID:    cveFixture,
		Source:        model.SourceUpstream,
		FixState:      model.FixFixed,
		FixedVersions: []string{"8.3.15"},
		Namespace:     "cna:php",
	}}, matchImage(t, m, digest("a"), vulnerable))

	patched := image(t, st, digest("b"), phpCLI("8.3.15"))
	require.Empty(t, matchImage(t, m, digest("b"), patched))

	// A package outside the map, or a synthetic digest, matches nothing.
	other := image(t, st, digest("c"), model.Package{Ecosystem: "binary", Classifier: "traefik-binary", Name: "traefik", Version: "8.3.14"})
	require.Empty(t, matchImage(t, m, digest("c"), other))
	require.Empty(t, matchImage(t, m, "runtime:containerd@1.7.0", vulnerable))
}

func TestUpstream_NodeGitRecord(t *testing.T) {
	st := newStore(t)
	raw := fixture(t, cveNode+".json")
	v, err := match.ParseOSV(raw)
	require.NoError(t, err)
	require.Contains(t, v.GetAffected()[0].GetVersions(), "v20.11.1")
	require.Equal(t, "https://github.com/nodejs/node", v.GetAffected()[0].GetRanges()[0].GetRepo())
	cacheGit(t, st, raw)

	m := upstream.New(st)
	node := func(version string) model.Package {
		return model.Package{Ecosystem: "binary", Classifier: "nodejs-binary", Name: "node", Version: version, Path: "/usr/local/bin/node"}
	}
	pkgs := image(t, st, digest("n"), node("20.11.1"))
	require.Equal(t, []model.Match{{
		ImageDigest:   digest("n"),
		PackageID:     pkgs[0].ID,
		AdvisoryID:    cveNode,
		Source:        model.SourceUpstream,
		FixState:      model.FixFixed,
		FixedVersions: []string{"20.12.1"},
		Namespace:     "git:" + nodeRepo,
	}}, matchImage(t, m, digest("n"), pkgs))

	fixed := image(t, st, digest("f"), node("20.12.1"))
	require.Empty(t, matchImage(t, m, digest("f"), fixed))
	// With a versions list, the listed tags decide: 20.11.2 lies in an extracted range but is not listed.
	ok, _, _ := upstream.MatchGitRecord(v, nodeRepo, []string{"v20.11.2"}, "20.11.2")
	require.False(t, ok)

	// ApplyOSV reaches the same match through the package index.
	deltas, err := m.ApplyOSV(ctx, []osv.Changed{{Ecosystem: osv.BucketGIT, ID: cveNode, Raw: raw}})
	require.NoError(t, err)
	require.Len(t, deltas, 1)
	require.Equal(t, store.MatchScope{Source: model.SourceUpstream, AdvisoryIDs: []string{cveNode}}, deltas[0].Scope)
	require.Len(t, deltas[0].Matches, 1)
	require.Equal(t, pkgs[0].ID, deltas[0].Matches[0].PackageID)
	a, ok, err := st.GetAdvisory(ctx, cveNode)
	require.NoError(t, err)
	require.True(t, ok)
	require.Contains(t, a.Aliases, "BIT-node-2024-27983")
}

func TestUpstream_PHPGitExtractedEvents(t *testing.T) {
	st := newStore(t)
	raw := fixture(t, cvePHP+".json")
	v, err := match.ParseOSV(raw)
	require.NoError(t, err)
	require.Empty(t, v.GetAffected()[0].GetVersions())
	cacheGit(t, st, raw)

	m := upstream.New(st)
	pkgs := image(t, st, digest("a"), phpCLI("8.3.13"))
	require.Equal(t, []model.Match{{
		ImageDigest:   digest("a"),
		PackageID:     pkgs[0].ID,
		AdvisoryID:    cvePHP,
		Source:        model.SourceUpstream,
		FixState:      model.FixFixed,
		FixedVersions: []string{"8.3.14"},
		Namespace:     "git:" + phpSrc,
	}}, matchImage(t, m, digest("a"), pkgs))

	patched := image(t, st, digest("b"), phpCLI("8.3.14"))
	require.Empty(t, matchImage(t, m, digest("b"), patched))

	// The extracted ranges are evaluated per range: 8.2.25 is in 8.2.0 to 8.2.26.
	ok, fs, fixed := upstream.MatchGitRecord(v, phpSrc, []string{"php-8.2.25"}, "8.2.25")
	require.True(t, ok)
	require.Equal(t, model.FixFixed, fs)
	require.Equal(t, []string{"8.2.26"}, fixed)
	// Another repository, or a withdrawn record, matches nothing.
	ok, _, _ = upstream.MatchGitRecord(v, nodeRepo, []string{"php-8.3.13"}, "8.3.13")
	require.False(t, ok)
	withdrawn, err := match.ParseOSV([]byte(strings.Replace(string(raw), `"id":`, `"withdrawn": "2026-01-01T00:00:00Z", "id":`, 1)))
	require.NoError(t, err)
	require.NotNil(t, withdrawn.GetWithdrawn())
	ok, _, _ = upstream.MatchGitRecord(withdrawn, phpSrc, []string{"php-8.3.13"}, "8.3.13")
	require.False(t, ok)
}

func TestUpstream_ApplyCNAScope(t *testing.T) {
	st := newStore(t)
	cacheGit(t, st, fixture(t, cvePHP+".json")) // extracted ranges for 8.1, 8.2 and 8.3
	// The CNA names only the 8.3 branch, with a later fix than the GIT record.
	require.NoError(t, st.PutUpstreamRanges(ctx, cvePHP, "php",
		[]byte(`{"defaultStatus":"unaffected","versions":[{"version":"8.3.*","lessThan":"8.3.15","status":"affected"}]}`)))

	both := image(t, st, digest("a"), phpCLI("8.3.13"))
	gitOnly := image(t, st, digest("b"), model.Package{Ecosystem: "binary", Classifier: "php-fpm-binary", Name: "php-fpm", Version: "8.2.25"})
	cnaOnly := image(t, st, digest("c"), phpCLI("8.3.14"))
	image(t, st, digest("d"), phpCLI("8.3.15"))

	m := upstream.New(st)
	deltas, err := m.ApplyCNA(ctx, []string{cvePHP})
	require.NoError(t, err)
	require.Len(t, deltas, 1)
	require.Equal(t, store.MatchScope{Source: model.SourceUpstream, AdvisoryIDs: []string{cvePHP}}, deltas[0].Scope)

	byPkg := map[string]model.Match{}
	for _, mt := range deltas[0].Matches {
		byPkg[mt.PackageID] = mt
	}
	require.Len(t, byPkg, 3)
	require.Equal(t, "cna:php", byPkg[both[0].ID].Namespace, "the CNA match wins")
	require.Equal(t, []string{"8.3.15"}, byPkg[both[0].ID].FixedVersions)
	require.Equal(t, "git:"+phpSrc, byPkg[gitOnly[0].ID].Namespace)
	require.Equal(t, []string{"8.2.26"}, byPkg[gitOnly[0].ID].FixedVersions)
	require.Equal(t, "cna:php", byPkg[cnaOnly[0].ID].Namespace)
	for _, mt := range deltas[0].Matches {
		require.Equal(t, cvePHP, mt.AdvisoryID)
		require.Equal(t, model.SourceUpstream, mt.Source)
		require.Equal(t, model.FixFixed, mt.FixState)
	}

	// MatchImage agrees for the image matched by both sources.
	require.Equal(t, []model.Match{byPkg[both[0].ID]}, matchImage(t, m, digest("a"), both))
}

func TestUpstream_ApplyOSVClearsDroppedRecord(t *testing.T) {
	st := newStore(t)
	raw := fixture(t, cvePHP+".json")
	cacheGit(t, st, raw)
	image(t, st, digest("a"), phpCLI("8.3.13"))
	m := upstream.New(st)

	deltas, err := m.ApplyOSV(ctx, []osv.Changed{{Ecosystem: osv.BucketGIT, ID: cvePHP, Raw: raw}})
	require.NoError(t, err)
	require.Len(t, deltas, 1)
	require.Len(t, deltas[0].Matches, 1)

	// The record's range moves to another repository: the feed hands it off once more, and the
	// Delta for its advisory now carries no matches.
	moved := []byte(strings.ReplaceAll(string(raw), "https://github.com/php/php-src", "https://github.com/example/php-fork"))
	deltas, err = m.ApplyOSV(ctx, []osv.Changed{
		{Ecosystem: osv.BucketGIT, ID: cvePHP, Raw: moved},
		{Ecosystem: "PyPI", ID: "PYSEC-2024-1", Raw: []byte(`{"id":"PYSEC-2024-1"}`)},
	})
	require.NoError(t, err)
	require.Len(t, deltas, 1)
	require.Equal(t, store.MatchScope{Source: model.SourceUpstream, AdvisoryIDs: []string{cvePHP}}, deltas[0].Scope)
	require.Empty(t, deltas[0].Matches)
}
