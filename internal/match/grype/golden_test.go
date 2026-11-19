//go:build golden

package grype

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/match"
	"github.com/the-it-dept/ffs/internal/model"
)

// goldenDir holds the fixtures hack/golden.sh generates.
var goldenDir = os.DirFS(filepath.Join("testdata", "golden"))

// TestGolden_MatchesGrypeCLI matches each fixture SBOM against the pinned Grype DB and compares the
// result with what the grype CLI reported for the same SBOM and DB (hack/golden.sh). The one
// documented deviation (spec §6.5): ffs drops grype's matches on the Go standard library.
// Run it with `make golden`.
func TestGolden_MatchesGrypeCLI(t *testing.T) {
	dbDir := os.Getenv("FFS_GOLDEN_DB")
	if dbDir == "" {
		t.Fatal("FFS_GOLDEN_DB is not set: run make golden")
	}
	desc, err := v6.ReadDescription(filepath.Join(dbDir, v6.VulnerabilityDBFileName))
	require.NoError(t, err)
	m := New(newStore(t))
	require.NoError(t, m.Load(dbDir, desc.Built.Time))

	for _, fixture := range []string{"debian-12", "ubuntu-24.04", "alpine-3.20", "ubi9", "distroless", "python", "node", "go-binary"} {
		t.Run(fixture, func(t *testing.T) {
			sj, err := fs.ReadFile(goldenDir, fixture+".syft.json")
			require.NoError(t, err)
			pkgs := goldenPackages(t, sj)
			ms, err := m.MatchImage(ctx, match.ImageInput{Digest: "sha256:" + fixture, SyftJSON: sj, Packages: pkgs})
			require.NoError(t, err)

			byID := make(map[string]model.Package, len(pkgs))
			for _, p := range pkgs {
				byID[p.ID] = p
			}
			var got []string
			for _, mt := range ms {
				if mt.FixState == model.FixNotAffected {
					continue
				}
				p := byID[mt.PackageID]
				got = append(got, goldenKey(p.Name, p.Version, p.Ecosystem, mt.AdvisoryID, string(mt.FixState)))
			}
			require.Equal(t, cliMatches(t, fixture), sortedSet(got))
		})
	}
}

// goldenPackages lists the SBOM's artifacts as ffs packages keyed by their syft ids.
func goldenPackages(t *testing.T, sj []byte) []model.Package {
	t.Helper()
	var doc struct {
		Artifacts []struct {
			ID, Name, Version, Type string
			Locations               []struct{ Path string }
		}
	}
	require.NoError(t, json.Unmarshal(sj, &doc))
	pkgs := make([]model.Package, len(doc.Artifacts))
	for i, a := range doc.Artifacts {
		pkgs[i] = model.Package{ID: a.ID, SyftID: a.ID, Name: a.Name, Version: a.Version, Ecosystem: a.Type}
		if len(a.Locations) > 0 {
			pkgs[i].Path = a.Locations[0].Path
		}
	}
	return pkgs
}

// cliMatches returns the grype CLI's matches for the fixture, minus the Go standard library.
func cliMatches(t *testing.T, fixture string) []string {
	t.Helper()
	b, err := fs.ReadFile(goldenDir, fixture+".grype.json")
	require.NoError(t, err)
	var doc struct {
		Matches []struct {
			Artifact      struct{ Name, Version, Type string }
			Vulnerability struct {
				ID  string
				Fix struct{ State string }
			}
		}
	}
	require.NoError(t, json.Unmarshal(b, &doc))
	var want []string
	for _, mt := range doc.Matches {
		a := mt.Artifact
		if a.Name == "stdlib" && a.Type == "go-module" {
			continue
		}
		state := mt.Vulnerability.Fix.State
		if state == "" { // the CLI prints a cleared fix state (e.g. apk CPE matches) as ""; grype reads it as unknown
			state = string(model.FixUnknown)
		}
		want = append(want, goldenKey(a.Name, a.Version, a.Type, mt.Vulnerability.ID, state))
	}
	return sortedSet(want)
}

func goldenKey(parts ...string) string { return strings.Join(parts, "|") }

func sortedSet(s []string) []string {
	slices.Sort(s)
	return slices.Compact(s)
}
