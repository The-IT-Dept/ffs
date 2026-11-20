package osvfast_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/feeds/osv"
	"github.com/the-it-dept/ffs/internal/match"
	"github.com/the-it-dept/ffs/internal/match/osvfast"
	"github.com/the-it-dept/ffs/internal/model"
)

var dHost = model.NodeGroupDigestPrefix + strings.Repeat("h", 16)

// linuxRecord is an Ubuntu 24.04 record for the linux source package, fixed in fixed, with an Ubuntu
// priority, whose upstream names cve.
func linuxRecord(t *testing.T, id, cve, fixed, priority string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"id": id, "modified": "2026-11-19T00:00:00Z", "upstream": []string{cve},
		"severity": []map[string]string{{"type": "Ubuntu", "score": priority}},
		"affected": []any{map[string]any{
			"package": map[string]string{"name": "linux", "ecosystem": "Ubuntu:24.04:LTS"},
			"ranges": []any{map[string]any{"type": "ECOSYSTEM",
				"events": []map[string]string{{"introduced": "0"}, {"fixed": fixed}}}},
		}},
	})
	require.NoError(t, err)
	return raw
}

// hostFixture stores an Ubuntu host SBOM with two binaries of the running linux source package and
// one of openssl, and caches (with their advisories) eight linux records and an openssl one. Five
// linux records match: UBUNTU-CVE-2026-1003 and UBUNTU-CVE-2026-1008 both name CVE-2026-1003 upstream
// and so canonicalise together, with different fixed versions and priorities; the other three are
// fixed at or before the installed version. MatchImage on the host reads nine records.
func hostFixture(t *testing.T) (*osvfast.Matcher, []model.Package) {
	t.Helper()
	st := newStore(t)
	m := osvfast.New(st)
	kernel := func(name string) model.Package {
		return model.Package{Ecosystem: "deb", Distro: ubuntu2404, Name: name, Version: "6.8.0-50.51",
			SourceName: "linux", SourceVersion: "6.8.0-50.51", Arch: "amd64"}
	}
	pkgs := image(t, st, dHost, kernel("linux-image-6.8.0-50-generic"), kernel("linux-modules-6.8.0-50-generic"), libssl3t64)
	recs := []struct{ id, cve, fixed, priority string }{
		{"UBUNTU-CVE-2026-1001", "CVE-2026-1001", "6.8.0-60.63", "medium"},
		{"UBUNTU-CVE-2026-1002", "CVE-2026-1002", "6.8.0-40.42", "high"},
		{"UBUNTU-CVE-2026-1003", "CVE-2026-1003", "6.8.0-55.58", "medium"},
		{"UBUNTU-CVE-2026-1004", "CVE-2026-1004", "6.8.0-50.51", "low"},
		{"UBUNTU-CVE-2026-1005", "CVE-2026-1005", "6.8.0-62.65", "low"},
		{"UBUNTU-CVE-2026-1006", "CVE-2026-1006", "6.8.0-61.64", "high"},
		{"UBUNTU-CVE-2026-1007", "CVE-2026-1007", "6.8.0-31.31", "high"},
		{"UBUNTU-CVE-2026-1008", "CVE-2026-1003", "6.8.0-57.60", "high"},
	}
	changes := []osv.Changed{changed(t, "Ubuntu", fixture(t, "UBUNTU-CVE-2024-5535"))}
	for _, r := range recs {
		changes = append(changes, changed(t, "Ubuntu", linuxRecord(t, r.id, r.cve, r.fixed, r.priority)))
	}
	apply(t, m, st, changes...)
	for _, id := range []string{"UBUNTU-CVE-2026-1003", "UBUNTU-CVE-2026-1008"} {
		adv, err := st.Canonical(ctx, id)
		require.NoError(t, err)
		require.Equal(t, "CVE-2026-1003", adv)
	}
	return m, pkgs
}

func TestMatchImageChunksRecords(t *testing.T) {
	m, pkgs := hostFixture(t)
	in := match.ImageInput{Digest: dHost, Packages: pkgs}

	osvfast.SetRecordChunk(t, 1<<30)
	want, err := m.MatchImage(ctx, in)
	require.NoError(t, err)
	// openssl's advisory on libssl3t64, then each matching linux advisory on both kernel binaries, in
	// record id order; UBUNTU-CVE-2026-1008 merges into CVE-2026-1003, which keeps the first priority
	// found.
	type key struct{ pkg, adv string }
	var got []key
	for _, mt := range want {
		got = append(got, key{mt.PackageID, mt.AdvisoryID})
	}
	var ssl string
	var kernel []string // in stored order, as the package index lists them
	for _, p := range pkgs {
		if p.SourceName == "linux" {
			kernel = append(kernel, p.ID)
		} else {
			ssl = p.ID
		}
	}
	k1, k2 := kernel[0], kernel[1]
	require.Equal(t, []key{{ssl, cve5535},
		{k1, "CVE-2026-1001"}, {k2, "CVE-2026-1001"}, {k1, "CVE-2026-1003"}, {k2, "CVE-2026-1003"},
		{k1, "CVE-2026-1005"}, {k2, "CVE-2026-1005"}, {k1, "CVE-2026-1006"}, {k2, "CVE-2026-1006"}}, got)
	require.Equal(t, []string{"6.8.0-55.58", "6.8.0-57.60"}, want[3].FixedVersions)
	require.Equal(t, model.SeverityMedium, want[3].VendorSeverity)

	for _, n := range []int{1, 2, 3} {
		osvfast.SetRecordChunk(t, n)
		chunked, err := m.MatchImage(ctx, in)
		require.NoError(t, err)
		require.Equal(t, want, chunked, "recordChunk %d", n)
	}
}

// TestMatchImageBoundsRecordLoads is the regression for reading every record a bucket's packages
// name at once: MatchImage reads at most recordChunk records at a time, and still reads them all.
func TestMatchImageBoundsRecordLoads(t *testing.T) {
	m, pkgs := hostFixture(t)
	osvfast.SetRecordChunk(t, 3)
	loads := osvfast.WatchRecordLoads(t)

	ms, err := m.MatchImage(ctx, match.ImageInput{Digest: dHost, Packages: pkgs})
	require.NoError(t, err)
	require.Len(t, ms, 9)
	require.Equal(t, []int{3, 3, 3}, *loads)
}

// TestMatchImageReadsAreBoundedInBytes: by default a read takes as many records as 64 MiB holds of the largest
// record the OSV feed caches (4 MiB), not a count: a host's kernel records average over 400 KB, and 256 of them
// at a time, parsed together, held most of a gigabyte.
func TestMatchImageReadsAreBoundedInBytes(t *testing.T) {
	records, bytes := osvfast.RecordChunk()
	require.Equal(t, 64<<20, bytes)
	require.Equal(t, 4<<20, osvfast.MaxCachedRecordBytes)
	require.Equal(t, 16, records)
	require.LessOrEqual(t, records*osvfast.MaxCachedRecordBytes, bytes)

	m, pkgs := hostFixture(t)
	loads := osvfast.WatchRecordLoads(t)
	ms, err := m.MatchImage(ctx, match.ImageInput{Digest: dHost, Packages: pkgs})
	require.NoError(t, err)
	require.Len(t, ms, 9)
	require.Equal(t, []int{9}, *loads, "nine records fit one read")
}
