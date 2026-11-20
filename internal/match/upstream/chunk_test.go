package upstream_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/feeds/osv"
	"github.com/the-it-dept/ffs/internal/match"
	"github.com/the-it-dept/ffs/internal/match/upstream"
	"github.com/the-it-dept/ffs/internal/model"
)

// phpRecord is a GIT record for php-src whose extracted range runs from introduced to fixed, with
// aliases.
func phpRecord(t *testing.T, id, introduced, fixed string, aliases ...string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"id": id, "modified": "2026-11-19T00:00:00Z", "aliases": aliases,
		"affected": []any{map[string]any{"ranges": []any{map[string]any{
			"type": "GIT", "repo": "https://" + phpSrc,
			"events": []map[string]string{{"introduced": "0"}, {"fixed": "38123aca18c3c1bd1f109ec77af2f175d7afcf35"}},
			"database_specific": map[string]any{"extracted_events": []any{map[string]any{
				"range": []map[string]string{{"introduced": introduced}, {"fixed": fixed}},
			}}},
		}}}},
	})
	require.NoError(t, err)
	return raw
}

// phpFixture stores an image with php-cli and php-fpm 8.3.13 and caches (with their advisories)
// seven php-src GIT records. Four match: OSV-2026-2003 aliases CVE-2026-2003 and so canonicalises
// with it, with a smaller fix; CVE-2026-2005 also has CNA ranges, which win over its GIT record. The
// other three are fixed at or before 8.3.13 or name another branch.
func phpFixture(t *testing.T) (*upstream.Matcher, []model.Package) {
	t.Helper()
	st := newStore(t)
	m := upstream.New(st)
	fpm := model.Package{Ecosystem: "binary", Classifier: "php-fpm-binary", Name: "php-fpm", Version: "8.3.13", Path: "/usr/local/sbin/php-fpm"}
	pkgs := image(t, st, digest("p"), phpCLI("8.3.13"), fpm)
	recs := [][]byte{
		phpRecord(t, "CVE-2026-2001", "8.3.0", "8.3.14"),
		phpRecord(t, "CVE-2026-2002", "8.3.0", "8.3.10"),
		phpRecord(t, "CVE-2026-2003", "8.3.0", "8.3.15"),
		phpRecord(t, "CVE-2026-2004", "8.2.0", "8.2.20"),
		phpRecord(t, "CVE-2026-2005", "8.3.0", "8.3.20"),
		phpRecord(t, "CVE-2026-2006", "8.1.0", "8.1.30"),
		phpRecord(t, "OSV-2026-2003", "8.3.0", "8.3.14", "CVE-2026-2003"),
	}
	var changes []osv.Changed
	for _, raw := range recs {
		cacheGit(t, st, raw)
		v, err := match.ParseOSV(raw)
		require.NoError(t, err)
		changes = append(changes, osv.Changed{Ecosystem: osv.BucketGIT, ID: v.GetId(), Raw: raw})
	}
	_, err := m.ApplyOSV(ctx, changes)
	require.NoError(t, err)
	require.NoError(t, st.PutUpstreamRanges(ctx, "CVE-2026-2005", "php",
		[]byte(`{"defaultStatus":"unaffected","versions":[{"version":"8.3.*","lessThan":"8.3.21","status":"affected"}]}`)))
	adv, err := st.Canonical(ctx, "OSV-2026-2003")
	require.NoError(t, err)
	require.Equal(t, "CVE-2026-2003", adv)
	return m, pkgs
}

func TestMatchImageChunksRecords(t *testing.T) {
	m, pkgs := phpFixture(t)

	upstream.SetRecordChunk(t, 1<<30)
	want := matchImage(t, m, digest("p"), pkgs)
	// The CNA matches first, then each matching GIT advisory on both packages in record id order;
	// OSV-2026-2003 merges into CVE-2026-2003 with its smaller fix.
	type key struct{ pkg, adv, ns string }
	var got []key
	for _, mt := range want {
		got = append(got, key{mt.PackageID, mt.AdvisoryID, mt.Namespace})
	}
	p1, p2, git := pkgs[0].ID, pkgs[1].ID, "git:"+phpSrc
	require.Equal(t, []key{{p1, "CVE-2026-2005", "cna:php"}, {p2, "CVE-2026-2005", "cna:php"},
		{p1, "CVE-2026-2001", git}, {p2, "CVE-2026-2001", git}, {p1, "CVE-2026-2003", git}, {p2, "CVE-2026-2003", git}}, got)
	require.Equal(t, []string{"8.3.14"}, want[4].FixedVersions)

	for _, n := range []int{1, 2, 3} {
		upstream.SetRecordChunk(t, n)
		require.Equal(t, want, matchImage(t, m, digest("p"), pkgs), "recordChunk %d", n)
	}
}

// TestMatchImageBoundsRecordLoads: MatchImage reads at most recordChunk of a repository's GIT
// records at a time, and still reads them all.
func TestMatchImageBoundsRecordLoads(t *testing.T) {
	m, pkgs := phpFixture(t)
	upstream.SetRecordChunk(t, 3)
	loads := upstream.WatchRecordLoads(t)

	require.Len(t, matchImage(t, m, digest("p"), pkgs), 6)
	require.Equal(t, []int{3, 3, 1}, *loads)
}
