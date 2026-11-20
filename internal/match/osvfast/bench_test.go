package osvfast_test

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/feeds/osv"
	"github.com/the-it-dept/ffs/internal/match"
	"github.com/the-it-dept/ffs/internal/match/osvfast"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

// kernelRecord is an Ubuntu record shaped like a kernel CVE's: one affected entry per linux source
// package (120 of them, none installed in a container image), each listing its binaries, plus one
// entry for a package the images do run.
func kernelRecord(tb testing.TB, i int) []byte {
	tb.Helper()
	type event map[string]string
	entry := func(name string) map[string]any {
		bins := make([]map[string]string, 40)
		for j := range bins {
			bins[j] = map[string]string{"binary_name": fmt.Sprintf("%s-image-%d", name, j), "binary_version": "6.8.0-50.51"}
		}
		return map[string]any{
			"package":            map[string]string{"name": name, "ecosystem": "Ubuntu:24.04:LTS"},
			"ranges":             []any{map[string]any{"type": "ECOSYSTEM", "events": []event{{"introduced": "0"}, {"fixed": "6.8.0-50.51"}}}},
			"ecosystem_specific": map[string]any{"binaries": bins},
		}
	}
	affected := []any{entry(fmt.Sprintf("src%d", i%100))}
	for k := range 120 {
		affected = append(affected, entry(fmt.Sprintf("linux-flavour-%d", k)))
	}
	raw, err := json.Marshal(map[string]any{
		"id": fmt.Sprintf("UBUNTU-CVE-2026-%05d", i), "modified": "2026-11-19T00:00:00Z",
		"upstream": []string{fmt.Sprintf("CVE-2026-%05d", i)}, "affected": affected,
	})
	require.NoError(tb, err)
	return raw
}

// BenchmarkApplyOSV_UbuntuKernelRecords measures the OSV fast path's apply time per 1,000 Ubuntu
// kernel-shaped records, against 60 Ubuntu images of 100 packages each. A large backlog of these
// must apply well inside the feed's 30-minute sync timeout.
func BenchmarkApplyOSV_UbuntuKernelRecords(b *testing.B) {
	st, err := store.Open(ctx, filepath.Join(b.TempDir(), "ffs.db"))
	require.NoError(b, err)
	b.Cleanup(func() { require.NoError(b, st.Close()) })
	for img := range 60 {
		pkgs := make([]model.Package, 100)
		for p := range pkgs {
			pkgs[p] = model.Package{Ecosystem: "deb", Distro: ubuntu2404, Name: fmt.Sprintf("lib%d-%d", p, img),
				Version: "1.0-1ubuntu1", SourceName: fmt.Sprintf("src%d", p), SourceVersion: "1.0-1ubuntu1"}
		}
		require.NoError(b, st.PutSBOM(ctx, fmt.Sprintf("sha256:%064d", img), []byte("{}"), pkgs))
	}
	recs := make([]osv.Changed, 1000)
	for i := range recs {
		raw := kernelRecord(b, i)
		v, err := match.ParseOSV(raw)
		require.NoError(b, err)
		hash, err := osv.AffectedHash(raw)
		require.NoError(b, err)
		_, err = st.PutOSVRecordAt(ctx, "Ubuntu", v.GetId(), v.GetModified().AsTime(), hash, raw, time.Now())
		require.NoError(b, err)
		var names []string
		for _, a := range v.GetAffected() {
			names = append(names, osv.IndexName("Ubuntu", a.GetPackage().GetName()))
		}
		require.NoError(b, st.PutOSVRecordNames(ctx, "Ubuntu", v.GetId(), names))
		recs[i] = osv.Changed{Ecosystem: "Ubuntu", ID: v.GetId(), Raw: raw}
	}
	m := osvfast.New(st)
	b.ResetTimer()
	for b.Loop() {
		deltas, err := m.ApplyOSV(ctx, recs)
		require.NoError(b, err)
		require.Len(b, deltas, len(recs))
	}
}
