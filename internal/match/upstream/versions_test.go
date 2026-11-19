package upstream_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/match/upstream"
	"github.com/the-it-dept/ffs/internal/model"
)

func TestCompareVersions(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"8.3.14", "8.3.15", -1},
		{"1.2", "1.2.0", 0},
		{"1.1.1w", "1.1.1", 1},
		{"1.1.1w", "1.1.1x", -1},
		{"3.0.0-alpha1", "3.0.0", -1},
		{"3.0.0rc2", "3.0.0RC1", 1},
		{"3.14.0a1", "3.14.0a3", -1},
		{"v20.11.1", "20.11.1", 0},
		{"10.0", "9.9", 1},
		{"1.0.1", "1.0rc1", 1},
		{"8.3", "8.3.14", -1},
		{"007", "7", 0},
		{"123456789012345678901234567890", "123456789012345678901234567891", -1},
	} {
		t.Run(fmt.Sprintf("%s_vs_%s", tc.a, tc.b), func(t *testing.T) {
			require.Equal(t, tc.want, upstream.CompareVersions(tc.a, tc.b))
			require.Equal(t, -tc.want, upstream.CompareVersions(tc.b, tc.a))
		})
	}
}

func TestCNARanges_Affects(t *testing.T) {
	type want struct {
		affected bool
		fs       model.FixState
		fixed    []string
	}
	yes := func(fs model.FixState, fixed ...string) want { return want{true, fs, fixed} }
	no := want{}
	affected := func(vs ...upstream.CNAVersion) upstream.CNARanges {
		for i := range vs {
			if vs[i].Status == "" {
				vs[i].Status = "affected"
			}
		}
		return upstream.CNARanges{DefaultStatus: "unaffected", Versions: vs}
	}

	for _, tc := range []struct {
		name    string
		r       upstream.CNARanges
		version string
		want    want
	}{
		{"wildcard lower bound", affected(upstream.CNAVersion{Version: "8.3.*", LessThan: "8.3.15"}), "8.3.14", yes(model.FixFixed, "8.3.15")},
		{"wildcard lower bound at fix", affected(upstream.CNAVersion{Version: "8.3.*", LessThan: "8.3.15"}), "8.3.15", no},
		{"wildcard lower bound below", affected(upstream.CNAVersion{Version: "8.3.*", LessThan: "8.3.15"}), "8.2.99", no},
		{"plain lower bound", affected(upstream.CNAVersion{Version: "20.0", LessThan: "20.11.1"}), "20.11.0", yes(model.FixFixed, "20.11.1")},
		{"wildcard upper bound", affected(upstream.CNAVersion{Version: "4.0", LessThan: "4.*"}), "4.9.1", yes(model.FixUnknown)},
		{"wildcard upper bound above", affected(upstream.CNAVersion{Version: "4.0", LessThan: "4.*"}), "5.0.0", no},
		{"lessThanOrEqual", affected(upstream.CNAVersion{Version: "*", LessThanOrEqual: "8.0.36"}), "8.0.36", yes(model.FixFixed)},
		{"lessThanOrEqual above", affected(upstream.CNAVersion{Version: "*", LessThanOrEqual: "8.0.36"}), "8.0.37", no},
		{"zero lower bound", affected(upstream.CNAVersion{Version: "0", LessThan: "3.12.9"}), "3.11.10", yes(model.FixFixed, "3.12.9")},
		{"changes before fix", affected(upstream.CNAVersion{Version: "1.5.13", LessThan: "*",
			Changes: []upstream.CNAChange{{At: "1.26.2", Status: "unaffected"}}}), "1.26.1", yes(model.FixFixed, "1.26.2")},
		{"changes at fix", affected(upstream.CNAVersion{Version: "1.5.13", LessThan: "*",
			Changes: []upstream.CNAChange{{At: "1.26.2", Status: "unaffected"}}}), "1.26.2", no},
		{"changes back to affected", affected(upstream.CNAVersion{Version: "1.5.13", LessThan: "*",
			Changes: []upstream.CNAChange{{At: "1.27.0", Status: "affected"}, {At: "1.26.2", Status: "unaffected"}}}), "1.27.1", yes(model.FixUnknown)},
		{"open upper bound", affected(upstream.CNAVersion{Version: "1.5.13", LessThan: "*"}), "1.4.0", no},
		{"github range", affected(upstream.CNAVersion{Version: ">= 7.4.0, < 7.4.2"}), "7.4.1", yes(model.FixFixed, "7.4.2")},
		{"github range at fix", affected(upstream.CNAVersion{Version: ">= 7.4.0, < 7.4.2"}), "7.4.2", no},
		{"github range below", affected(upstream.CNAVersion{Version: ">= 7.4.0, < 7.4.2"}), "7.2.9", no},
		{"github upper only", affected(upstream.CNAVersion{Version: "< 6.2.17"}), "6.0.20", yes(model.FixFixed, "6.2.17")},
		{"github bad comparator", affected(upstream.CNAVersion{Version: ">= 7.4.0, ~7.4"}), "7.4.1", no},
		{"exact version", affected(upstream.CNAVersion{Version: "2.4.60"}), "2.4.60", yes(model.FixUnknown)},
		{"exact version other", affected(upstream.CNAVersion{Version: "2.4.60"}), "2.4.61", no},
		{"placeholder alone", affected(upstream.CNAVersion{Version: "n/a"}), "1.0", no},
		{"wildcard alone", affected(upstream.CNAVersion{Version: "8.3.*"}), "8.3.9", yes(model.FixUnknown)},
		{"git version type", affected(upstream.CNAVersion{Version: "c0efd232", LessThan: "95edf13a", VersionType: "git"}), "1.0", no},
		{"unaffected entry", upstream.CNARanges{Versions: []upstream.CNAVersion{{Version: "0", LessThan: "9.9", Status: "unaffected"}}}, "1.0", no},
		{"default status alone", upstream.CNARanges{DefaultStatus: "affected"}, "1.0", no},
		{"empty version", affected(upstream.CNAVersion{Version: "0", LessThan: "9.9"}), "", no},
		{"smallest fix of two ranges", affected(upstream.CNAVersion{Version: "0", LessThan: "2.0"}, upstream.CNAVersion{Version: "1.0", LessThan: "1.5"}),
			"1.2", yes(model.FixFixed, "1.5")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			affected, fs, fixed := tc.r.Affects(tc.version)
			require.Equal(t, tc.want, want{affected, fs, fixed})
		})
	}
}
