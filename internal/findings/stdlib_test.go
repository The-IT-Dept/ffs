package findings

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

func TestGroupStdlib(t *testing.T) {
	sf := func(id, installed string, p model.Priority, fixed ...string) model.Finding {
		return model.Finding{Fingerprint: "fp-" + id, AdvisoryID: id, GoStdlib: true, Priority: p,
			Packages: []model.FindingPackage{{Name: "stdlib", Ecosystem: "go-module", Installed: installed,
				Path: "/usr/local/bin/tool", Fixed: fixed}}}
	}
	openssl := model.Finding{Fingerprint: "fp-openssl", AdvisoryID: "CVE-2026-0001", Priority: model.PriorityHigh,
		Packages: []model.FindingPackage{{Name: "openssl", Ecosystem: "deb", Installed: "3.0.13-1", Fixed: []string{"3.0.15-1"}}}}

	groups, rest := GroupStdlib([]model.Finding{
		// The smallest fixed version of an advisory counts: 1.23.0 must not become FixedIn.
		sf("GO-2024-0003", "go1.22.3", model.PriorityMedium, "1.22.5", "1.23.0"),
		openssl,
		sf("GO-2024-0001", "go1.22.3", model.PriorityHigh, "1.22.12"),
		sf("GO-2023-0009", "go1.21.0", model.PriorityLow, "1.21.4"),
		sf("GO-2024-0002", "go1.22.3", model.PriorityMedium, "1.22.7"),
	})
	require.Len(t, groups, 2)
	assert.Equal(t, StdlibGroup{Installed: "go1.21.0", AdvisoryIDs: []string{"GO-2023-0009"}, FixedIn: "1.21.4",
		Highest: model.PriorityLow}, groups[0])
	assert.Equal(t, StdlibGroup{Installed: "go1.22.3", AdvisoryIDs: []string{"GO-2024-0001", "GO-2024-0002", "GO-2024-0003"},
		FixedIn: "1.22.12", Highest: model.PriorityHigh}, groups[1]) // 1.22.12 beats 1.22.7: semantic, not lexical
	assert.Equal(t, []model.Finding{openssl}, rest)
	assert.Equal(t, "Go 1.22.3 standard library: 3 advisories, fixed in Go 1.22.12", groups[1].Title())
	assert.Equal(t, "Go 1.21.0 standard library: 1 advisory, fixed in Go 1.21.4", groups[0].Title())

	unfixed, rest := GroupStdlib([]model.Finding{
		sf("GO-2024-0001", "go1.22.3", model.PriorityMedium),
		sf("GO-2024-0002", "go1.22.3", model.PriorityMedium),
		sf("GO-2024-0003", "go1.22.3", model.PriorityMedium),
	})
	assert.Empty(t, rest)
	require.Len(t, unfixed, 1)
	assert.Empty(t, unfixed[0].FixedIn)
	assert.Equal(t, "Go 1.22.3 standard library: 3 advisories, no fix yet", unfixed[0].Title())

	ordered, _ := GroupStdlib([]model.Finding{sf("GO-1", "go1.10.0", model.PriorityLow), sf("GO-2", "go1.9.7", model.PriorityLow)})
	assert.Equal(t, []string{"go1.9.7", "go1.10.0"}, []string{ordered[0].Installed, ordered[1].Installed})
}

func TestGroupStdlib_FixedInChoosesTheBranchFirst(t *testing.T) {
	sf := func(id string, fixed ...string) model.Finding {
		return model.Finding{Fingerprint: "fp-" + id, AdvisoryID: id, GoStdlib: true, Priority: model.PriorityMedium,
			Packages: []model.FindingPackage{{Name: "stdlib", Ecosystem: "go-module", Installed: "go1.22.3",
				Path: "/usr/local/bin/tool", Fixed: fixed}}}
	}
	cases := []struct {
		name string
		fs   []model.Finding
		want string
	}{
		{"every advisory fixed on the installed branch: the highest fix there",
			[]model.Finding{sf("GO-1", "1.22.5", "1.23.1"), sf("GO-2", "1.22.12", "1.23.6")}, "1.22.12"},
		// The highest of each advisory's lowest fix is 1.23.2, which leaves GO-1 unfixed (1.23.6 fixes it).
		{"one advisory unfixed on the installed branch: the next branch, its highest fix",
			[]model.Finding{sf("GO-1", "1.22.12", "1.23.6"), sf("GO-2", "1.23.2")}, "1.23.6"},
		{"a branch the other advisory was not fixed on is skipped",
			[]model.Finding{sf("GO-1", "1.22.5", "1.24.1"), sf("GO-2", "1.23.2")}, "1.24.1"},
		{"an advisory fixed only on earlier branches needs nothing on a later one",
			[]model.Finding{sf("GO-1", "1.22.5"), sf("GO-2", "1.23.2")}, "1.23.2"},
		{"advisories with no fix do not count",
			[]model.Finding{sf("GO-1", "1.22.7"), sf("GO-2")}, "1.22.7"},
		{"release candidates parse",
			[]model.Finding{sf("GO-1", "1.23.0-rc.2"), sf("GO-2", "1.23.1")}, "1.23.1"},
		{"no fixes", []model.Finding{sf("GO-1"), sf("GO-2")}, ""},
		// W25: go1.22.3 with fixes on 1.21.x only (bad or partial fix data) names no fix below its branch.
		{"every fix on an earlier branch: none is named",
			[]model.Finding{sf("GO-1", "1.21.9"), sf("GO-2", "1.21.12", "1.20.14")}, ""},
		{"an advisory fixed only on an earlier branch needs nothing on the installed one",
			[]model.Finding{sf("GO-1", "1.21.9"), sf("GO-2", "1.22.7")}, "1.22.7"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			groups, rest := GroupStdlib(c.fs)
			require.Empty(t, rest)
			require.Len(t, groups, 1)
			assert.Equal(t, c.want, groups[0].FixedIn)
		})
	}

	// A version that is not a Go version keeps the highest of each advisory's lowest fix.
	odd := sf("GO-1", "1.22.5")
	odd.Packages[0].Installed = "devel"
	groups, _ := GroupStdlib([]model.Finding{odd, func() model.Finding {
		f := sf("GO-2", "1.23.2", "1.22.9")
		f.Packages[0].Installed = "devel"
		return f
	}()})
	require.Len(t, groups, 1)
	assert.Equal(t, "1.22.9", groups[0].FixedIn)
}
