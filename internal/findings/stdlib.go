package findings

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/semantic"

	"github.com/the-it-dept/ffs/internal/model"
)

// StdlibGroup is the Go standard library findings of one Go version, shown as one item in alerts
// and the dashboard (spec §6.5). Grouping is presentation only: each finding keeps its fingerprint.
type StdlibGroup struct {
	Installed   string // "go1.22.3"
	AdvisoryIDs []string
	FixedIn     string // the lowest Go version that fixes every advisory that has a fix; "" when none has
	Highest     model.Priority
}

// GroupStdlib splits fs into Go standard library groups, one per installed Go version (the first
// package's) and sorted by it, and the other findings in their original order.
func GroupStdlib(fs []model.Finding) (groups []StdlibGroup, rest []model.Finding) {
	byVersion := map[string]*StdlibGroup{}
	for _, f := range fs {
		if !f.GoStdlib || len(f.Packages) == 0 {
			rest = append(rest, f)
			continue
		}
		v := f.Packages[0].Installed
		g := byVersion[v]
		if g == nil {
			g = &StdlibGroup{Installed: v}
			byVersion[v] = g
		}
		g.AdvisoryIDs = append(g.AdvisoryIDs, f.AdvisoryID)
		g.Highest = max(g.Highest, f.Priority)
		if fix := smallestFix(f.Packages, v); fix != "" && (g.FixedIn == "" || compareGo(fix, g.FixedIn) > 0) {
			g.FixedIn = fix
		}
	}
	for _, g := range byVersion {
		g.AdvisoryIDs = sortedSet(g.AdvisoryIDs)
		groups = append(groups, *g)
	}
	slices.SortFunc(groups, func(a, b StdlibGroup) int {
		return cmp.Or(compareGo(strings.TrimPrefix(a.Installed, "go"), strings.TrimPrefix(b.Installed, "go")),
			strings.Compare(a.Installed, b.Installed))
	})
	return groups, rest
}

// Title reads "Go 1.22.3 standard library: 3 advisories, fixed in Go 1.22.12", or ends
// "no fix yet" when no advisory has a fixed version.
func (g StdlibGroup) Title() string {
	n := fmt.Sprintf("%d advisories", len(g.AdvisoryIDs))
	if len(g.AdvisoryIDs) == 1 {
		n = "1 advisory"
	}
	fix := "no fix yet"
	if g.FixedIn != "" {
		fix = "fixed in Go " + g.FixedIn
	}
	return fmt.Sprintf("Go %s standard library: %s, %s", strings.TrimPrefix(g.Installed, "go"), n, fix)
}

// smallestFix returns the lowest fixed version listed on the packages at the installed version.
func smallestFix(ps []model.FindingPackage, installed string) string {
	var fix string
	for _, p := range ps {
		if p.Installed != installed {
			continue
		}
		for _, v := range p.Fixed {
			if fix == "" || compareGo(v, fix) < 0 {
				fix = v
			}
		}
	}
	return fix
}

// compareGo compares two Go versions the way Go vulndb does, falling back to the strings.
func compareGo(a, b string) int {
	va, err := semantic.Parse(a, "Go")
	if err != nil {
		return strings.Compare(a, b)
	}
	vb, err := semantic.Parse(b, "Go")
	if err != nil {
		return strings.Compare(a, b)
	}
	c, err := va.Compare(vb)
	if err != nil {
		return strings.Compare(a, b)
	}
	return c
}
