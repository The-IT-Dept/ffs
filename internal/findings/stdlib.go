package findings

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/google/osv-scalibr/semantic"

	"github.com/the-it-dept/ffs/internal/model"
)

// StdlibGroup is the Go standard library findings of one Go version, shown as one item in alerts
// and the dashboard (spec §6.5). Grouping is presentation only: each finding keeps its fingerprint.
type StdlibGroup struct {
	Installed   string // "go1.22.3"
	AdvisoryIDs []string
	FixedIn     string // the lowest Go version, on one branch, fixing every advisory that has a fix; "" when none has, or none at or after the installed branch
	Highest     model.Priority
}

// GroupStdlib splits fs into Go standard library groups, one per installed Go version (the first
// package's) and sorted by it, and the other findings in their original order.
func GroupStdlib(fs []model.Finding) (groups []StdlibGroup, rest []model.Finding) {
	byVersion := map[string]*StdlibGroup{}
	fixes := map[string][][]string{} // installed version → the fixed versions of each advisory
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
		if fixed := fixedAt(f.Packages, v); len(fixed) > 0 {
			fixes[v] = append(fixes[v], fixed)
		}
	}
	for v, g := range byVersion {
		g.AdvisoryIDs = sortedSet(g.AdvisoryIDs)
		g.FixedIn = stdlibFixedIn(fixes[v], v)
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

// fixedAt returns the fixed versions listed on the packages at the installed version.
func fixedAt(ps []model.FindingPackage, installed string) []string {
	var out []string
	for _, p := range ps {
		if p.Installed == installed {
			out = append(out, p.Fixed...)
		}
	}
	return out
}

// stdlibFixedIn returns the lowest Go version, on one release branch, that fixes every advisory of
// fixes (each advisory's fixed versions, one per release branch it was fixed on), or "" when there
// are none. The branch comes first: the installed version's branch when every advisory is fixed on it,
// else the lowest later branch on which each advisory is fixed, by a fix on that branch or by fixes
// on earlier branches only. On that branch it takes the highest of each advisory's lowest fix, so
// it never names a version on a branch where another advisory is still unfixed. When no branch at
// or after the installed one has a fix (every listed fix is on an earlier branch: bad or partial
// fix data) it returns "", never a version below the installed branch. Versions that are not Go
// versions fall back to the highest of each advisory's lowest fix.
func stdlibFixedIn(fixes [][]string, installed string) string {
	if len(fixes) == 0 {
		return ""
	}
	from, ok := goBranchOf(installed)
	if !ok {
		return highestLowestFix(fixes)
	}
	branches := []goBranch{from}
	for _, fs := range fixes {
		for _, v := range fs {
			b, ok := goBranchOf(v)
			if !ok {
				return highestLowestFix(fixes)
			}
			if b.compare(from) > 0 && !slices.Contains(branches, b) {
				branches = append(branches, b)
			}
		}
	}
	slices.SortFunc(branches, goBranch.compare)
	for _, b := range branches {
		if v, ok := fixedOnBranch(fixes, b); ok {
			return v
		}
	}
	return "" // every fix is on a branch below the installed one
}

// fixedOnBranch returns the lowest version on branch b that fixes every advisory of fixes, and
// whether b has one: an advisory with a fix on b needs its lowest fix there, one fixed only on
// earlier branches needs nothing, and one fixed on a later branch but not on b leaves b unfixed.
func fixedOnBranch(fixes [][]string, b goBranch) (string, bool) {
	var need string
	for _, fs := range fixes {
		var lowest string
		later := false
		for _, v := range fs {
			vb, _ := goBranchOf(v)
			switch c := vb.compare(b); {
			case c == 0 && (lowest == "" || compareGo(v, lowest) < 0):
				lowest = v
			case c > 0:
				later = true
			}
		}
		switch {
		case lowest != "":
			if need == "" || compareGo(lowest, need) > 0 {
				need = lowest
			}
		case later:
			return "", false
		}
	}
	return need, need != ""
}

// highestLowestFix is the highest of each advisory's lowest fixed version.
func highestLowestFix(fixes [][]string) string {
	var out string
	for _, fs := range fixes {
		var lowest string
		for _, v := range fs {
			if lowest == "" || compareGo(v, lowest) < 0 {
				lowest = v
			}
		}
		if out == "" || compareGo(lowest, out) > 0 {
			out = lowest
		}
	}
	return out
}

// goBranch is a Go release branch: 1.22 for go1.22.3.
type goBranch struct{ major, minor int }

func (a goBranch) compare(b goBranch) int {
	return cmp.Or(cmp.Compare(a.major, b.major), cmp.Compare(a.minor, b.minor))
}

// goBranchOf returns the release branch of a Go version such as "go1.22.3", "1.22.3" or "1.21.0-rc.2".
func goBranchOf(v string) (goBranch, bool) {
	parts := strings.SplitN(strings.TrimPrefix(strings.TrimPrefix(v, "go"), "v"), ".", 3)
	if len(parts) < 2 {
		return goBranch{}, false
	}
	minor, _, _ := strings.Cut(parts[1], "-")
	maj, err1 := strconv.Atoi(parts[0])
	mnr, err2 := strconv.Atoi(minor)
	if err1 != nil || err2 != nil {
		return goBranch{}, false
	}
	return goBranch{maj, mnr}, true
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
