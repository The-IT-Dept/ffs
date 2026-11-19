package findings

import (
	"path"
	"slices"
	"strings"
	"time"

	"github.com/the-it-dept/ffs/internal/model"
)

// ExceptionRule is the matching part of an Exception (spec §6.8).
type ExceptionRule struct {
	Namespace, Name string
	ClusterWide     bool      // the Exception lives in the ffs install namespace
	AdvisoryIDs     []string  // canonical IDs (Task 22 resolves aliases before caching)
	Packages        []string  // package names
	ImageRepoGlobs  []string  // path.Match globs over the normalised repo
	Owners          []string  // owner Name, or "Kind/Name"; case-insensitive
	Expires         time.Time // the rule stops matching at this instant
	VEXStatus       string    // "not_affected" | "affected" | "fixed" | "under_investigation" | ""
}

// Key returns "namespace/name", the value a finding's ExceptedBy holds.
func (r ExceptionRule) Key() string { return r.Namespace + "/" + r.Name }

// Matches reports whether r applies to f now. aliases are the other IDs of f's advisory. The rule
// must be unexpired, in f's namespace unless cluster-wide (so cluster-level owners, which have no
// namespace, only match cluster-wide rules), and have at least one criterion. Every non-empty
// criterion list must hit; entries within a list are alternatives.
func (r ExceptionRule) Matches(f model.Finding, aliases []string, now time.Time) bool {
	if !now.Before(r.Expires) {
		return false
	}
	if !r.ClusterWide && r.Namespace != f.Owner.Namespace {
		return false
	}
	if len(r.AdvisoryIDs) == 0 && len(r.Packages) == 0 && len(r.ImageRepoGlobs) == 0 && len(r.Owners) == 0 {
		return false
	}
	ids := append([]string{f.AdvisoryID}, aliases...)
	return hits(r.AdvisoryIDs, func(id string) bool { return slices.ContainsFunc(ids, equalFold(id)) }) &&
		hits(r.Packages, func(name string) bool {
			return slices.ContainsFunc(f.Packages, func(p model.FindingPackage) bool { return p.Name == name })
		}) &&
		hits(r.ImageRepoGlobs, func(glob string) bool {
			ok, err := path.Match(glob, f.ImageRepo)
			return err == nil && ok
		}) &&
		hits(r.Owners, func(o string) bool {
			return strings.EqualFold(o, f.Owner.Name) || strings.EqualFold(o, f.Owner.Kind+"/"+f.Owner.Name)
		})
}

// hits reports whether an empty criterion list, or any entry of a non-empty one, matches.
func hits(list []string, match func(string) bool) bool {
	return len(list) == 0 || slices.ContainsFunc(list, match)
}

func equalFold(a string) func(string) bool {
	return func(b string) bool { return strings.EqualFold(a, b) }
}
