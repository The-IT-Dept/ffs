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
	Owners          []string  // "Kind/Name", or a bare Name for namespaced owners only; case-insensitive
	Expires         time.Time // the rule stops matching at this instant
	VEXStatus       string    // "not_affected" | "affected" | "fixed" | "under_investigation" | ""
}

// Key returns "namespace/name", the value a finding's ExceptedBy holds.
func (r ExceptionRule) Key() string { return r.Namespace + "/" + r.Name }

// Matches reports whether r applies to f now. aliases are the other IDs of f's advisory. The rule
// must be unexpired, in f's namespace unless cluster-wide (so cluster-level owners, which have no
// namespace, only match cluster-wide rules), and have at least one criterion. Every non-empty
// criterion list must hit; entries within a list are alternatives. An owner entry matches as
// ownerMatches says.
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
		hits(r.Owners, func(o string) bool { return ownerMatches(o, f.Owner) })
}

// ownerMatches reports whether an Exception owner entry names o, ignoring case. "Kind/Name" matches
// any owner. A bare name matches only a namespaced (workload) owner: a cluster-level owner, which
// has no namespace (Cluster, ContainerRuntime, Nodes), matches only its Kind/Name form. The Nodes
// owner and the Cluster owner are both named after the cluster, so a bare cluster name must never
// except every host finding.
func ownerMatches(entry string, o model.OwnerRef) bool {
	if strings.EqualFold(entry, o.Kind+"/"+o.Name) {
		return true
	}
	return o.Namespace != "" && strings.EqualFold(entry, o.Name)
}

// hits reports whether an empty criterion list, or any entry of a non-empty one, matches.
func hits(list []string, match func(string) bool) bool {
	return len(list) == 0 || slices.ContainsFunc(list, match)
}

func equalFold(a string) func(string) bool {
	return func(b string) bool { return strings.EqualFold(a, b) }
}
