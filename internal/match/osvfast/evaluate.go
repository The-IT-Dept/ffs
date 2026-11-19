package osvfast

import (
	"cmp"
	"regexp"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/semantic"
	"github.com/ossf/osv-schema/bindings/go/osvschema"

	"github.com/the-it-dept/ffs/internal/feeds/osv"
	"github.com/the-it-dept/ffs/internal/match/osvrange"
	"github.com/the-it-dept/ffs/internal/model"
)

// Evaluate reports whether version is affected by the affected entry a, comparing versions the way
// a's ecosystem does (osv-scalibr semantic). Its ECOSYSTEM and SEMVER ranges are walked with
// osvrange.Evaluate (GIT ranges are ignored), and a version listed in a.Versions is affected too.
// fixed holds the smallest fixed version above version from the ranges that affect it (from any
// range when only the versions list does); fs is FixFixed with a fixed version, else FixNotFixed.
// An unaffected version gives an empty fs and no fixed versions.
// The error wraps semantic.ErrUnsupportedEcosystem for an ecosystem semantic cannot compare, or
// reports a version that does not parse in it.
func Evaluate(a *osvschema.Affected, version string) (affected bool, fs model.FixState, fixed []string, err error) {
	eco := a.GetPackage().GetEcosystem()
	vs := versions{}
	if err := vs.parse(version, eco); err != nil {
		return false, "", nil, err
	}

	var hit, other []string // smallest fixed versions of the affecting and the other ranges
	for _, r := range a.GetRanges() {
		if t := r.GetType(); t != osvschema.Range_ECOSYSTEM && t != osvschema.Range_SEMVER {
			continue
		}
		events := make([]osvrange.Event, 0, len(r.GetEvents()))
		for _, e := range r.GetEvents() {
			ev := osvrange.Event{Introduced: e.GetIntroduced(), Fixed: e.GetFixed(), LastAffected: e.GetLastAffected()}
			// osvrange compares an event by its first set field, except an introduced "0".
			if s := cmp.Or(ev.Introduced, ev.Fixed, ev.LastAffected); s != "" && ev.Introduced != "0" {
				if err := vs.parse(s, eco); err != nil {
					return false, "", nil, err
				}
			}
			events = append(events, ev)
		}
		res := osvrange.Evaluate(events, vs.compare, version)
		if res.Affected {
			affected = true
			hit = append(hit, res.Fixed...)
		} else {
			other = append(other, res.Fixed...)
		}
	}
	if !affected {
		if !slices.Contains(a.GetVersions(), version) {
			return false, "", nil, nil
		}
		hit = other
	}
	if len(hit) > 0 {
		return true, model.FixFixed, []string{slices.MinFunc(hit, vs.compare)}, nil
	}
	return true, model.FixNotFixed, nil, nil
}

// versions holds the parsed form of every version an evaluation compares.
type versions map[string]semantic.Version

func (vs versions) parse(s, eco string) error {
	if _, ok := vs[s]; ok {
		return nil
	}
	v, err := semantic.Parse(s, eco)
	if err != nil {
		return err
	}
	vs[s] = v
	return nil
}

// compare compares two versions already parsed by parse.
func (vs versions) compare(a, b string) int {
	// Every version was parsed for the same ecosystem, so Compare cannot report a type mismatch.
	c, _ := vs[a].Compare(vs[b])
	return c
}

var goToolchain = regexp.MustCompile(`^(\d+)\.(\d+)(?:\.(\d+))?(?:(rc|beta)(\d+))?$`)

// InstalledVersion returns the version of p to evaluate against OSV ranges, or false when p has
// none usable.
//   - Go standard library ("go1.22.3"): the toolchain version as semver, "go1.22" → "1.22.0" and
//     "go1.22rc1" → "1.22.0-rc.1".
//   - Go modules: the version without its "v"; "(devel)" and empty are unusable.
//   - Packages of a source-join ecosystem (Debian, Ubuntu, Alpine, Wolfi, Chainguard): the source
//     version when known, since those records name source packages.
//   - rpm: "epoch:version" when the package has an epoch its version does not carry already.
func InstalledVersion(p model.Package) (string, bool) {
	switch {
	case p.GoStdlib || p.Ecosystem == goModule && p.Name == goStdlib:
		return goStdlibVersion(p.Version)
	case p.Ecosystem == goModule:
		if p.Version == "" || p.Version == "(devel)" {
			return "", false
		}
		v := strings.TrimPrefix(p.Version, "v")
		return v, v != ""
	}
	if eco, ok := osv.PackageEcosystem(p); ok && osv.SourceJoin(osv.BucketOf(eco)) && p.SourceVersion != "" {
		return p.SourceVersion, true
	}
	v := p.Version
	if p.Ecosystem == "rpm" && p.Epoch != "" && !hasEpoch(v) {
		v = p.Epoch + ":" + v
	}
	return v, v != ""
}

// goStdlibVersion turns a Go toolchain version ("go1.22.3", "go1.22", "go1.22rc1", possibly with a
// " X:…" or "+…" suffix) into the semver form Go vulndb ranges use.
func goStdlibVersion(v string) (string, bool) {
	v = strings.TrimPrefix(v, "go")
	if i := strings.IndexAny(v, " +-"); i >= 0 {
		v = v[:i]
	}
	m := goToolchain.FindStringSubmatch(v)
	if m == nil {
		return "", false
	}
	patch := m[3]
	if patch == "" {
		patch = "0"
	}
	out := m[1] + "." + m[2] + "." + patch
	if m[4] != "" {
		out += "-" + m[4] + "." + m[5]
	}
	return out, true
}

// hasEpoch reports whether an rpm or deb version starts with a numeric "N:" epoch.
func hasEpoch(v string) bool {
	e, _, ok := strings.Cut(v, ":")
	if !ok || e == "" {
		return false
	}
	return strings.Trim(e, "0123456789") == ""
}

// epochMismatch reports whether the installed version and one of a's event versions disagree on
// having an epoch. semantic reads a missing epoch as 0, which grype does not, so such an entry is
// left to grype. The introduced "0" sentinel is not a version and is not compared.
func epochMismatch(a *osvschema.Affected, installed string) bool {
	has := hasEpoch(installed)
	for _, r := range a.GetRanges() {
		for _, e := range r.GetEvents() {
			for _, s := range []string{e.GetIntroduced(), e.GetFixed(), e.GetLastAffected()} {
				if s != "" && s != "0" && hasEpoch(s) != has {
					return true
				}
			}
		}
	}
	return false
}

// vendorSeverity returns the severity the record's source assigns to the affected entry a and
// where it comes from: a Debian urgency, an Ubuntu priority or a GHSA rating. A rating that does
// not parse to a severity ("not yet assigned", "end-of-life", "untriaged", empty) gives none.
func vendorSeverity(v *osvschema.Vulnerability, a *osvschema.Affected, bucket string) (model.Severity, string) {
	var rating, source string
	switch {
	case bucket == bucketDebian:
		rating, source = a.GetEcosystemSpecific().GetFields()["urgency"].GetStringValue(), "debian"
	case strings.HasPrefix(v.GetId(), "GHSA-"):
		rating, source = v.GetDatabaseSpecific().GetFields()["severity"].GetStringValue(), "ghsa"
	default:
		for _, s := range v.GetSeverity() {
			if s.GetType() == osvschema.Severity_Ubuntu {
				rating, source = s.GetScore(), "ubuntu"
				break
			}
		}
	}
	if sev := model.ParseSeverity(rating); sev != model.SeverityUnknown {
		return sev, source
	}
	return model.SeverityUnknown, ""
}
