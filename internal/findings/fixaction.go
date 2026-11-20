package findings

import (
	"cmp"
	"strings"

	"github.com/google/osv-scalibr/semantic"

	"github.com/the-it-dept/ffs/internal/model"
)

// osvEcosystems maps the syft package types osv-scalibr has a version ordering for to the OSV
// ecosystem that names it. Other types compare as semver. The OS package types are here for host
// findings, whose fix action names a package version (an image finding rebuilds instead).
var osvEcosystems = map[string]string{"go-module": "Go", "npm": "npm", "python": "PyPI", "gem": "RubyGems", "rust-crate": "crates.io",
	"java-archive": "Maven", "php-composer": "Packagist", "dotnet": "NuGet", "hex": "Hex",
	"deb": "Debian", "apk": "Alpine", "rpm": "Red Hat"}

// osPackageTypes are the package types a rebuild on the distro's current packages fixes.
var osPackageTypes = map[string]bool{"deb": true, "rpm": true, "apk": true}

// fixAction returns how the finding built from vs, whose fixed versions are fixed, is cleared
// (spec §11.1), short of an image-tag upgrade, which the store derives from the Suggestion:
//   - with no fix, won't fix or no fix yet, by the fix state;
//   - with an OS package affected, a rebuild on its distro (the first OS package by name), unless
//     the finding is a host finding (host): a node has no image to rebuild;
//   - else the first package by name with a fixed version, moved to its smallest fixed version
//     above the installed one.
func fixAction(vs []verdict, fixed []string, host bool) *model.FixAction {
	state := fixState(vs)
	available := len(fixed) > 0 || state == model.FixFixed
	if !available {
		return noFix(state)
	}
	var osPkg *model.Package
	for i := range vs {
		p := &vs[i].pkg
		if osPackageTypes[p.Ecosystem] && (osPkg == nil || compareOSPackages(p, osPkg) < 0) {
			osPkg = p
		}
	}
	if osPkg != nil && !host {
		return rebuild(osPkg.Distro)
	}
	return packageAction(packages(vs))
}

// carriedFix is the action of a stored finding that has none, because it was stored before Build
// set one. A FindingPackage carries no distro, so an OS package gets a rebuild without one; a host
// finding (the Nodes owner's) gets the package action instead.
func carriedFix(c model.Finding) *model.FixAction {
	switch {
	case !c.FixAvailable:
		return noFix(c.FixState)
	case len(c.Packages) > 0 && osPackageTypes[c.Packages[0].Ecosystem] && c.Owner.Kind != model.OwnerKindNodes:
		return rebuild(nil)
	}
	return packageAction(c.Packages)
}

// noFix is the action of a finding without a fixed version.
func noFix(state model.FixState) *model.FixAction {
	if state == model.FixWontFix {
		return &model.FixAction{Kind: model.FixKindWontFix, Key: "wontfix", Label: model.FixLabelWontFix}
	}
	return &model.FixAction{Kind: model.FixKindNone, Key: "none", Label: model.FixLabelNone}
}

// compareOSPackages orders OS packages by name, then distro ID and version ID.
func compareOSPackages(a, b *model.Package) int {
	da, db := distroOf(a), distroOf(b)
	return cmp.Or(strings.Compare(a.Name, b.Name), strings.Compare(da.ID, db.ID), strings.Compare(da.VersionID, db.VersionID))
}

func distroOf(p *model.Package) model.Distro {
	if p.Distro == nil {
		return model.Distro{}
	}
	return *p.Distro
}

// rebuild is the action of rebuilding the image on d's current packages; d may be unknown (nil).
func rebuild(d *model.Distro) *model.FixAction {
	if d == nil {
		return &model.FixAction{Kind: model.FixKindRebuild, Key: "rebuild::", Label: "Rebuild"}
	}
	label := d.ID + " " + d.VersionID + " rebuild"
	if d.VersionID == "" { // a distro release without a version, such as debian testing
		label = d.ID + " rebuild"
	}
	distro := *d
	return &model.FixAction{Kind: model.FixKindRebuild, Key: "rebuild:" + d.ID + ":" + d.VersionID, Label: label, Distro: &distro}
}

// packageAction moves the first package with a fixed version (ps is sorted by name) to its smallest
// fixed version above the installed one. When no package lists one, the first package moves to
// an unnamed fixed version.
func packageAction(ps []model.FindingPackage) *model.FixAction {
	if len(ps) == 0 {
		return noFix(model.FixUnknown)
	}
	p := ps[0]
	for _, q := range ps {
		if len(q.Fixed) > 0 {
			p = q
			break
		}
	}
	to := minFixed(p.Ecosystem, p.Installed, p.Fixed)
	label := p.Name + " " + p.Installed + " → " + cmp.Or(to, "fixed version")
	return &model.FixAction{Kind: model.FixKindPackage, Key: "package:" + p.Ecosystem + ":" + p.Name + ":" + p.Installed + ":" + to,
		Label: label, Package: p.Name, Ecosystem: p.Ecosystem, From: p.Installed, To: to}
}

// minFixed returns the smallest fixed version greater than installed, else the smallest fixed
// version; "" when fixed is empty. A Go toolchain version is spelled as installed is, so the Go
// standard library's go1.22.3 moves to go1.22.5, not to vulndb's 1.22.5.
func minFixed(ecosystem, installed string, fixed []string) string {
	var above, lowest string
	for _, v := range fixed {
		if v == "" {
			continue
		}
		if lowest == "" || compareVersions(ecosystem, v, lowest) < 0 {
			lowest = v
		}
		if compareVersions(ecosystem, v, installed) > 0 && (above == "" || compareVersions(ecosystem, v, above) < 0) {
			above = v
		}
	}
	to := cmp.Or(above, lowest)
	if ecosystem == goModule && to != "" && strings.HasPrefix(installed, goPrefix) && !strings.HasPrefix(to, goPrefix) {
		to = goPrefix + to
	}
	return to
}

const (
	goModule = "go-module" // the syft type of Go modules and the Go standard library
	goPrefix = "go"        // starts a Go toolchain version, which syft reports for the standard library
)

// compareVersions orders two versions of a package type: by its OSV ecosystem's rules when it has
// one and both parse, else as semver, else as strings. A Go toolchain version ("go1.22.3", the Go
// standard library's) compares without its "go", as Go vulndb's fixed versions are written.
func compareVersions(ecosystem, a, b string) int {
	eco, ok := osvEcosystems[ecosystem]
	if ecosystem == goModule {
		a, b = strings.TrimPrefix(a, goPrefix), strings.TrimPrefix(b, goPrefix)
	}
	if ok {
		va, errA := semantic.Parse(a, eco)
		vb, errB := semantic.Parse(b, eco)
		if errA == nil && errB == nil {
			if c, err := va.Compare(vb); err == nil {
				return c
			}
			return strings.Compare(a, b)
		}
	}
	if c, err := semantic.ParseSemverVersion(a).Compare(semantic.ParseSemverVersion(b)); err == nil {
		return c
	}
	return strings.Compare(a, b)
}
