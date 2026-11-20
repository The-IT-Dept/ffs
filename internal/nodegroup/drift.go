package nodegroup

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/semantic"

	"github.com/the-it-dept/ffs/internal/model"
)

// semanticEcosystems maps the package ecosystems whose versions ffs compares to osv-scalibr
// semantic ecosystems.
var semanticEcosystems = map[string]string{"deb": "Debian", "rpm": "Red Hat", "apk": "Alpine", "go-module": "Go"}

// compareVersions compares two versions of one package ecosystem. It is false when the ecosystem
// is not compared or a version does not parse.
func compareVersions(ecosystem, a, b string) (int, bool) {
	eco, ok := semanticEcosystems[ecosystem]
	if !ok {
		return 0, false
	}
	va, err := semantic.Parse(a, eco)
	if err != nil {
		return 0, false
	}
	vb, err := semantic.Parse(b, eco)
	if err != nil {
		return 0, false
	}
	c, err := va.Compare(vb)
	if err != nil {
		return 0, false
	}
	return c, true
}

// packageKey identifies a package across two groups.
type packageKey struct{ ecosystem, name, arch string }

func comparePackageKeys(a, b packageKey) int {
	return cmp.Or(strings.Compare(a.ecosystem, b.ecosystem), strings.Compare(a.name, b.name), strings.Compare(a.arch, b.arch))
}

// Drift is the difference between two node groups, read as "to compared with from".
//
// Fields compare the kernel release, OS image, container runtime, kubelet and, when both groups
// have one, the distro. Packages compare only when both groups are agent groups and both package
// slices are non-nil (nil means no stored SBOM). Packages are keyed by (ecosystem, name, arch); a
// key held at several versions is represented by its highest. Kernel packages are left out when
// the kernel release differs, because the kernel field already reports them.
func Drift(from, to model.NodeGroup, fromPkgs, toPkgs []model.Package) model.NodeDrift {
	d := model.NodeDrift{From: from.ID, To: to.ID, Fields: fieldDrift(from, to)}
	if from.Kind != model.NodeGroupAgent || to.Kind != model.NodeGroupAgent || fromPkgs == nil || toPkgs == nil {
		return d
	}
	d.PackagesCompared = true
	skipKernel := from.KernelRelease != to.KernelRelease
	fromVersions, toVersions := versionsByKey(fromPkgs, skipKernel), versionsByKey(toPkgs, skipKernel)

	var onlyFrom, onlyTo, changed []packageKey
	for k, fv := range fromVersions {
		switch tv, ok := toVersions[k]; {
		case !ok:
			onlyFrom = append(onlyFrom, k)
		case tv != fv:
			changed = append(changed, k)
		}
	}
	for k := range toVersions {
		if _, ok := fromVersions[k]; !ok {
			onlyTo = append(onlyTo, k)
		}
	}
	for _, keys := range [][]packageKey{onlyFrom, onlyTo, changed} {
		slices.SortFunc(keys, comparePackageKeys)
	}

	for _, k := range onlyFrom {
		d.OnlyFrom = append(d.OnlyFrom, model.DriftPackage{Ecosystem: k.ecosystem, Name: k.name, Version: fromVersions[k], Arch: k.arch})
	}
	for _, k := range onlyTo {
		d.OnlyTo = append(d.OnlyTo, model.DriftPackage{Ecosystem: k.ecosystem, Name: k.name, Version: toVersions[k], Arch: k.arch})
	}
	for _, k := range changed {
		v := model.VersionDrift{Ecosystem: k.ecosystem, Name: k.name, Arch: k.arch, From: fromVersions[k], To: toVersions[k]}
		if c, ok := compareVersions(k.ecosystem, v.To, v.From); ok && c > 0 {
			v.Newer = "to"
			d.NewerInTo++
		} else if ok && c < 0 {
			v.Newer = "from"
			d.NewerInFrom++
		}
		d.Changed = append(d.Changed, v)
	}
	return d
}

// fieldDrift lists the node fields that differ, in summary order.
func fieldDrift(from, to model.NodeGroup) []model.FieldDrift {
	var fields []model.FieldDrift
	add := func(field, f, t string) {
		if f != t {
			fields = append(fields, model.FieldDrift{Field: field, From: f, To: t})
		}
	}
	add("kernel", from.KernelRelease, to.KernelRelease)
	add("osImage", from.OSImage, to.OSImage)
	add("containerRuntime", from.ContainerRuntimeVersion, to.ContainerRuntimeVersion)
	add("kubelet", from.KubeletVersion, to.KubeletVersion)
	if from.Distro != nil && to.Distro != nil {
		add("distro", distroString(from.Distro), distroString(to.Distro))
	}
	return fields
}

func distroString(d *model.Distro) string {
	return strings.TrimSpace(d.ID + " " + d.VersionID)
}

// versionsByKey maps each package key to the version findings would show for it, keeping the
// highest when a key is held at several versions (a Go module embedded in several binaries).
func versionsByKey(pkgs []model.Package, skipKernel bool) map[packageKey]string {
	out := make(map[packageKey]string, len(pkgs))
	for _, p := range pkgs {
		if _, isKernel := KernelReleaseOf(p); skipKernel && isKernel {
			continue
		}
		k := packageKey{p.Ecosystem, p.Name, p.Arch}
		v := displayVersion(p)
		if cur, ok := out[k]; !ok || higherVersion(p.Ecosystem, v, cur) {
			out[k] = v
		}
	}
	return out
}

// displayVersion is the package version with its epoch, as findings show it, unless the version
// already carries the epoch.
func displayVersion(p model.Package) string {
	if p.Epoch == "" || strings.HasPrefix(p.Version, p.Epoch+":") {
		return p.Version
	}
	return p.Epoch + ":" + p.Version
}

// higherVersion reports whether a is above b, comparing lexically when the ecosystem does not
// compare them or they compare equal, so the choice does not depend on input order.
func higherVersion(ecosystem, a, b string) bool {
	c, ok := compareVersions(ecosystem, a, b)
	if !ok || c == 0 {
		c = strings.Compare(a, b)
	}
	return c > 0
}

// summaryFields are the node fields in summary order, with their summary labels.
var summaryFields = []struct{ field, label string }{
	{"kernel", "kernel"}, {"osImage", "OS"}, {"containerRuntime", "runtime"}, {"kubelet", "kubelet"}, {"distro", "distro"},
}

// Summary is a one-line drift summary, To against From:
// "kernel 7.0.0-38 vs 7.0.0-34; 14 packages newer; 2 only here". It is "" when nothing differs.
func Summary(d model.NodeDrift) string {
	var parts []string
	for _, sf := range summaryFields {
		for _, f := range d.Fields {
			if f.Field != sf.field {
				continue
			}
			from, to := f.From, f.To
			if f.Field == "kernel" {
				if shortFrom, shortTo := ShortKernel(from), ShortKernel(to); shortFrom != shortTo {
					from, to = shortFrom, shortTo
				}
			}
			parts = append(parts, sf.label+" "+orUnknown(to)+" vs "+orUnknown(from))
		}
	}
	if n := d.NewerInTo; n > 0 {
		parts = append(parts, fmt.Sprintf("%d %s newer", n, packagesNoun(n)))
	}
	if n := d.NewerInFrom; n > 0 {
		parts = append(parts, fmt.Sprintf("%d %s older", n, packagesNoun(n)))
	}
	if n := len(d.OnlyTo); n > 0 {
		parts = append(parts, fmt.Sprintf("%d only here", n))
	}
	if n := len(d.OnlyFrom); n > 0 {
		parts = append(parts, fmt.Sprintf("%d missing", n))
	}
	return strings.Join(parts, "; ")
}

func packagesNoun(n int) string {
	if n == 1 {
		return "package"
	}
	return "packages"
}

func orUnknown(v string) string {
	if v == "" {
		return "unknown"
	}
	return v
}
