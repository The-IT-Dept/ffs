package nodegroup

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"

	"github.com/the-it-dept/ffs/internal/model"
)

// FingerprintInput is what identifies a host: its packages (after kernel filtering), its distro, its
// running kernel and its container runtime version.
type FingerprintInput struct {
	Packages       []model.Package
	Distro         *model.Distro // the host SBOM's distro (os-release); nil when it has none
	Kernel         *model.NodeKernel
	KernelRelease  string
	RuntimeVersion string
}

// Fingerprint returns the sha256 hex of the host's identity lines, sorted and joined by "\n":
//
//	pkg\t<ecosystem>\t<name>\t<version>\t<arch>\t<epoch>\t<distro>\t<source name>\t<source version>\t<purl>\t<cpes>
//	                                                one per distinct package; Path is ignored
//	distro\t<ID>\t<version ID>                     always present; empty fields without a distro
//	kernel\t<release>\t<package>\t<version>        always present; package and version empty without a Kernel
//	runtime\t<container runtime version>
//
// A package's <distro> is "<ID> <version ID>" ("" without one) and <cpes> its CPEs sorted and joined by
// " ". Every field the matcher reads is in the hash, so two hosts share a fingerprint, and with it the one
// stored group SBOM, only when their packages would match the same way: a document stripped of its distro,
// upstream or CPE metadata gets a fingerprint of its own.
func Fingerprint(in FingerprintInput) string {
	lines := make([]string, 0, len(in.Packages)+3)
	for _, p := range in.Packages {
		cpes := slices.Clone(p.CPEs)
		slices.Sort(cpes)
		lines = append(lines, strings.Join([]string{"pkg", p.Ecosystem, p.Name, p.Version, p.Arch, p.Epoch, distroText(p.Distro),
			p.SourceName, p.SourceVersion, p.PURL, strings.Join(cpes, " ")}, "\t"))
	}
	var id, versionID string
	if in.Distro != nil {
		id, versionID = in.Distro.ID, in.Distro.VersionID
	}
	var pkg, version string
	if in.Kernel != nil {
		pkg, version = in.Kernel.Package, in.Kernel.Version
	}
	lines = append(lines,
		strings.Join([]string{"distro", id, versionID}, "\t"),
		strings.Join([]string{"kernel", in.KernelRelease, pkg, version}, "\t"),
		"runtime\t"+in.RuntimeVersion)
	slices.Sort(lines)
	lines = slices.Compact(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])
}

// distroText is a package's distro as a fingerprint field: "<ID> <version ID>", or "" without one.
func distroText(d *model.Distro) string {
	if d == nil {
		return ""
	}
	return d.ID + " " + d.VersionID
}
