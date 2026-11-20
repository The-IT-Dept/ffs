package nodegroup

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"

	"github.com/the-it-dept/ffs/internal/model"
)

// FingerprintInput is what identifies a host: its packages (after kernel filtering), its running
// kernel and its container runtime version.
type FingerprintInput struct {
	Packages       []model.Package
	Kernel         *model.NodeKernel
	KernelRelease  string
	RuntimeVersion string
}

// Fingerprint returns the sha256 hex of the host's identity lines, sorted and joined by "\n":
//
//	pkg\t<ecosystem>\t<name>\t<version>\t<arch>   one per distinct package; Path is ignored
//	kernel\t<release>\t<package>\t<version>       always present; package and version empty without a Kernel
//	runtime\t<container runtime version>
func Fingerprint(in FingerprintInput) string {
	lines := make([]string, 0, len(in.Packages)+2)
	for _, p := range in.Packages {
		lines = append(lines, strings.Join([]string{"pkg", p.Ecosystem, p.Name, p.Version, p.Arch}, "\t"))
	}
	var pkg, version string
	if in.Kernel != nil {
		pkg, version = in.Kernel.Package, in.Kernel.Version
	}
	lines = append(lines,
		strings.Join([]string{"kernel", in.KernelRelease, pkg, version}, "\t"),
		"runtime\t"+in.RuntimeVersion)
	slices.Sort(lines)
	lines = slices.Compact(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])
}
