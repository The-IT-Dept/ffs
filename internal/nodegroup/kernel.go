package nodegroup

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/the-it-dept/ffs/internal/model"
)

// The kernel package rule table: which installed packages belong to which kernel release.
var (
	// debKernelRe captures the package kind and the release of a per-release deb kernel package.
	// Meta packages (linux-image-generic, linux-generic) do not match.
	debKernelRe = regexp.MustCompile(`^linux-(image|image-unsigned|modules|modules-extra|headers|tools)-(\d+\.\d+\.\d+-\d+[-a-z0-9]*)$`)
	// apkKernelRe captures the flavour of an Alpine kernel package.
	apkKernelRe = regexp.MustCompile(`^linux-(lts|virt|edge|rpi)$`)
	// flavourlessReleaseRe matches a deb release without a flavour (linux-headers-7.0.0-34), which
	// belongs to every release that starts with it and a "-".
	flavourlessReleaseRe = regexp.MustCompile(`^\d+\.\d+\.\d+-\d+$`)
)

// rpmKernelNames are the rpm kernel packages besides the kernel-uek* family.
var rpmKernelNames = []string{"kernel", "kernel-core", "kernel-modules", "kernel-modules-core", "kernel-modules-extra"}

// rpmUEKPrefix starts every Oracle UEK kernel package name.
const rpmUEKPrefix = "kernel-uek"

// rpmImageNames are the rpm kernel image packages, most preferred first.
var rpmImageNames = []string{"kernel-core", "kernel", "kernel-uek-core", "kernel-uek"}

// KernelSplit separates the running kernel's packages from those of other installed kernels.
type KernelSplit struct {
	Running []model.Package // every package not in Other, in input order
	Other   []model.Package // packages of kernels that are not running; excluded everywhere
	Kernel  *model.NodeKernel
	// RebootPending is true when an installed kernel image is newer than the running kernel.
	RebootPending bool
	RebootReason  string // "installed kernel <newest release> is newer than the running kernel <running release>"
}

// kernelPackage is a package's place in the kernel rule table.
type kernelPackage struct {
	release string
	image   bool // a kernel image package, which can stand for its release's kernel
	rank    int  // preference among image packages of one release, lowest first
}

// classifyKernel places p in the kernel rule table. It is false for a package that belongs to no
// kernel release.
func classifyKernel(p model.Package) (kernelPackage, bool) {
	switch p.Ecosystem {
	case "deb":
		m := debKernelRe.FindStringSubmatch(p.Name)
		if m == nil {
			return kernelPackage{}, false
		}
		k := kernelPackage{release: m[2]}
		switch m[1] {
		case "image":
			k.image = true
		case "image-unsigned":
			k.image, k.rank = true, 1
		}
		return k, true
	case "rpm":
		if p.Version == "" || (!slices.Contains(rpmKernelNames, p.Name) && !strings.HasPrefix(p.Name, rpmUEKPrefix)) {
			return kernelPackage{}, false
		}
		// uname -r is <version>-<release>.<arch>; the rpm epoch is not part of it.
		k := kernelPackage{release: p.Version}
		if _, vr, ok := strings.Cut(p.Version, ":"); ok {
			k.release = vr
		}
		if p.Arch != "" {
			k.release += "." + p.Arch
		}
		if i := slices.Index(rpmImageNames, p.Name); i >= 0 {
			k.image, k.rank = true, i
		}
		return k, true
	case "apk":
		m := apkKernelRe.FindStringSubmatch(p.Name)
		if m == nil {
			return kernelPackage{}, false
		}
		base, rev, ok := cutAlpineRevision(p.Version)
		if !ok {
			return kernelPackage{}, false
		}
		return kernelPackage{release: base + "-" + rev + "-" + m[1], image: true}, true
	}
	return kernelPackage{}, false
}

// KernelReleaseOf returns the kernel release a package belongs to, per the kernel package rule
// table. It is false for a package that is not a per-release kernel package.
func KernelReleaseOf(p model.Package) (release string, ok bool) {
	k, ok := classifyKernel(p)
	return k.release, ok
}

// SplitKernels keeps the running kernel's packages and moves every other installed kernel's
// packages to Other. An empty runningRelease (osrelease unreadable) keeps every package in Running.
func SplitKernels(pkgs []model.Package, runningRelease string) KernelSplit {
	if runningRelease == "" {
		return KernelSplit{Running: slices.Clone(pkgs)}
	}
	var (
		s          KernelSplit
		images     []model.Package // every installed kernel image package, running or not
		kernel     *model.Package
		kernelRank int
	)
	for _, p := range pkgs {
		k, ok := classifyKernel(p)
		if !ok {
			s.Running = append(s.Running, p)
			continue
		}
		if k.image {
			images = append(images, p)
		}
		if !belongsToRelease(p.Ecosystem, k.release, runningRelease) {
			s.Other = append(s.Other, p)
			continue
		}
		s.Running = append(s.Running, p)
		if k.image && k.release == runningRelease && (kernel == nil || k.rank < kernelRank) {
			kernel, kernelRank = &p, k.rank
		}
	}
	if kernel != nil {
		s.Kernel = &model.NodeKernel{Release: runningRelease, Package: kernel.Name, Version: kernel.Version, SourceName: kernel.SourceName}
	}
	s.RebootPending, s.RebootReason = rebootPending(images, kernel, runningRelease)
	return s
}

// belongsToRelease reports whether a kernel package of release belongs to the running kernel: the
// releases are equal, or the package is a flavourless deb one whose release starts the running one.
func belongsToRelease(ecosystem, release, runningRelease string) bool {
	return release == runningRelease ||
		ecosystem == "deb" && flavourlessReleaseRe.MatchString(release) && strings.HasPrefix(runningRelease, release+"-")
}

// rebootPending compares the newest installed kernel image with the running kernel.
func rebootPending(images []model.Package, kernel *model.Package, runningRelease string) (bool, string) {
	running, ecosystem, ok := runningKernelVersion(images, kernel, runningRelease)
	if !ok {
		return false, ""
	}
	var newest *model.Package
	for i := range images {
		p := &images[i]
		if p.Ecosystem != ecosystem {
			continue
		}
		if c, ok := compareVersions(ecosystem, p.Version, running); !ok || c <= 0 {
			continue
		}
		if newest != nil {
			if c, ok := compareVersions(ecosystem, p.Version, newest.Version); !ok || c <= 0 {
				continue
			}
		}
		newest = p
	}
	if newest == nil {
		return false, ""
	}
	release, _ := KernelReleaseOf(*newest)
	return true, fmt.Sprintf("installed kernel %s is newer than the running kernel %s", release, runningRelease)
}

// runningKernelVersion is the package version of the running kernel and its ecosystem.
//
// Without the running kernel's package, an Alpine kernel package of the same flavour gives it:
// Alpine upgrades linux-<flavour> in place, and the running release <base>-<N>-<flavour> came from
// package version <base>-r<N>. Otherwise the running version is unknown.
func runningKernelVersion(images []model.Package, kernel *model.Package, runningRelease string) (version, ecosystem string, ok bool) {
	if kernel != nil {
		return kernel.Version, kernel.Ecosystem, true
	}
	for _, p := range images {
		if p.Ecosystem != "apk" {
			continue
		}
		rest, ok := strings.CutSuffix(runningRelease, "-"+strings.TrimPrefix(p.Name, "linux-"))
		if !ok {
			continue
		}
		if i := strings.LastIndexByte(rest, '-'); i > 0 && isDigits(rest[i+1:]) {
			return rest[:i] + "-r" + rest[i+1:], "apk", true
		}
	}
	return "", "", false
}

// cutAlpineRevision splits an Alpine package version "<base>-r<N>" into base and N.
func cutAlpineRevision(version string) (base, rev string, ok bool) {
	i := strings.LastIndex(version, "-r")
	if i <= 0 || !isDigits(version[i+2:]) {
		return "", "", false
	}
	return version[:i], version[i+2:], true
}

func isDigits(s string) bool {
	return s != "" && strings.Trim(s, "0123456789") == ""
}
