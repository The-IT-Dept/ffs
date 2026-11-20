package nodegroup

import (
	"regexp"
	"strings"

	"github.com/the-it-dept/ffs/internal/model"
)

// maxSlugLen bounds the fallback form of OSImageSlug.
const maxSlugLen = 24

var (
	shortKernelRe = regexp.MustCompile(`^\d+\.\d+(\.\d+)?(-\d+)?`)
	slugWordRe    = regexp.MustCompile(`^[A-Za-z]+`)
	slugVersionRe = regexp.MustCompile(`(?:^|[\s(])v?(\d+(?:\.\d+)*)(?:[\s)]|$)`)
	slugRunRe     = regexp.MustCompile(`[a-z0-9.]+`)
)

// ShortKernel returns the version and ABI part of a kernel release: "7.0.0-34-generic" gives
// "7.0.0-34" and "5.14.0-427.el9.x86_64" gives "5.14.0-427". A release that does not start with a
// version is returned unchanged.
func ShortKernel(release string) string {
	if m := shortKernelRe.FindString(release); m != "" {
		return m
	}
	return release
}

// OSImageSlug turns node.status.nodeInfo.osImage into a short name part.
//
// The primary form is "<word>-<version>": the leading run of letters, lowercased ("rhel" for an
// image starting with "Red Hat"), and the first version token ("Talos (v1.9.0)" gives
// "talos-1.9.0"). Without a leading word or a version token, the lowercased [a-z0-9.] runs are
// joined by "-", adding whole runs while the result stays within 24 characters.
func OSImageSlug(osImage string) string {
	word := strings.ToLower(slugWordRe.FindString(osImage))
	if strings.HasPrefix(osImage, "Red Hat") {
		word = "rhel"
	}
	if m := slugVersionRe.FindStringSubmatch(osImage); word != "" && m != nil {
		return word + "-" + m[1]
	}
	slug := ""
	for _, run := range slugRunRe.FindAllString(strings.ToLower(osImage), -1) {
		switch {
		case slug == "":
			slug = run[:min(len(run), maxSlugLen)]
		case len(slug)+1+len(run) <= maxSlugLen:
			slug += "-" + run
		default:
			return slug
		}
	}
	return slug
}

// GroupName is the stable part of a group's label: "<distro ID>-<version ID>-k<short kernel>".
//
// Without a distro ID it starts with OSImageSlug(osImage), or "linux" when that is empty. The
// version ID is left out when empty, and the kernel part when kernelRelease is empty.
func GroupName(distro *model.Distro, osImage, kernelRelease string) string {
	var name string
	switch {
	case distro != nil && distro.ID != "" && distro.VersionID != "":
		name = distro.ID + "-" + distro.VersionID
	case distro != nil && distro.ID != "":
		name = distro.ID
	default:
		name = OSImageSlug(osImage)
	}
	if name == "" {
		name = "linux"
	}
	if kernelRelease != "" {
		name += "-k" + ShortKernel(kernelRelease)
	}
	return name
}

// GroupLabel is a group's display label: the name and the first six characters of its ID.
func GroupLabel(name, id string) string {
	return name + "-" + id[:min(len(id), 6)]
}

// GroupDigest is the synthetic digest a group's host SBOM is stored under: "nodegroup:<id>".
func GroupDigest(id string) string {
	return model.NodeGroupDigestPrefix + id
}

// IDFromDigest returns the group ID of a "nodegroup:<id>" digest. It is false for any other digest
// and for an empty ID.
func IDFromDigest(digest string) (string, bool) {
	id, ok := strings.CutPrefix(digest, model.NodeGroupDigestPrefix)
	if !ok || id == "" {
		return "", false
	}
	return id, true
}
