package eol

import (
	"regexp"
	"strings"

	"github.com/the-it-dept/ffs/internal/model"
)

// ProductVersion names an endoflife.date product and a version of it.
type ProductVersion struct{ Product, Version string }

// ClusterProduct maps a cluster distribution and its version to the endoflife.date product.
func ClusterProduct(distribution, version string) ProductVersion {
	p := "kubernetes"
	switch distribution {
	case "k3s", "rke2":
		p = distribution
	case "eks":
		p = "amazon-eks"
	case "gke":
		p = "google-kubernetes-engine"
	}
	return ProductVersion{p, version}
}

var nodeOS = []struct {
	re      *regexp.Regexp
	product string
}{
	{regexp.MustCompile(`^Ubuntu (\d+\.\d+)`), "ubuntu"},
	{regexp.MustCompile(`^Debian GNU/Linux (\d+)`), "debian"},
	{regexp.MustCompile(`^Talos \(v?(\d+(?:\.\d+)*)\)`), "talos"},
	{regexp.MustCompile(`^Bottlerocket OS (\d+(?:\.\d+)*)`), "bottlerocket"},
	{regexp.MustCompile(`^Flatcar .*?(\d+\.\d+\.\d+)`), "flatcar"},
	{regexp.MustCompile(`^Amazon Linux (\d+)`), "amazon-linux"},
	{regexp.MustCompile(`^SUSE Linux Enterprise Server (\d+)(?: SP(\d+))?`), "sles"},
	{regexp.MustCompile(`^Red Hat Enterprise Linux (\d+(?:\.\d+)?)`), "rhel"},
	{regexp.MustCompile(`^Rocky Linux (\d+(?:\.\d+)?)`), "rocky-linux"},
	{regexp.MustCompile(`^AlmaLinux (\d+(?:\.\d+)?)`), "almalinux"},
	{regexp.MustCompile(`^CentOS Stream (\d+)`), "centos-stream"},
	{regexp.MustCompile(`^openSUSE Leap (\d+\.\d+)`), "opensuse"},
	{regexp.MustCompile(`^Fedora (?:Linux )?(\d+)`), "fedora"},
	{regexp.MustCompile(`^Alpine Linux v(\d+\.\d+(?:\.\d+)?)`), "alpine-linux"},
}

// NodeOSProduct maps a node's OSImage string to its product and version; ok is false for an
// operating system it does not know.
func NodeOSProduct(osImage string) (ProductVersion, bool) {
	osImage = strings.TrimSpace(osImage)
	for _, n := range nodeOS {
		m := n.re.FindStringSubmatch(osImage)
		if m == nil {
			continue
		}
		var parts []string
		for _, g := range m[1:] {
			if g != "" {
				parts = append(parts, g)
			}
		}
		return ProductVersion{n.product, strings.Join(parts, ".")}, true
	}
	return ProductVersion{}, false
}

var distroProducts = map[string]string{
	"debian": "debian", "ubuntu": "ubuntu", "alpine": "alpine-linux", "rhel": "rhel", "rocky": "rocky-linux",
	"almalinux": "almalinux", "amzn": "amazon-linux", "ol": "oracle-linux", "sles": "sles",
	"opensuse-leap": "opensuse", "fedora": "fedora", "photon": "photon", "wolfi": "wolfi", "chainguard": "chainguard",
}

// DistroProduct maps an image's distro to its product and version. Images under gcr.io/distroless/
// are the distroless product at their base Debian version.
func DistroProduct(d *model.Distro, repo string) (ProductVersion, bool) {
	if d == nil || d.VersionID == "" {
		return ProductVersion{}, false
	}
	if strings.HasPrefix(repo, "gcr.io/distroless/") {
		return ProductVersion{"distroless", d.VersionID}, true
	}
	p, ok := distroProducts[d.ID]
	return ProductVersion{p, d.VersionID}, ok
}

var runtimeBinaries = map[string]string{
	"php-cli": "php", "php-fpm": "php", "libphp": "php", "node": "nodejs", "python": "python", "ruby": "ruby", "go": "go",
}

// RuntimeProducts returns the language runtimes found as binaries or the Go standard library,
// once per product and version. Distro-packaged runtimes are not listed: the distro covers them.
func RuntimeProducts(pkgs []model.Package) []ProductVersion {
	var out []ProductVersion
	seen := map[ProductVersion]bool{}
	add := func(pv ProductVersion) {
		if !seen[pv] {
			seen[pv] = true
			out = append(out, pv)
		}
	}
	for _, p := range pkgs {
		switch {
		case p.GoStdlib:
			v := strings.TrimPrefix(p.Version, "go")
			v, _, _ = strings.Cut(v, " ")
			if v != "" {
				add(ProductVersion{"go", v})
			}
		case p.Ecosystem == "binary" || p.Classifier != "":
			if prod, ok := runtimeBinaries[p.Name]; ok && p.Version != "" {
				add(ProductVersion{prod, p.Version})
			}
		}
	}
	return out
}

// ContainerRuntimeProduct maps a node's container runtime, already split by
// inventory.ParseRuntimeVersion, to its product; only containerd has an endoflife.date product.
func ContainerRuntimeProduct(name, version string) (ProductVersion, bool) {
	if name == "containerd" {
		return ProductVersion{"containerd", version}, true
	}
	return ProductVersion{}, false
}
