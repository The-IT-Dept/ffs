// Package agent is the node side of ffs: the collector that stages read-only host inputs and content-store images
// for the non-root cataloguer and reports them to the controller.
package agent

import "fmt"

// Distribution selects the host-path table for a node's Kubernetes distribution.
type Distribution string

// Supported distributions.
const (
	DistContainerd Distribution = "containerd"
	DistK3s        Distribution = "k3s"
	DistRKE2       Distribution = "rke2"
	DistCRIO       Distribution = "crio"
)

// BinaryNames are the host binaries the agent stages for their Go modules. Each is looked for in every BinDirs entry.
var BinaryNames = []string{"containerd", "containerd-shim-runc-v2", "runc", "kubelet", "k3s", "rke2", "crictl", "crio"}

// HostPaths is the fixed table of host paths the agent reads, all mounted read-only under the host root.
type HostPaths struct {
	OSRelease  []string            // os-release files
	PackageDBs map[string][]string // package database dirs by family: "dpkg", "rpm", "apk"
	// BinDirs are searched for BinaryNames. A "*" path segment expands to the child directory whose name sorts
	// highest in version-aware order.
	BinDirs      []string
	BinaryNames  []string
	ContentStore string // containerd content store; "" when the runtime has none (CRI-O)
}

var (
	baseBinDirs = []string{"/usr/bin", "/usr/sbin", "/usr/local/bin"}
	k3sBinDirs  = []string{"/var/lib/rancher/k3s/data/current/bin", "/var/lib/rancher/k3s/data/current/bin/aux"}
	rke2BinDirs = []string{"/var/lib/rancher/rke2/data/*/bin"}
)

// PathsFor returns the host-path table of a distribution. Each call returns fresh slices and maps.
func PathsFor(d Distribution) HostPaths {
	p := HostPaths{
		OSRelease: []string{"/etc/os-release"},
		PackageDBs: map[string][]string{
			"dpkg": {"/var/lib/dpkg"},
			"rpm":  {"/var/lib/rpm"},
			"apk":  {"/lib/apk/db"},
		},
		BinDirs:     append([]string(nil), baseBinDirs...),
		BinaryNames: append([]string(nil), BinaryNames...),
	}
	switch d {
	case DistK3s:
		p.BinDirs = append(p.BinDirs, k3sBinDirs...)
		p.ContentStore = "/var/lib/rancher/k3s/agent/containerd/io.containerd.content.v1.content"
	case DistRKE2:
		p.BinDirs = append(p.BinDirs, rke2BinDirs...)
		p.ContentStore = "/var/lib/rancher/rke2/agent/containerd/io.containerd.content.v1.content"
	case DistCRIO:
		p.ContentStore = ""
	default:
		p.ContentStore = "/var/lib/containerd/io.containerd.content.v1.content"
	}
	return p
}

// ParseDistribution parses a --distribution value.
func ParseDistribution(s string) (Distribution, error) {
	switch d := Distribution(s); d {
	case DistContainerd, DistK3s, DistRKE2, DistCRIO:
		return d, nil
	}
	return "", fmt.Errorf("unknown distribution %q: want containerd, k3s, rke2 or crio", s)
}
