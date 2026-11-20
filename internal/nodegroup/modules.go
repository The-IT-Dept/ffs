package nodegroup

import (
	"regexp"
	"slices"

	"github.com/the-it-dept/ffs/internal/model"
)

// KubernetesModules are the Go modules of Kubernetes distributions. Their matches from host
// binaries are suppressed on the Nodes owner, because the Cluster owner reports them.
var KubernetesModules = []string{"k8s.io/kubernetes", "github.com/k3s-io/k3s", "github.com/rancher/rke2"}

// RuntimeModules are the Go modules of container runtimes. Their matches from host binaries are
// suppressed on the Nodes owner while the ContainerRuntime owner is active.
var RuntimeModules = []string{"github.com/containerd/containerd", "github.com/containerd/containerd/v2",
	"github.com/opencontainers/runc", "github.com/cri-o/cri-o"}

// ModuleAliases maps forked Go modules to their upstream paths. Syft names a replaced Go module by
// its replacement, and k3s builds on k3s-io forks, which Grype matches under neither name.
var ModuleAliases = map[string]string{
	"github.com/k3s-io/containerd":    "github.com/containerd/containerd",
	"github.com/k3s-io/containerd/v2": "github.com/containerd/containerd/v2",
	"github.com/k3s-io/kubernetes":    "k8s.io/kubernetes",
}

// distroBuildSuffixRe matches the k3s and rke2 build suffix on a forked module's version.
var distroBuildSuffixRe = regexp.MustCompile(`-(k3s|rke2r)\d+$`)

// SuppressedModules returns the Go modules whose matches the Nodes owner ignores, sorted: the
// Kubernetes modules, plus the runtime modules unless the ContainerRuntime owner is retired. The
// slice is a copy.
func SuppressedModules(runtimeRetired bool) []string {
	out := slices.Clone(KubernetesModules)
	if !runtimeRetired {
		out = append(out, RuntimeModules...)
	}
	slices.Sort(out)
	return out
}

// RuntimeOwnerName returns the ContainerRuntime owner a finding's go-module packages belong to:
// "containerd" for the containerd modules and "cri-o" for cri-o. It is false otherwise, including
// for runc alone.
func RuntimeOwnerName(pkgs []model.FindingPackage) (string, bool) {
	for _, p := range pkgs {
		if p.Ecosystem != "go-module" {
			continue
		}
		switch p.Name {
		case "github.com/containerd/containerd", "github.com/containerd/containerd/v2":
			return "containerd", true
		case "github.com/cri-o/cri-o":
			return "cri-o", true
		}
	}
	return "", false
}

// CanonicalModule returns the upstream name and version of a Go module: the name through
// ModuleAliases and, for a Kubernetes or runtime module, the version without a trailing
// -k3s<N> or -rke2r<N>.
func CanonicalModule(name, version string) (string, string) {
	if upstream, ok := ModuleAliases[name]; ok {
		name = upstream
	}
	if slices.Contains(KubernetesModules, name) || slices.Contains(RuntimeModules, name) {
		version = distroBuildSuffixRe.ReplaceAllString(version, "")
	}
	return name, version
}
