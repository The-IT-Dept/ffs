package nodegroup

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

func TestSuppressedModules(t *testing.T) {
	require.Equal(t, []string{"github.com/containerd/containerd", "github.com/containerd/containerd/v2", "github.com/cri-o/cri-o",
		"github.com/k3s-io/k3s", "github.com/opencontainers/runc", "github.com/rancher/rke2", "k8s.io/kubernetes"}, SuppressedModules(false))
	got := SuppressedModules(true)
	require.Equal(t, []string{"github.com/k3s-io/k3s", "github.com/rancher/rke2", "k8s.io/kubernetes"}, got)
	got[0] = "changed"
	require.Equal(t, "k8s.io/kubernetes", KubernetesModules[0]) // a copy is returned
}

func TestCanonicalModule(t *testing.T) {
	for _, tc := range [][4]string{ // name, version → want name, want version
		{"github.com/k3s-io/containerd/v2", "v2.1.4-k3s2", "github.com/containerd/containerd/v2", "v2.1.4"},
		{"github.com/k3s-io/kubernetes", "v1.35.2-k3s1", "k8s.io/kubernetes", "v1.35.2"},
		{"github.com/rancher/rke2", "v1.35.2-rke2r1", "github.com/rancher/rke2", "v1.35.2"},
		{"github.com/opencontainers/runc", "v1.3.0", "github.com/opencontainers/runc", "v1.3.0"},
		{"golang.org/x/net", "v0.33.0-k3s1", "golang.org/x/net", "v0.33.0-k3s1"}, // other names unchanged
	} {
		name, version := CanonicalModule(tc[0], tc[1])
		require.Equal(t, [2]string{tc[2], tc[3]}, [2]string{name, version}, tc[0])
	}
}

func TestRuntimeOwnerName(t *testing.T) {
	gm := func(n string) model.FindingPackage { return model.FindingPackage{Name: n, Ecosystem: "go-module"} }
	for want, pkgs := range map[string][]model.FindingPackage{
		"containerd": {gm("github.com/opencontainers/runc"), gm("github.com/containerd/containerd/v2")},
		"cri-o":      {gm("github.com/cri-o/cri-o")},
		"":           {gm("github.com/opencontainers/runc"), {Name: "github.com/containerd/containerd", Ecosystem: "deb"}},
	} {
		name, ok := RuntimeOwnerName(pkgs)
		require.Equal(t, want != "", ok, want)
		require.Equal(t, want, name)
	}
}
