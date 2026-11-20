package nodegroup

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

func TestShortKernel(t *testing.T) {
	for in, want := range map[string]string{"7.0.0-34-generic": "7.0.0-34", "5.14.0-427.el9.x86_64": "5.14.0-427",
		"6.6.31-0-lts": "6.6.31-0", "6.1.0-18-amd64": "6.1.0-18", "6.12.48+deb13-amd64": "6.12.48", "6.12": "6.12", "": "", "custom": "custom"} {
		require.Equal(t, want, ShortKernel(in), in)
	}
}

func TestOSImageSlug(t *testing.T) {
	for in, want := range map[string]string{
		"Ubuntu 26.04 LTS": "ubuntu-26.04", "Debian GNU/Linux 13 (trixie)": "debian-13", "Talos (v1.9.0)": "talos-1.9.0",
		"Red Hat Enterprise Linux 9.4 (Plow)": "rhel-9.4", "Flatcar Container Linux by Kinvolk 4152.2.0 (Oklo)": "flatcar-4152.2.0",
		"Bottlerocket OS 1.20.0 (aws-k8s-1.29)": "bottlerocket-1.20.0", "Container-Optimized OS from Google": "container-optimized-os",
		"": "",
	} {
		require.Equal(t, want, OSImageSlug(in), in)
		require.LessOrEqual(t, len(OSImageSlug(in)), 24, in)
	}
}

func TestGroupNameLabelDigest(t *testing.T) {
	require.Equal(t, "ubuntu-26.04-k7.0.0-34", GroupName(&model.Distro{ID: "ubuntu", VersionID: "26.04"}, "Ubuntu 26.04 LTS", "7.0.0-34-generic"))
	require.Equal(t, "arch-k6.12.1", GroupName(&model.Distro{ID: "arch"}, "", "6.12.1-arch1-1"))
	require.Equal(t, "debian-13-k6.12.48", GroupName(nil, "Debian GNU/Linux 13 (trixie)", "6.12.48+deb13-amd64"))
	require.Equal(t, "linux-k6.6.31-0", GroupName(nil, "", "6.6.31-0-lts"))
	require.Equal(t, "linux", GroupName(nil, "", ""))
	require.Equal(t, "ubuntu-26.04-k7.0.0-34-3f9c1a", GroupLabel("ubuntu-26.04-k7.0.0-34", "3f9c1a"+strings.Repeat("0", 58)))
	require.Equal(t, "nodegroup:3f9c1a", GroupDigest("3f9c1a"))
	id, ok := IDFromDigest("nodegroup:3f9c1a")
	require.True(t, ok)
	require.Equal(t, "3f9c1a", id)
	for _, d := range []string{"sha256:3f9c1a", "nodegroup:", ""} {
		_, ok := IDFromDigest(d)
		require.False(t, ok, d)
	}
}

func TestFallbackGroups(t *testing.T) {
	now := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	w2 := model.Node{Name: "worker-2", OSImage: "Ubuntu 26.04 LTS", KernelVersion: "7.0.0-34-generic",
		ContainerRuntimeVersion: "containerd://2.2.1-k3s1", KubeletVersion: "v1.35.2+k3s1", Arch: "amd64"}
	// golden: sha256("nodeinfo\x00Ubuntu 26.04 LTS\x007.0.0-34-generic\x00containerd://2.2.1-k3s1\x00v1.35.2+k3s1\x00amd64")
	require.Equal(t, "3fc82a6150f15237ba389c36ad093f851316e150c9a3a9707ea50ad37516a8f6", FallbackID(w2))
	w1, cp, arm := w2, w2, w2
	w1.Name = "worker-1"
	cp.Name, cp.KernelVersion = "cp-1", "7.0.0-38-generic"
	arm.Name, arm.Arch = "worker-arm-1", "arm64"
	require.NotEqual(t, FallbackID(w2), FallbackID(arm)) // Arch is part of the identity
	gs := FallbackGroups([]model.Node{w2, cp, w1, arm}, now)
	require.Len(t, gs, 3)
	require.True(t, slices.IsSortedFunc(gs, func(a, b model.NodeGroup) int { return strings.Compare(a.Label, b.Label) }))
	i := slices.IndexFunc(gs, func(g model.NodeGroup) bool { return g.ID == FallbackID(w2) })
	require.Equal(t, model.NodeGroup{ID: FallbackID(w2), Kind: model.NodeGroupNodeInfo, Name: "ubuntu-26.04-k7.0.0-34",
		Label: "ubuntu-26.04-k7.0.0-34-3fc82a", OSImage: "Ubuntu 26.04 LTS", KernelRelease: "7.0.0-34-generic",
		ContainerRuntimeVersion: "containerd://2.2.1-k3s1", KubeletVersion: "v1.35.2+k3s1", Arch: "amd64",
		Members: []string{"worker-1", "worker-2"}, FirstSeen: now, LastSeen: now}, gs[i])
}
