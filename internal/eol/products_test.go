package eol

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

func TestClusterProduct(t *testing.T) {
	for _, tc := range []struct{ dist, ver, product string }{
		{"k3s", "1.31.4", "k3s"}, {"rke2", "1.35.1", "rke2"}, {"eks", "1.33.5", "amazon-eks"},
		{"gke", "1.33.5", "google-kubernetes-engine"}, {"", "1.35.1", "kubernetes"},
	} {
		require.Equal(t, ProductVersion{tc.product, tc.ver}, ClusterProduct(tc.dist, tc.ver), tc.dist)
	}
}

func TestNodeOSProduct(t *testing.T) {
	for in, want := range map[string]ProductVersion{
		"Ubuntu 24.04.4 LTS":                                 {"ubuntu", "24.04"},
		"Debian GNU/Linux 12 (bookworm)":                     {"debian", "12"},
		"Talos (v1.9.1)":                                     {"talos", "1.9.1"},
		"Bottlerocket OS 1.30.0 (aws-k8s-1.31)":              {"bottlerocket", "1.30.0"},
		"Flatcar Container Linux by Kinvolk 4230.2.3 (Oklo)": {"flatcar", "4230.2.3"},
		"Amazon Linux 2023.6.20241010":                       {"amazon-linux", "2023"},
		"SUSE Linux Enterprise Server 15 SP6":                {"sles", "15.6"},
		"Red Hat Enterprise Linux 9.4 (Plow)":                {"rhel", "9.4"},
		"Rocky Linux 9.4 (Blue Onyx)":                        {"rocky-linux", "9.4"},
		"AlmaLinux 9.4 (Seafoam Ocelot)":                     {"almalinux", "9.4"},
		"CentOS Stream 9":                                    {"centos-stream", "9"},
		"openSUSE Leap 15.6":                                 {"opensuse", "15.6"},
		"Fedora Linux 41 (Server Edition)":                   {"fedora", "41"},
		"Alpine Linux v3.20":                                 {"alpine-linux", "3.20"},
	} {
		got, ok := NodeOSProduct(in)
		require.True(t, ok, in)
		require.Equal(t, want, got, in)
	}
	_, ok := NodeOSProduct("Plan 9")
	require.False(t, ok)
}

func TestDistroProduct(t *testing.T) {
	for _, tc := range []struct {
		d    *model.Distro
		repo string
		want ProductVersion
	}{
		{&model.Distro{ID: "debian", VersionID: "12"}, "docker.io/library/nginx", ProductVersion{"debian", "12"}},
		{&model.Distro{ID: "alpine", VersionID: "3.20.3"}, "docker.io/library/nginx", ProductVersion{"alpine-linux", "3.20.3"}},
		{&model.Distro{ID: "amzn", VersionID: "2023"}, "docker.io/library/nginx", ProductVersion{"amazon-linux", "2023"}},
		{&model.Distro{ID: "debian", VersionID: "12"}, "gcr.io/distroless/static-debian12", ProductVersion{"distroless", "12"}},
	} {
		got, ok := DistroProduct(tc.d, tc.repo)
		require.True(t, ok, tc.repo)
		require.Equal(t, tc.want, got)
	}
	_, ok := DistroProduct(nil, "x")
	require.False(t, ok)
}

func TestRuntimeProducts(t *testing.T) {
	bin := func(name, v string) model.Package { return model.Package{Ecosystem: "binary", Name: name, Version: v} }
	got := RuntimeProducts([]model.Package{
		bin("php-cli", "8.3.14"), bin("php-fpm", "8.3.14"), bin("node", "22.11.0"), bin("python", "3.12.7"), bin("ruby", "3.3.6"),
		{Ecosystem: "go-module", Name: "stdlib", Version: "go1.25.3 X:boringcrypto", GoStdlib: true},
		{Ecosystem: "deb", Name: "python3.11", Version: "3.11.2"},
	})
	require.Equal(t, []ProductVersion{
		{"php", "8.3.14"}, {"nodejs", "22.11.0"}, {"python", "3.12.7"}, {"ruby", "3.3.6"}, {"go", "1.25.3"},
	}, got)
}

func TestContainerRuntimeProduct(t *testing.T) {
	got, ok := ContainerRuntimeProduct("containerd", "2.2.1")
	require.True(t, ok)
	require.Equal(t, ProductVersion{"containerd", "2.2.1"}, got)
	_, ok = ContainerRuntimeProduct("cri-o", "1.31.3")
	require.False(t, ok)
}

func TestCentOSAndAzureLinux(t *testing.T) {
	for in, want := range map[string]ProductVersion{
		"CentOS Linux 7 (Core)":     {"centos", "7"},
		"CentOS Linux 8":            {"centos", "8"},
		"Microsoft Azure Linux 3.0": {"azure-linux", "3.0"},
		"CBL-Mariner/Linux 2.0":     {"azure-linux", "2.0"},
	} {
		got, ok := NodeOSProduct(in)
		require.True(t, ok, in)
		require.Equal(t, want, got, in)
	}
	for _, tc := range []struct {
		d    *model.Distro
		want ProductVersion
	}{
		{&model.Distro{ID: "centos", VersionID: "7"}, ProductVersion{"centos", "7"}},
		{&model.Distro{ID: "azurelinux", VersionID: "3.0"}, ProductVersion{"azure-linux", "3.0"}},
		{&model.Distro{ID: "mariner", VersionID: "2.0"}, ProductVersion{"azure-linux", "2.0"}},
	} {
		got, ok := DistroProduct(tc.d, "docker.io/library/app")
		require.True(t, ok, tc.d.ID)
		require.Equal(t, tc.want, got, tc.d.ID)
	}

	// CentOS has endoflife.date cycles; Azure Linux, which endoflife.date does not track, has a note
	e := newEvaluator(t, store.EOLCycle{Product: "centos", Cycle: "7", EOLDate: day(2024, 6, 30)})
	s, ok := e.Evaluate("centos", "7")
	require.True(t, ok)
	require.Equal(t, "CentOS 7 reached end of life 2024-06-30", Text(s, now))
	s, ok = e.Evaluate("azure-linux", "3.0")
	require.True(t, ok)
	require.Equal(t, "Azure Linux 3.0: lifecycle published by Microsoft", Support(s, now))
}
