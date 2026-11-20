package nodegroup

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

func TestDrift_PackagesAndFields(t *testing.T) {
	from := model.NodeGroup{ID: "aaaa01", Kind: model.NodeGroupAgent, KernelRelease: "7.0.0-34-generic", OSImage: "Ubuntu 26.04 LTS",
		ContainerRuntimeVersion: "containerd://2.2.1", KubeletVersion: "v1.35.2", Distro: &model.Distro{ID: "ubuntu", VersionID: "26.04"}}
	to := from
	to.ID, to.KernelRelease = "bbbb02", "7.0.0-38-generic"
	d := func(name, version string) model.Package {
		return model.Package{Ecosystem: "deb", Name: name, Version: version, Arch: "amd64"}
	}
	gm := func(name, version, path string) model.Package {
		return model.Package{Ecosystem: "go-module", Name: name, Version: version, Path: path}
	}
	fromPkgs := []model.Package{d("openssl", "3.0.13-1"), d("libc6", "2.39-0ubuntu8"), d("zlib1g", "1:1.3-1"),
		d("curl", "8.5.0-2ubuntu10.6"), d("only-from", "1.0"), d("linux-image-7.0.0-34-generic", "7.0.0-34.34"),
		gm("github.com/containerd/containerd/v2", "v2.2.0", "/usr/bin/containerd"), gm("golang.org/x/net", "v0.33.0", "/usr/bin/a"),
		{Ecosystem: "binary", Name: "helper", Version: "1.0"}}
	toPkgs := []model.Package{d("openssl", "3.0.13-1"), d("libc6", "2.39-0ubuntu8.4"), d("zlib1g", "1:1.3.1-1"),
		d("curl", "8.5.0-2ubuntu10.5"), d("only-to", "2.0"), d("linux-image-7.0.0-38-generic", "7.0.0-38.38"),
		gm("github.com/containerd/containerd/v2", "v2.2.1", "/usr/bin/containerd"),
		gm("golang.org/x/net", "v0.30.0", "/usr/bin/a"), gm("golang.org/x/net", "v0.33.0", "/usr/bin/b"), // highest stands
		{Ecosystem: "binary", Name: "helper", Version: "1.1"}}
	got := Drift(from, to, fromPkgs, toPkgs)
	require.Equal(t, []model.FieldDrift{{Field: "kernel", From: "7.0.0-34-generic", To: "7.0.0-38-generic"}}, got.Fields)
	require.True(t, got.PackagesCompared)
	require.Equal(t, []model.DriftPackage{{Ecosystem: "deb", Name: "only-from", Version: "1.0", Arch: "amd64"}}, got.OnlyFrom) // kernel packages left out
	require.Equal(t, []model.DriftPackage{{Ecosystem: "deb", Name: "only-to", Version: "2.0", Arch: "amd64"}}, got.OnlyTo)
	require.Equal(t, []model.VersionDrift{
		{Ecosystem: "binary", Name: "helper", From: "1.0", To: "1.1", Newer: ""}, // ecosystem not comparable
		{Ecosystem: "deb", Name: "curl", Arch: "amd64", From: "8.5.0-2ubuntu10.6", To: "8.5.0-2ubuntu10.5", Newer: "from"},
		{Ecosystem: "deb", Name: "libc6", Arch: "amd64", From: "2.39-0ubuntu8", To: "2.39-0ubuntu8.4", Newer: "to"},
		{Ecosystem: "deb", Name: "zlib1g", Arch: "amd64", From: "1:1.3-1", To: "1:1.3.1-1", Newer: "to"},
		{Ecosystem: "go-module", Name: "github.com/containerd/containerd/v2", From: "v2.2.0", To: "v2.2.1", Newer: "to"},
	}, got.Changed)
	require.Equal(t, 3, got.NewerInTo)
	require.Equal(t, 1, got.NewerInFrom)
	require.Equal(t, "kernel 7.0.0-38 vs 7.0.0-34; 3 packages newer; 1 package older; 1 only here; 1 missing", Summary(got))

	// Same release, different kernel build (Debian keeps the ABI name): the kernel packages compare.
	same := Drift(from, from, []model.Package{d("linux-image-7.0.0-34-generic", "7.0.0-34.34")},
		[]model.Package{d("linux-image-7.0.0-34-generic", "7.0.0-34.35")})
	require.Equal(t, 1, same.NewerInTo)
	require.Equal(t, "1 package newer", Summary(same))

	require.Equal(t, "", Summary(Drift(from, from, fromPkgs, fromPkgs)))
	ni := to
	ni.Kind, ni.Distro = model.NodeGroupNodeInfo, nil
	noPkgs := Drift(from, ni, fromPkgs, nil)
	require.False(t, noPkgs.PackagesCompared)
	require.Empty(t, noPkgs.Changed)
	require.False(t, Drift(from, to, fromPkgs, nil).PackagesCompared) // nil: SBOM not stored
}

func TestSummary_FieldOrderAndLabels(t *testing.T) {
	d := model.NodeDrift{Fields: []model.FieldDrift{
		{Field: "kernel", From: "7.0.0-34-generic", To: "7.0.0-34-lowlatency"},
		{Field: "osImage", From: "Ubuntu 24.04 LTS", To: "Ubuntu 26.04 LTS"},
		{Field: "containerRuntime", From: "containerd://2.1.0", To: "containerd://2.2.1"},
		{Field: "kubelet", From: "", To: "v1.35.2"},
		{Field: "distro", From: "ubuntu 24.04", To: "ubuntu 26.04"},
	}, NewerInTo: 2, NewerInFrom: 1, OnlyTo: make([]model.DriftPackage, 4), OnlyFrom: make([]model.DriftPackage, 1)}
	require.Equal(t, "kernel 7.0.0-34-lowlatency vs 7.0.0-34-generic; OS Ubuntu 26.04 LTS vs Ubuntu 24.04 LTS; "+
		"runtime containerd://2.2.1 vs containerd://2.1.0; kubelet v1.35.2 vs unknown; distro ubuntu 26.04 vs ubuntu 24.04; "+
		"2 packages newer; 1 package older; 4 only here; 1 missing", Summary(d))
}
