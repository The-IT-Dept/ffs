package inventory

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

func TestNormalizeK8sVersion(t *testing.T) {
	for _, tc := range []struct {
		in, version, dist string
		low               bool
	}{
		{"v1.35.2+k3s1", "1.35.2", "k3s", false},
		{"v1.31.4+rke2r1", "1.31.4", "rke2", false},
		{"v1.30.4-eks-a737599", "1.30.4", "eks", true},
		{"v1.31.1-gke.1678000", "1.31.1", "gke", true},
		{"v1.35.0", "1.35.0", "", false},
	} {
		v, dist, low, err := NormalizeK8sVersion(tc.in)
		require.NoError(t, err, tc.in)
		require.Equal(t, tc.version, v, tc.in)
		require.Equal(t, tc.dist, dist, tc.in)
		require.Equal(t, tc.low, low, tc.in)
	}
	_, _, _, err := NormalizeK8sVersion("garbage")
	require.Error(t, err)
}

func TestParseRuntimeVersion(t *testing.T) {
	for _, tc := range []struct{ in, name, version string }{
		{"containerd://2.2.1", "containerd", "2.2.1"},
		{"containerd://1.7.23-k3s2", "containerd", "1.7.23"},
		{"cri-o://1.31.3", "cri-o", "1.31.3"},
		{"docker://27.3.1", "docker", "27.3.1"},
	} {
		name, version, ok := ParseRuntimeVersion(tc.in)
		require.True(t, ok, tc.in)
		require.Equal(t, tc.name, name, tc.in)
		require.Equal(t, tc.version, version, tc.in)
	}
	for _, in := range []string{"", "containerd", "containerd://"} {
		_, _, ok := ParseRuntimeVersion(in)
		require.False(t, ok, in)
	}
}

func synthPackage(digest, eco, name, version, path string) model.Package {
	p := model.Package{ImageDigest: digest, Ecosystem: eco, Name: name, Version: version, Path: path}
	p.ID = model.PackageID(digest, p)
	return p
}

func digestsOf(cs []model.ContainerUse) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.Digest)
	}
	return out
}

func TestBuildClusterInventory_K3s(t *testing.T) {
	ci := model.ClusterInfo{GitVersion: "v1.35.2+k3s1", Version: "1.35.2", Distribution: "k3s"}
	nodes := []model.Node{{KubeletVersion: "v1.35.2+k3s1", ContainerRuntimeVersion: "containerd://2.1.4-k3s1"},
		{KubeletVersion: "v1.35.2+k3s1", ContainerRuntimeVersion: "containerd://2.1.4-k3s1"},
		{KubeletVersion: "v1.34.5+k3s1", ContainerRuntimeVersion: "containerd://1.7.27-k3s1"}}
	syn := BuildClusterInventory("dev", ci, nodes, t0, ClusterOptions{})
	require.Len(t, syn, 2)

	cl := syn[0]
	require.Equal(t, model.OwnerRef{Kind: "Cluster", Name: "dev"}, cl.Owner.Ref)
	require.Equal(t, []string{"k8s:1.34.5", "k8s:1.35.2"}, digestsOf(cl.Owner.Containers))
	for _, c := range cl.Owner.Containers {
		require.Equal(t, "kubernetes", c.Repo)
		require.Equal(t, "kubernetes", c.Name)
		require.Equal(t, model.ContainerRegular, c.Kind)
	}
	require.Equal(t, "v1.35.2+k3s1", cl.Owner.Containers[1].ImageRef)
	require.Equal(t, "v1.34.5+k3s1", cl.Owner.Containers[0].ImageRef)
	require.Equal(t, []model.Package{synthPackage("k8s:1.35.2", "kubernetes", "kubernetes", "1.35.2",
		"control plane; kubelet on 2 nodes")}, cl.Packages["k8s:1.35.2"])
	require.Equal(t, "kubelet on 1 node", cl.Packages["k8s:1.34.5"][0].Path)
	require.Len(t, cl.Images, 2)
	for _, img := range cl.Images {
		require.Equal(t, "kubernetes", img.Repo)
		require.Contains(t, img.Coverage.Notes, "kernel, runc and other bundled components (flannel) are not inventoried")
		require.Len(t, img.Coverage.Notes, 1)
	}

	rt := syn[1]
	require.Equal(t, model.OwnerRef{Kind: "ContainerRuntime", Name: "containerd"}, rt.Owner.Ref)
	require.Equal(t, []string{"runtime:containerd@1.7.27", "runtime:containerd@2.1.4"}, digestsOf(rt.Owner.Containers))
	for _, c := range rt.Owner.Containers {
		require.Equal(t, "containerd", c.Repo)
	}
	require.Equal(t, synthPackage("runtime:containerd@2.1.4", "go-module", "github.com/containerd/containerd/v2", "v2.1.4",
		"2 nodes"), rt.Packages["runtime:containerd@2.1.4"][0])
	require.Equal(t, "github.com/containerd/containerd", rt.Packages["runtime:containerd@1.7.27"][0].Name)
	require.Equal(t, "1 node", rt.Packages["runtime:containerd@1.7.27"][0].Path)

	for _, s := range syn {
		for _, img := range s.Images {
			require.Equal(t, "inventory", img.Source, img.Digest)
			require.Equal(t, model.ImageCatalogued, img.Status, img.Digest)
			require.Contains(t, s.Packages, img.Digest)
		}
	}

	ci.KubeProxyVersion = "1.35.2"
	syn = BuildClusterInventory("dev", ci, nodes, t0, ClusterOptions{})
	require.Equal(t, "control plane; kubelet on 2 nodes; kube-proxy", syn[0].Packages["k8s:1.35.2"][0].Path)

	syn = BuildClusterInventory("dev", ci, []model.Node{
		{KubeletVersion: "v1.35.2+k3s1", ContainerRuntimeVersion: "cri-o://1.31.3"},
		{KubeletVersion: "v1.35.2+k3s1", ContainerRuntimeVersion: "docker://27.3.1"},
	}, t0, ClusterOptions{})
	require.Len(t, syn, 2)
	require.Equal(t, model.OwnerRef{Kind: "ContainerRuntime", Name: "cri-o"}, syn[1].Owner.Ref)
	require.Equal(t, synthPackage("runtime:cri-o@1.31.3", "go-module", "github.com/cri-o/cri-o", "v1.31.3", "1 node"),
		syn[1].Packages["runtime:cri-o@1.31.3"][0])

	eks := model.ClusterInfo{GitVersion: "v1.30.4-eks-a737599", Version: "1.30.4", Distribution: "eks", LowConfidence: true}
	syn = BuildClusterInventory("dev", eks, nil, t0, ClusterOptions{})
	require.Len(t, syn, 1)
	require.Equal(t, "control plane", syn[0].Packages["k8s:1.30.4"][0].Path)
	require.Equal(t, []string{"kernel, runc and other bundled components (flannel) are not inventoried",
		"version normalised from v1.30.4-eks-a737599; vendor builds may include backported fixes"}, syn[0].Images[0].Coverage.Notes)

	require.Empty(t, BuildClusterInventory("dev", model.ClusterInfo{KubeProxyVersion: "1.35.2"},
		[]model.Node{{ContainerRuntimeVersion: "docker://27.3.1"}}, t0, ClusterOptions{}))
}

func TestBuildClusterInventory_RuntimeRetired(t *testing.T) {
	ci := model.ClusterInfo{GitVersion: "v1.35.2+k3s1", Version: "1.35.2", Distribution: "k3s"}
	nodes := []model.Node{{KubeletVersion: "v1.35.2+k3s1", ContainerRuntimeVersion: "containerd://2.1.4-k3s1"}}
	syn := BuildClusterInventory("dev", ci, nodes, t0, ClusterOptions{RuntimeRetired: true})
	require.Len(t, syn, 1)
	require.Equal(t, model.OwnerKindCluster, syn[0].Owner.Ref.Kind)
	require.Empty(t, syn[0].Images[0].Coverage.Notes) // NoteBundled dropped
	eks := model.ClusterInfo{GitVersion: "v1.30.4-eks-a737599", Version: "1.30.4", Distribution: "eks", LowConfidence: true}
	syn = BuildClusterInventory("dev", eks, nil, t0, ClusterOptions{RuntimeRetired: true})
	require.Equal(t, []string{"version normalised from v1.30.4-eks-a737599; vendor builds may include backported fixes"},
		syn[0].Images[0].Coverage.Notes)
}
