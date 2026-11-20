package agent

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPathsFor(t *testing.T) {
	base := []string{"/usr/bin", "/usr/sbin", "/usr/local/bin"}
	dbs := map[string][]string{"dpkg": {"/var/lib/dpkg"}, "rpm": {"/var/lib/rpm"}, "apk": {"/lib/apk/db"}}
	names := []string{"containerd", "containerd-shim-runc-v2", "runc", "kubelet", "k3s", "rke2", "crictl", "crio"}
	for _, tc := range []struct {
		dist         Distribution
		binDirs      []string
		contentStore string
	}{
		{DistContainerd, base, "/var/lib/containerd/io.containerd.content.v1.content"},
		{DistK3s, append(append([]string(nil), base...), "/var/lib/rancher/k3s/data/current/bin", "/var/lib/rancher/k3s/data/current/bin/aux"),
			"/var/lib/rancher/k3s/agent/containerd/io.containerd.content.v1.content"},
		{DistRKE2, append(append([]string(nil), base...), "/var/lib/rancher/rke2/data/*/bin"),
			"/var/lib/rancher/rke2/agent/containerd/io.containerd.content.v1.content"},
		{DistCRIO, base, ""},
	} {
		t.Run(string(tc.dist), func(t *testing.T) {
			p := PathsFor(tc.dist)
			require.Equal(t, []string{"/etc/os-release"}, p.OSRelease)
			require.Equal(t, dbs, p.PackageDBs)
			require.Equal(t, tc.binDirs, p.BinDirs)
			require.Equal(t, names, p.BinaryNames)
			require.Equal(t, tc.contentStore, p.ContentStore)
		})
	}
	require.Equal(t, "crio", BinaryNames[len(BinaryNames)-1])

	// Each call is independent: appending to one table never changes another.
	p := PathsFor(DistContainerd)
	p.BinDirs = append(p.BinDirs, "/opt/bin")
	p.PackageDBs["dpkg"] = nil
	require.Equal(t, base, PathsFor(DistContainerd).BinDirs)
	require.Equal(t, dbs, PathsFor(DistContainerd).PackageDBs)
}

func TestParseDistribution(t *testing.T) {
	for _, s := range []string{"containerd", "k3s", "rke2", "crio"} {
		d, err := ParseDistribution(s)
		require.NoError(t, err)
		require.Equal(t, Distribution(s), d)
	}
	for _, s := range []string{"auto", ""} {
		_, err := ParseDistribution(s)
		require.EqualError(t, err, `unknown distribution "`+s+`": want containerd, k3s, rke2 or crio`)
	}
}
