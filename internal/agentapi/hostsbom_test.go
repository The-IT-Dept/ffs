package agentapi

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/agentapi/wire"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/sbom"
)

func TestIngest_CoverageOf(t *testing.T) {
	blocked := func(p string) model.NodeCoverageGap {
		return model.NodeCoverageGap{Code: model.GapNodeAgentBlocked, Detail: "node agent cannot read " + p + ": permission denied"}
	}
	noDB := model.NodeCoverageGap{Code: model.GapNoPackageDatabase, Detail: "no package database (image-based OS)"}
	notMounted := model.NodeCoverageGap{Code: model.GapNoPackageDatabase, Detail: "package database not mounted; set nodeAgent.packageDatabases"}
	store := model.NodeCoverageGap{Code: model.GapContentStoreUnreadable,
		Detail: "no containerd content store on this node; side-loaded images cannot be catalogued from it"}
	missing := model.NodeCoverageGap{Code: model.GapNodeAgentMissing, Detail: "node agent has not reported"}
	denied := func(p string) wire.Problem {
		return wire.Problem{Code: wire.ProblemPermissionDenied, Path: p, Detail: "permission denied"}
	}
	withStore := &wire.Images{ContentStore: true}

	for name, tc := range map[string]struct {
		r         wire.Report
		stored    []model.NodeCoverageGap
		want      []model.NodeCoverageGap
		mutableOS bool // not an image-based OS
	}{
		"clean": {r: wire.Report{Host: &wire.Host{PackageDB: "dpkg"}, Images: withStore}},
		"permission denied": {r: wire.Report{Images: withStore, Problems: []wire.Problem{denied("/var/lib/rpm")}},
			want: []model.NodeCoverageGap{blocked("/var/lib/rpm")}},
		"no package db problem": {r: wire.Report{Images: withStore, Problems: []wire.Problem{{Code: wire.ProblemNoPackageDB}}},
			want: []model.NodeCoverageGap{noDB}},
		"content store problem": {r: wire.Report{Images: withStore, Problems: []wire.Problem{{Code: wire.ProblemContentStore, Detail: "x"}}},
			want: []model.NodeCoverageGap{store}},
		"catalog and scratch problems are not gaps": {r: wire.Report{Images: withStore,
			Problems: []wire.Problem{{Code: wire.ProblemCatalog, Detail: "busy: x"}, {Code: wire.ProblemScratch, Detail: "y"}}}},
		"empty package db": {r: wire.Report{Host: &wire.Host{}, Images: withStore}, want: []model.NodeCoverageGap{noDB}},
		"empty package db, denied": {r: wire.Report{Host: &wire.Host{}, Images: withStore, Problems: []wire.Problem{denied("/var/lib/dpkg/status")}},
			want: []model.NodeCoverageGap{blocked("/var/lib/dpkg/status")}},
		"no content store": {r: wire.Report{Images: &wire.Images{}}, want: []model.NodeCoverageGap{store}},
		"images absent carries the stored content-store gap only": {r: wire.Report{},
			stored: []model.NodeCoverageGap{store, blocked("/var/lib/rpm"), missing}, want: []model.NodeCoverageGap{store}},
		"images present drops the stored gap": {r: wire.Report{Images: withStore}, stored: []model.NodeCoverageGap{store}},
		"de-duplicated and ordered": {r: wire.Report{Host: &wire.Host{}, Images: &wire.Images{}, Problems: []wire.Problem{
			denied("/var/lib/rpm"), {Code: wire.ProblemContentStore}, denied("/var/lib/dpkg"), denied("/var/lib/rpm"),
			{Code: wire.ProblemNoPackageDB}, {Code: wire.ProblemNoPackageDB}}},
			want: []model.NodeCoverageGap{store, noDB, blocked("/var/lib/dpkg"), blocked("/var/lib/rpm")}},
		"no package db problem, not image-based": {r: wire.Report{Images: withStore, Problems: []wire.Problem{{Code: wire.ProblemNoPackageDB}}},
			mutableOS: true, want: []model.NodeCoverageGap{notMounted}},
		"empty package db, not image-based": {r: wire.Report{Host: &wire.Host{}, Images: withStore}, mutableOS: true,
			want: []model.NodeCoverageGap{notMounted}},
	} {
		require.Equal(t, tc.want, coverageOf(&tc.r, tc.stored, !tc.mutableOS), name)
	}
}

func TestIngest_ImageBasedOSFromOSRelease(t *testing.T) {
	for _, tc := range []struct {
		os      *osRelease
		osImage string
		want    bool
	}{
		{&osRelease{ID: "talos"}, "", true},
		{&osRelease{ID: "flatcar", IDLike: []string{"coreos"}}, "", true},
		{&osRelease{ID: "bottlerocket"}, "", true},
		{&osRelease{ID: "cos"}, "", true},
		{&osRelease{ID: "acme-edge", IDLike: []string{"flatcar"}}, "", true},
		{&osRelease{ID: "ubuntu", IDLike: []string{"debian"}}, "Talos (v1.11.0)", false}, // os-release wins over the OS image
		{&osRelease{ID: "alpine"}, "", false},
		{&osRelease{ID: "rhcos", IDLike: []string{"rhel", "fedora"}}, "", false},
		{nil, "Talos (v1.11.0)", true},
		{nil, "Flatcar Container Linux by Kinvolk 4230.2.0 (Oklo)", true},
		{nil, "Bottlerocket OS 1.42.0 (aws-k8s-1.34)", true},
		{nil, "Container-Optimized OS from Google", true},
		{&osRelease{}, "Container-Optimized OS from Google", true}, // no ID: the OS image
		{nil, "Ubuntu 24.04.3 LTS", false},
		{nil, "Alpine Linux v3.22", false},
		{nil, "", false},
	} {
		require.Equal(t, tc.want, imageBasedOS(tc.os, tc.osImage), "%+v %q", tc.os, tc.osImage)
	}
}

func TestIngest_BinariesOf(t *testing.T) {
	doc, err := sbom.DecodeSyftJSON(syftDoc(t, nil,
		goPkg("github.com/containerd/containerd/v2", "v2.2.1", "/usr/bin/containerd", "github.com/containerd/containerd/v2"),
		goPkg("github.com/opencontainers/runc", "v1.3.0", "/usr/sbin/runc", "github.com/opencontainers/runc"),
		goPkg("golang.org/x/net", "v0.40.0", "/usr/bin/kubelet", "k8s.io/kubernetes"),
		goPkg("github.com/k3s-io/k3s", "v1.37.1+k3s1", "/usr/local/bin/k3s", "github.com/k3s-io/k3s"),
	))
	require.NoError(t, err)
	got := binariesOf(doc, []wire.Binary{
		{Name: "runc", Path: "/usr/bin/runc"},
		{Name: "kubelet", Path: "/usr/bin/kubelet"},
		{Name: "containerd", Path: "/usr/bin/containerd"},
		{Name: "k3s", Path: "/usr/local/bin/k3s"},
		{Name: "crictl", Path: "/usr/local/bin/k3s"},
	})
	require.Equal(t, []model.NodeBinary{
		{Name: "containerd", Path: "/usr/bin/containerd", Module: "github.com/containerd/containerd/v2", Version: "v2.2.1"},
		{Name: "crictl", Path: "/usr/local/bin/k3s", Module: "github.com/k3s-io/k3s", Version: "v1.37.1+k3s1"},
		{Name: "k3s", Path: "/usr/local/bin/k3s", Module: "github.com/k3s-io/k3s", Version: "v1.37.1+k3s1"},
		{Name: "kubelet", Path: "/usr/bin/kubelet"}, // only a dependency at the path: the main module is not catalogued
		{Name: "runc", Path: "/usr/bin/runc"},       // the module is at another path
	}, got)
	require.Nil(t, binariesOf(doc, nil))
}

func TestIngest_ProblemText(t *testing.T) {
	require.Equal(t, "/var/lib/rpm: permission denied", problemText(wire.Problem{Code: "permission_denied", Path: "/var/lib/rpm", Detail: "permission denied"}))
	require.Equal(t, "no dpkg, rpm or apk database found", problemText(wire.Problem{Code: "no_package_db", Detail: "no dpkg, rpm or apk database found"}))
	require.Equal(t, "busy: cataloguer is busy", problemText(wire.Problem{Code: "catalog", Detail: "busy: cataloguer is busy"}))
}
