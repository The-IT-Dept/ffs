package store

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

// Jump lists only what in-use container images hold: a candidate image and its packages are not
// hits, nor are the synthetic Kubernetes, runtime and node group digests; a package held only by a
// node group's host packages is a hostpackage hit naming the group's digest.
func TestJump_InUseContainerImagesAndHostPackages(t *testing.T) {
	s := newStore(t)
	const inUse, candidate, host = "sha256:aaa", "sha256:bbb", "nodegroup:g1"
	for _, d := range []string{inUse, candidate} {
		require.NoError(t, s.UpsertImage(ctx, model.Image{Digest: d, Repo: "docker.io/library/nginx", Status: model.ImageCatalogued}))
		require.NoError(t, s.PutSBOM(ctx, d, nil, []model.Package{deb("openssl", "")}))
	}
	require.NoError(t, s.UpsertImage(ctx, model.Image{Digest: host, Repo: "docker.io/library/nginx-host", Status: model.ImageCatalogued}))
	require.NoError(t, s.PutSBOM(ctx, host, nil, []model.Package{deb("openssl", ""), deb("nginx-kmod", "")}))
	require.NoError(t, s.UpsertImage(ctx, model.Image{Digest: "k8s:1.35.1", Repo: "nginx-k8s", Status: model.ImageCatalogued}))
	require.NoError(t, s.UpsertOwner(ctx, model.Owner{
		Ref:        model.OwnerRef{Kind: "Deployment", Namespace: "shop", Name: "web"},
		Containers: []model.ContainerUse{{Name: "nginx", Digest: inUse}},
	}))
	require.NoError(t, s.UpsertOwner(ctx, model.Owner{Ref: model.NodesOwner(testCluster), Containers: []model.ContainerUse{{Name: "g1", Digest: host}}}))
	require.NoError(t, s.UpsertOwner(ctx, model.Owner{Ref: model.OwnerRef{Kind: "Cluster", Name: testCluster},
		Containers: []model.ContainerUse{{Name: "kubernetes", Digest: "k8s:1.35.1"}}}))
	require.NoError(t, s.UpsertAdvisory(ctx, model.Advisory{ID: "CVE-2026-0002", Aliases: []string{"GHSA-aaaa-bbbb-cccc"}, Title: "A title"}))

	hits, more, err := s.Jump(ctx, "OPENSSL", 0)
	require.NoError(t, err)
	require.False(t, more)
	require.Equal(t, []JumpHit{{Kind: "package", ID: "deb/openssl", Label: "openssl", Detail: "deb", Prefix: true}}, hits,
		"a package a container holds is a package hit, wherever else it is")

	hits, _, err = s.Jump(ctx, "nginx", 0)
	require.NoError(t, err)
	require.Equal(t, []JumpHit{
		{Kind: "image", ID: inUse, Label: "docker.io/library/nginx", Detail: inUse},
		{Kind: "hostpackage", ID: host, Label: "nginx-kmod", Detail: "1.0", Prefix: true},
	}, hits, "neither the candidate image nor a synthetic digest is an image hit")

	hits, _, err = s.Jump(ctx, "aaaa-bbbb", 0)
	require.NoError(t, err)
	require.Equal(t, []JumpHit{{Kind: "advisory", ID: "CVE-2026-0002", Label: "CVE-2026-0002", Detail: "A title"}}, hits)
	hits, _, err = s.Jump(ctx, "ghsa", 0)
	require.NoError(t, err)
	require.Equal(t, []JumpHit{{Kind: "advisory", ID: "CVE-2026-0002", Label: "CVE-2026-0002", Detail: "A title", Prefix: true}}, hits,
		"an alias starting with the query is a prefix hit")

	hits, _, err = s.Jump(ctx, "%", 0)
	require.NoError(t, err)
	require.Empty(t, hits)
}

func TestStore_CountFindings(t *testing.T) {
	s := newStore(t)
	owner := model.OwnerRef{Kind: "Deployment", Namespace: "shop", Name: "web"}
	var fs []model.Finding
	for i, st := range []model.FindingState{model.StateOpen, model.StateOpen, model.StateExcepted} {
		id := string(rune('a' + i))
		fs = append(fs, model.Finding{Fingerprint: id, Owner: owner, ImageRepo: "r", AdvisoryID: "CVE-2026-000" + id,
			State: st, Priority: model.PriorityHigh})
	}
	require.NoError(t, s.ApplyFindings(ctx, fs, nil))

	f := FindingFilter{States: []model.FindingState{model.StateOpen}}
	got, err := s.ListFindings(ctx, f)
	require.NoError(t, err)
	n, err := s.CountFindings(ctx, f)
	require.NoError(t, err)
	require.Equal(t, len(got), n)
	require.Equal(t, 2, n)

	f.Limit, f.Offset = 1, 1
	n, err = s.CountFindings(ctx, f)
	require.NoError(t, err)
	require.Equal(t, 2, n, "limit and offset are ignored")

	one, ok, err := s.GetFinding(ctx, "a")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "CVE-2026-000a", one.AdvisoryID)
	_, ok, err = s.GetFinding(ctx, "nope")
	require.NoError(t, err)
	require.False(t, ok)
}
