package store

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

func TestGrypeKeys_ReplaceAndLookup(t *testing.T) {
	s := newStore(t)
	const d, other = "sha256:d", "sha256:other"
	require.NoError(t, s.PutGrypeKeys(ctx, d, []string{"openssl"}, []string{"php"}))
	require.NoError(t, s.PutGrypeKeys(ctx, other, []string{"OpenSSL", "libssl3"}, nil))

	got, err := s.DigestsForGrypeKeys(ctx, nil, []string{"php"})
	require.NoError(t, err)
	require.Equal(t, []string{d}, got)
	got, err = s.DigestsForGrypeKeys(ctx, []string{"openssl"}, nil)
	require.NoError(t, err)
	require.Equal(t, []string{d, other}, got, "names are lowercased on write")
	got, err = s.DigestsForGrypeKeys(ctx, []string{"php"}, nil)
	require.NoError(t, err)
	require.Empty(t, got, "a CPE product is not a package name")

	// a second put replaces the digest's keys
	require.NoError(t, s.PutGrypeKeys(ctx, d, []string{"bind9"}, []string{"Bind"}))
	got, err = s.DigestsForGrypeKeys(ctx, []string{"openssl"}, []string{"php"})
	require.NoError(t, err)
	require.Equal(t, []string{other}, got)
	got, err = s.DigestsForGrypeKeys(ctx, []string{"BIND9"}, []string{"bind"})
	require.NoError(t, err)
	require.Equal(t, []string{d}, got)

	all, err := s.GrypeDigests(ctx)
	require.NoError(t, err)
	require.Equal(t, []string{d, other}, all)
}

// TestCataloguedLiveSBOMs: the SBOMs a full Grype DB re-match reads are counted: catalogued images
// and node groups some owner runs, not pending ones, not departed ones and not the synthetic
// Kubernetes and runtime digests.
func TestCataloguedLiveSBOMs(t *testing.T) {
	s := newStore(t)
	n, err := s.CataloguedLiveSBOMs(ctx)
	require.NoError(t, err)
	require.Zero(t, n)

	for _, img := range []model.Image{
		{Digest: "sha256:web", Repo: "ghcr.io/example/web", Status: model.ImageCatalogued},
		{Digest: "sha256:api", Repo: "ghcr.io/example/api", Status: model.ImageCatalogued},
		{Digest: "sha256:new", Repo: "ghcr.io/example/new", Status: model.ImagePending},
		{Digest: "sha256:gone", Repo: "ghcr.io/example/gone", Status: model.ImageCatalogued},
		{Digest: "nodegroup:workers", Repo: "nodegroup", Status: model.ImageCatalogued},
		{Digest: "k8s:v1.34.2", Repo: "kubernetes", Status: model.ImageCatalogued},
	} {
		require.NoError(t, s.UpsertImage(ctx, img))
	}
	require.NoError(t, s.UpsertOwner(ctx, model.Owner{Ref: model.OwnerRef{Kind: "Deployment", Namespace: "shop", Name: "web"},
		Containers: []model.ContainerUse{{Name: "web", Digest: "sha256:web"}, {Name: "api", Digest: "sha256:api"},
			{Name: "new", Digest: "sha256:new"}, {Name: "side", Digest: "sha256:web"}}}))
	require.NoError(t, s.UpsertOwner(ctx, model.Owner{Ref: model.OwnerRef{Kind: "Cluster", Name: "nodes"},
		Containers: []model.ContainerUse{{Name: "host", Digest: "nodegroup:workers"}, {Name: "k8s", Digest: "k8s:v1.34.2"}}}))

	n, err = s.CataloguedLiveSBOMs(ctx)
	require.NoError(t, err)
	require.Equal(t, 3, n, "web, api and the node group")
}
