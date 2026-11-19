package store

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

func TestUpsertImage_PendingDoesNotDowngrade(t *testing.T) {
	s := newStore(t)
	img := model.Image{Digest: "sha256:a", Repo: "docker.io/library/nginx", Platform: "linux/amd64", Status: model.ImageCatalogued,
		Source: "registry", ConfigUser: "nginx", Coverage: model.Coverage{UnattributedELF: 2}, CataloguedAt: t0, Attempts: 1}
	require.NoError(t, s.UpsertImage(ctx, img))
	require.NoError(t, s.UpsertImage(ctx, model.Image{Digest: "sha256:a", Repo: "ghcr.io/mirror/nginx", Status: model.ImagePending}))

	got, ok, err := s.GetImage(ctx, "sha256:a")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, model.ImageCatalogued, got.Status)
	require.Equal(t, 2, got.Coverage.UnattributedELF)
	require.Equal(t, "linux/amd64", got.Platform)
	require.Equal(t, "nginx", got.ConfigUser)
	require.Equal(t, t0, got.CataloguedAt)
	require.Equal(t, "ghcr.io/mirror/nginx", got.Repo) // non-empty Repo is still updated

	failed := img
	failed.Status, failed.StatusReason, failed.Attempts, failed.QuarantinedUntil = model.ImageCatalogFailed, "timeout", 2, t0.Add(24*time.Hour)
	require.NoError(t, s.UpsertImage(ctx, failed))
	got, _, err = s.GetImage(ctx, "sha256:a")
	require.NoError(t, err)
	require.Equal(t, "timeout", got.StatusReason)
	require.Equal(t, 2, got.Attempts)
	require.True(t, got.QuarantinedUntil.Equal(t0.Add(24*time.Hour)))

	list, err := s.ListImages(ctx, ImageFilter{Statuses: []model.ImageStatus{model.ImageCatalogFailed}})
	require.NoError(t, err)
	require.Len(t, list, 1)
	_, ok, err = s.GetImage(ctx, "sha256:none")
	require.NoError(t, err)
	require.False(t, ok)
}

func TestPutSBOM_ReplacesPackagesAndCompresses(t *testing.T) {
	s := newStore(t)
	sbom := bytes.Repeat([]byte(`{"artifacts":[]}`), 1<<16)
	require.NoError(t, s.PutSBOM(ctx, "sha256:a", sbom, []model.Package{deb("openssl", ""), deb("libssl3", "openssl"), deb("zlib1g", "zlib")}))
	openssl := deb("openssl", "")
	openssl.SyftID = "abc"
	require.NoError(t, s.PutSBOM(ctx, "sha256:a", sbom[:32], []model.Package{openssl, deb("curl", "")}))

	pk, err := s.PackagesForImage(ctx, "sha256:a")
	require.NoError(t, err)
	require.Len(t, pk, 2)
	require.ElementsMatch(t, []string{"curl", "openssl"}, names(pk))
	require.Equal(t, model.PackageID("sha256:a", pk[0]), pk[0].ID)
	require.Equal(t, "sha256:a", pk[0].ImageDigest)
	for _, p := range pk {
		if p.Name == "openssl" {
			require.Equal(t, "abc", p.SyftID)
			require.Equal(t, &model.Distro{ID: "debian", VersionID: "12", Codename: "bookworm"}, p.Distro)
		}
	}

	got, ok, err := s.GetSBOM(ctx, "sha256:a")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, sbom[:32], got)

	require.NoError(t, s.PutSBOM(ctx, "sha256:a", sbom, nil))
	var n int
	require.NoError(t, s.rdb.QueryRowContext(ctx, `SELECT length(syft_zst) FROM sboms WHERE digest = ?`, "sha256:a").Scan(&n))
	require.Less(t, n, len(sbom)/10)
	pk, err = s.PackagesForImage(ctx, "sha256:a")
	require.NoError(t, err)
	require.Empty(t, pk)

	require.NoError(t, s.PutSBOM(ctx, "k8s:1.35.2", nil, []model.Package{{Ecosystem: "kubernetes", Name: "kubernetes", Version: "1.35.2"}}))
	_, ok, err = s.GetSBOM(ctx, "k8s:1.35.2")
	require.NoError(t, err)
	require.False(t, ok)
	pk, err = s.PackagesForImage(ctx, "k8s:1.35.2")
	require.NoError(t, err)
	require.Len(t, pk, 1)
	require.Nil(t, pk[0].Distro)
}

func TestPackagesByName(t *testing.T) {
	s := newStore(t)
	d12 := &model.Distro{ID: "debian", VersionID: "12", Codename: "bookworm"}
	d11 := &model.Distro{ID: "debian", VersionID: "11"}
	put(t, s, "sha256:a", pkg("deb", d12, "libssl3", "openssl"), pkg("deb", d12, "openssl", ""), pkg("npm", d12, "lodash", ""))
	put(t, s, "sha256:b", pkg("deb", d11, "libssl1.1", "openssl"), pkg("npm", nil, "lodash", ""))

	bySource, err := s.PackagesByName(ctx, "deb", &model.Distro{ID: "debian", VersionID: "12"}, "openssl", true)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"libssl3", "openssl"}, names(bySource)) // an empty source_name equals the binary name

	byName, err := s.PackagesByName(ctx, "deb", d12, "libssl3", false)
	require.NoError(t, err)
	require.Equal(t, []string{"libssl3"}, names(byName))

	anyDistro, err := s.PackagesByName(ctx, "npm", nil, "lodash", false)
	require.NoError(t, err)
	require.Len(t, anyDistro, 2)

	ecos, err := s.EcosystemsInUse(ctx)
	require.NoError(t, err)
	require.Equal(t, []EcosystemKey{{"deb", "debian", "11"}, {"deb", "debian", "12"}, {"npm", "", ""}, {"npm", "debian", "12"}}, ecos)
}

func TestTagDigest(t *testing.T) {
	s := newStore(t)
	const nginx = "docker.io/library/nginx"
	require.NoError(t, s.PutTagDigest(ctx, nginx, "1.27", "sha256:a", t0))
	require.NoError(t, s.PutTagDigest(ctx, nginx, "1.27", "sha256:b", t0.Add(time.Hour)))

	digest, at, ok, err := s.TagDigest(ctx, nginx, "1.27")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "sha256:b", digest)
	require.True(t, at.Equal(t0.Add(time.Hour)))

	_, _, ok, err = s.TagDigest(ctx, nginx, "1.28")
	require.NoError(t, err)
	require.False(t, ok)
}
