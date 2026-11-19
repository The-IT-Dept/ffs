package store

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

func TestStore_SearchOnlyInUseDigests(t *testing.T) {
	s := newStore(t)
	const inUse, candidate = "sha256:aaa", "sha256:bbb"
	for _, d := range []string{inUse, candidate} {
		require.NoError(t, s.UpsertImage(ctx, model.Image{Digest: d, Repo: "docker.io/library/nginx", Status: model.ImageCatalogued}))
		require.NoError(t, s.PutSBOM(ctx, d, nil, []model.Package{deb("openssl", "")}))
	}
	require.NoError(t, s.UpsertOwner(ctx, model.Owner{
		Ref:        model.OwnerRef{Kind: "Deployment", Namespace: "shop", Name: "web"},
		Containers: []model.ContainerUse{{Name: "nginx", Digest: inUse}},
	}))
	require.NoError(t, s.UpsertAdvisory(ctx, model.Advisory{ID: "CVE-2026-0002", Aliases: []string{"GHSA-aaaa-bbbb-cccc"}, Title: "A title"}))

	hits, err := s.Search(ctx, "OPENSSL", 0)
	require.NoError(t, err)
	require.Len(t, hits, 1)
	require.Equal(t, SearchHit{Kind: "package", ID: "openssl", Label: "openssl", Ecosystem: "deb", Version: hits[0].Version, Digests: []string{inUse}}, hits[0])

	hits, err = s.Search(ctx, "nginx", 0)
	require.NoError(t, err)
	require.Equal(t, []SearchHit{{Kind: "image", ID: inUse, Label: "docker.io/library/nginx", Digests: []string{inUse}}}, hits)

	hits, err = s.Search(ctx, "aaaa-bbbb", 0)
	require.NoError(t, err)
	require.Equal(t, []SearchHit{{Kind: "advisory", ID: "CVE-2026-0002", Label: "A title"}}, hits)

	hits, err = s.Search(ctx, "%", 0)
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
