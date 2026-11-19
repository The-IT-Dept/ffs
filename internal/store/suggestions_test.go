package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

// suggestionsByRepo returns the Suggestion of each of the owner's findings, by image repository.
func suggestionsByRepo(t *testing.T, s *Store, key string) map[string]*model.Suggestion {
	t.Helper()
	fs, err := s.FindingsForOwner(ctx, key)
	require.NoError(t, err)
	out := map[string]*model.Suggestion{}
	for _, f := range fs {
		out[f.ImageRepo] = f.Suggestion
	}
	return out
}

func TestStore_SuggestionFollowsFindings(t *testing.T) {
	s := newStore(t)
	const key, repo, other = "Deployment/netbox/netbox", "ghcr.io/x", "ghcr.io/y"
	onX := fd("fp-x", model.StateOpen, model.PriorityHigh)
	onY := fd("fp-y", model.StateOpen, model.PriorityHigh)
	onY.ImageRepo = other
	require.NoError(t, s.ApplyFindings(ctx, []model.Finding{onX, onY}, nil))

	sg := model.Suggestion{Repo: repo, FromTag: "1.0", ToTag: "1.1", ToDigest: "sha256:idx", Tier: model.TierPatch,
		Fixes: map[model.Priority]int{model.PriorityHigh: 1}, FixedIDs: []string{"CVE-2026-0001"}, ComputedAt: t0}
	cands := []CandidateDigest{
		{Tag: "1.1", Tier: model.TierPatch, Platform: "linux/arm64", Digest: "sha256:cand-arm64"},
		{Tag: "1.1", Tier: model.TierPatch, Platform: "linux/amd64", Digest: "sha256:cand"},
	}
	require.NoError(t, s.PutSuggestion(ctx, key, sg, cands))
	require.Equal(t, map[string]*model.Suggestion{repo: &sg, other: nil}, suggestionsByRepo(t, s, key))

	got, ok, err := s.GetSuggestion(ctx, key, repo)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, OwnerSuggestion{OwnerKey: key, Suggestion: sg, Candidates: cands}, got)
	_, ok, err = s.GetSuggestion(ctx, key, other)
	require.NoError(t, err)
	require.False(t, ok)

	// a recompute writes findings without a suggestion; the stored one stands
	require.NoError(t, s.ApplyFindings(ctx, []model.Finding{onX}, nil))
	newer := fd("fp-x2", model.StateOpen, model.PriorityMedium)
	newer.AdvisoryID = "CVE-2026-0002"
	require.NoError(t, s.ApplyFindings(ctx, []model.Finding{newer}, nil))
	fs, err := s.FindingsForOwner(ctx, key)
	require.NoError(t, err)
	require.Len(t, fs, 3)
	for _, f := range fs {
		if f.ImageRepo == repo {
			require.Equal(t, &sg, f.Suggestion, f.Fingerprint)
		} else {
			require.Nil(t, f.Suggestion, f.Fingerprint)
		}
	}

	keys, err := s.SuggestionKeysForDigests(ctx, []string{"sha256:cand"})
	require.NoError(t, err)
	require.Equal(t, []SuggestionKey{{key, repo}}, keys)

	require.NoError(t, s.DeleteSuggestions(ctx, key, []string{}), "an empty list deletes nothing")
	_, ok, err = s.GetSuggestion(ctx, key, repo)
	require.NoError(t, err)
	require.True(t, ok)

	require.NoError(t, s.DeleteSuggestions(ctx, key, nil))
	for r, got := range suggestionsByRepo(t, s, key) {
		require.Nil(t, got, r)
	}
	all, err := s.ListSuggestions(ctx)
	require.NoError(t, err)
	require.Empty(t, all)
	keys, err = s.SuggestionKeysForDigests(ctx, []string{"sha256:cand"})
	require.NoError(t, err)
	require.Empty(t, keys)

	require.NoError(t, s.PutSuggestion(ctx, key, sg, cands))
	all, err = s.ListSuggestions(ctx)
	require.NoError(t, err)
	require.Len(t, all, 1)
	require.NoError(t, s.DeleteOwner(ctx, key))
	all, err = s.ListSuggestions(ctx)
	require.NoError(t, err)
	require.Empty(t, all)
	keys, err = s.SuggestionKeysForDigests(ctx, []string{"sha256:cand"})
	require.NoError(t, err)
	require.Empty(t, keys, "the owner's candidates go with it")
}

func TestStore_PruneImages(t *testing.T) {
	s := newStore(t)
	now := t0
	const (
		used, cand, old, fresh = "sha256:d-used", "sha256:d-cand", "sha256:d-old", "sha256:d-new"
		synthetic, pending     = "k8s:1.35.1", "sha256:d-pending"
	)
	seedImage := func(digest string, catalogued time.Time) {
		t.Helper()
		status := model.ImageCatalogued
		if catalogued.IsZero() {
			status = model.ImagePending
		}
		require.NoError(t, s.UpsertImage(ctx, model.Image{Digest: digest, Repo: "ghcr.io/x", Status: status, CataloguedAt: catalogued}))
		p := deb("libssl3", "openssl")
		p.ID = model.PackageID(digest, p)
		require.NoError(t, s.PutSBOM(ctx, digest, []byte(`{"artifacts":[]}`), []model.Package{p}))
		seed(t, s, mt(digest, p.ID, "CVE-2026-0001", model.SourceGrype))
		require.NoError(t, s.PutGrypeKeys(ctx, digest, []string{"openssl"}, nil))
	}
	for _, d := range []string{used, cand, old, synthetic} {
		seedImage(d, now.AddDate(0, 0, -100))
	}
	seedImage(fresh, now.AddDate(0, 0, -1))
	seedImage(pending, time.Time{})
	require.NoError(t, s.UpsertOwner(ctx, model.Owner{Ref: model.OwnerRef{Kind: "Deployment", Namespace: "shop", Name: "web"},
		Containers: []model.ContainerUse{{Name: "web", Repo: "ghcr.io/x", Digest: used}}}))
	require.NoError(t, s.PutSuggestion(ctx, "Deployment/shop/web", model.Suggestion{Repo: "ghcr.io/x", Tier: model.TierPatch, ComputedAt: now},
		[]CandidateDigest{{Tag: "1.1", Tier: model.TierPatch, Platform: "linux/amd64", Digest: cand}}))

	n, err := s.PruneImages(ctx, now.AddDate(0, 0, -90))
	require.NoError(t, err)
	require.Equal(t, 1, n)

	present := func(digest string) (image, pkgs, sbom, matches bool) {
		t.Helper()
		_, image, err := s.GetImage(ctx, digest)
		require.NoError(t, err)
		ps, err := s.PackagesForImage(ctx, digest)
		require.NoError(t, err)
		_, sbom, err = s.GetSBOM(ctx, digest)
		require.NoError(t, err)
		ms, err := s.MatchesForDigests(ctx, []string{digest})
		require.NoError(t, err)
		return image, len(ps) > 0, sbom, len(ms) > 0
	}
	image, pkgs, sbom, matches := present(old)
	require.False(t, image || pkgs || sbom || matches, "every row of the pruned image is gone")
	for _, d := range []string{used, cand, fresh, synthetic, pending} {
		image, pkgs, sbom, matches := present(d)
		require.True(t, image && pkgs && sbom && matches, d)
	}
	keyed, err := s.GrypeDigests(ctx)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{used, cand, fresh, synthetic, pending}, keyed)

	n, err = s.PruneImages(ctx, time.Time{})
	require.NoError(t, err)
	require.Zero(t, n)
}
