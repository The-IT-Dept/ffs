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
		if f.ImageRepo == repo && f.AdvisoryID == "CVE-2026-0001" {
			require.Equal(t, &sg, f.Suggestion, f.Fingerprint)
		} else {
			require.Nil(t, f.Suggestion, "%s: the suggestion does not fix it", f.Fingerprint)
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

func TestStore_Announcements(t *testing.T) {
	s := newStore(t)
	const key, repo, other = "Deployment/netbox/netbox", "ghcr.io/x", "ghcr.io/y"
	f := fd("fp-x", model.StateOpen, model.PriorityHigh)
	require.NoError(t, s.ApplyFindings(ctx, []model.Finding{f}, nil))
	sg := model.Suggestion{Repo: repo, FromTag: "1.0", ToTag: "1.1", ToDigest: "sha256:idx", Tier: model.TierPatch, ComputedAt: t0}
	require.NoError(t, s.PutSuggestion(ctx, key, sg, []CandidateDigest{{Tag: "1.1", Tier: model.TierPatch, Platform: "linux/amd64", Digest: "sha256:cand"}}))
	announced := func(r string) (string, string, bool) {
		t.Helper()
		tag, digest, ok, err := s.Announced(ctx, key, r)
		require.NoError(t, err)
		return tag, digest, ok
	}
	_, _, ok := announced(repo)
	require.False(t, ok)

	up := model.Transition{Fingerprint: f.Fingerprint, Owner: f.Owner, AdvisoryID: f.AdvisoryID, FromState: model.StateOpen,
		ToState: model.StateOpen, FromPriority: model.PriorityHigh, ToPriority: model.PriorityHigh, Trigger: model.TriggerUpgradeAvailable, At: t0}
	require.NoError(t, s.AnnounceSuggestion(ctx, key, sg, []model.Transition{up}))
	ts, err := s.TransitionsAfter(ctx, 0, 0)
	require.NoError(t, err)
	require.Len(t, ts, 1)
	require.Equal(t, model.TriggerUpgradeAvailable, ts[0].Trigger)
	require.Equal(t, f.Fingerprint, ts[0].Fingerprint)
	tag, digest, ok := announced(repo)
	require.True(t, ok)
	require.Equal(t, []string{"1.1", "sha256:idx"}, []string{tag, digest})
	_, _, ok = announced(other)
	require.False(t, ok)

	require.NoError(t, s.DeleteSuggestions(ctx, key, nil))
	_, _, ok = announced(repo)
	require.True(t, ok, "a withdrawn suggestion keeps its announcement")

	require.NoError(t, s.DeleteAnnouncements(ctx, key, []string{}), "an empty list deletes nothing")
	require.NoError(t, s.DeleteAnnouncements(ctx, key, []string{other}))
	_, _, ok = announced(repo)
	require.True(t, ok)
	require.NoError(t, s.DeleteAnnouncements(ctx, key, []string{repo}))
	_, _, ok = announced(repo)
	require.False(t, ok)

	require.NoError(t, s.AnnounceSuggestion(ctx, key, sg, nil))
	require.NoError(t, s.DeleteAnnouncements(ctx, key, nil))
	_, _, ok = announced(repo)
	require.False(t, ok, "nil deletes every repository's")

	require.NoError(t, s.AnnounceSuggestion(ctx, key, sg, nil))
	require.NoError(t, s.DeleteOwner(ctx, key))
	_, _, ok = announced(repo)
	require.False(t, ok, "the owner's announcements go with it")
}

func TestStore_PruneImages(t *testing.T) {
	s := newStore(t)
	now := t0
	const (
		used, cand, old, revived = "sha256:d-used", "sha256:d-cand", "sha256:d-old", "sha256:d-revived"
		synthetic, pending       = "k8s:1.35.1", "sha256:d-pending"
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
	for _, d := range []string{used, cand, old, revived, synthetic} {
		seedImage(d, now.AddDate(0, 0, -100))
	}
	seedImage(pending, time.Time{})
	owner := model.Owner{Ref: model.OwnerRef{Kind: "Deployment", Namespace: "shop", Name: "web"},
		Containers: []model.ContainerUse{{Name: "web", Repo: "ghcr.io/x", Digest: used}}}
	require.NoError(t, s.UpsertOwner(ctx, owner))
	require.NoError(t, s.PutSuggestion(ctx, "Deployment/shop/web", model.Suggestion{Repo: "ghcr.io/x", Tier: model.TierPatch, ComputedAt: now},
		[]CandidateDigest{{Tag: "1.1", Tier: model.TierPatch, Platform: "linux/amd64", Digest: cand}}))

	// Acquisition records of an image that is pruned go with it; a used image keeps its own.
	for _, d := range []string{old, used} {
		require.NoError(t, s.MarkUnmatched(ctx, d, now))
		_, err := s.BeginAcquire(ctx, d, now)
		require.NoError(t, err)
	}

	week := 7 * 24 * time.Hour
	n, err := s.PruneImages(ctx, now, week)
	require.NoError(t, err)
	require.Zero(t, n, "an image is pruned a week after it is first seen unused, however old")
	// revived is used again: its unused clock stops
	owner.Containers = append(owner.Containers, model.ContainerUse{Name: "sidecar", Repo: "ghcr.io/x", Digest: revived})
	require.NoError(t, s.UpsertOwner(ctx, owner))
	n, err = s.PruneImages(ctx, now.Add(6*24*time.Hour), week)
	require.NoError(t, err)
	require.Zero(t, n)
	n, err = s.PruneImages(ctx, now.Add(8*24*time.Hour), week)
	require.NoError(t, err)
	require.Equal(t, 2, n)

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
	for _, d := range []string{old, pending} {
		image, pkgs, sbom, matches := present(d)
		require.False(t, image || pkgs || sbom || matches, "every row of the pruned image %s is gone", d)
	}
	for _, d := range []string{used, cand, revived, synthetic} {
		image, pkgs, sbom, matches := present(d)
		require.True(t, image && pkgs && sbom && matches, d)
	}
	keyed, err := s.GrypeDigests(ctx)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{used, cand, revived, synthetic}, keyed)
	unmatched, err := s.UnmatchedDigests(ctx, []string{old, used})
	require.NoError(t, err)
	require.Equal(t, []string{used}, unmatched)
	stale, err := s.BeginAcquire(ctx, old, now)
	require.NoError(t, err)
	require.False(t, stale, "a pruned image that comes back is not charged for an acquisition before its prune")
	stale, err = s.BeginAcquire(ctx, used, now)
	require.NoError(t, err)
	require.True(t, stale)

	_, err = s.PruneImages(ctx, time.Time{}, week)
	require.Error(t, err)
}

// TestStore_SuggestionOnlyOnFixedFindings is the regression test for F40 (and the finding side of
// F39): a stored suggestion is a finding's Suggestion only when the upgrade fixes that finding's
// advisory, so a finding no tag fixes never shows a target, and a tier-none suggestion is on none.
func TestStore_SuggestionOnlyOnFixedFindings(t *testing.T) {
	s := newStore(t)
	const key, repo = "Deployment/netbox/netbox", "ghcr.io/x"
	fixed := fd("fp-fixed", model.StateOpen, model.PriorityHigh)
	wontFix := fd("fp-wontfix", model.StateOpen, model.PriorityHigh)
	wontFix.AdvisoryID = "CVE-2026-0009"
	require.NoError(t, s.ApplyFindings(ctx, []model.Finding{fixed, wontFix}, nil))
	byFP := func() map[string]*model.Suggestion {
		t.Helper()
		fs, err := s.FindingsForOwner(ctx, key)
		require.NoError(t, err)
		out := map[string]*model.Suggestion{}
		for _, f := range fs {
			out[f.Fingerprint] = f.Suggestion
		}
		return out
	}

	sg := model.Suggestion{Repo: repo, FromTag: "1.27.3", ToTag: "1.27.4", Tier: model.TierPatch,
		Fixes: map[model.Priority]int{model.PriorityHigh: 1}, FixedIDs: []string{"CVE-2026-0001"}, ComputedAt: t0}
	require.NoError(t, s.PutSuggestion(ctx, key, sg, nil))
	require.Equal(t, map[string]*model.Suggestion{"fp-fixed": &sg, "fp-wontfix": nil}, byFP())

	// a recompute keeps it that way
	require.NoError(t, s.ApplyFindings(ctx, []model.Finding{fixed, wontFix}, nil))
	require.Equal(t, map[string]*model.Suggestion{"fp-fixed": &sg, "fp-wontfix": nil}, byFP())

	// a new suggestion that fixes the other advisory moves to it
	other := sg
	other.ToTag, other.FixedIDs = "1.28.0", []string{"CVE-2026-0009"}
	require.NoError(t, s.PutSuggestion(ctx, key, other, nil))
	require.Equal(t, map[string]*model.Suggestion{"fp-fixed": nil, "fp-wontfix": &other}, byFP())

	// nothing in the line fixes anything: the owner-level suggestion is stored, no finding carries it
	none := model.Suggestion{Repo: repo, FromTag: "1.27.3", Tier: model.TierNone, Notes: []string{"no upgrade path in this repository"},
		Alternatives: []model.Suggestion{{Repo: repo, FromTag: "1.27.3", ToTag: "2.0.0", Tier: model.TierMajor,
			FixedIDs: []string{"CVE-2026-0001"}}}, ComputedAt: t0}
	require.NoError(t, s.PutSuggestion(ctx, key, none, nil))
	require.Equal(t, map[string]*model.Suggestion{"fp-fixed": nil, "fp-wontfix": nil}, byFP())
	require.NoError(t, s.ApplyFindings(ctx, []model.Finding{fixed, wontFix}, nil))
	require.Equal(t, map[string]*model.Suggestion{"fp-fixed": nil, "fp-wontfix": nil}, byFP())
	got, ok, err := s.GetSuggestion(ctx, key, repo)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, model.TierNone, got.Suggestion.Tier)
}

func TestStore_SuggestionStaleAndApplied(t *testing.T) {
	s := newStore(t)
	const key, repo = "Deployment/netbox/netbox", "ghcr.io/x"
	sg := model.Suggestion{Repo: repo, FromTag: "1.0", ToTag: "1.1", ToDigest: "sha256:idx", Tier: model.TierPatch,
		FixedIDs: []string{"CVE-2026-0001"}, ComputedAt: t0}
	cands := []CandidateDigest{{Tag: "1.1", Tier: model.TierPatch, Platform: "linux/amd64", Digest: "sha256:cand"}}
	applied := &AppliedUpgrade{Tag: "1.0", Tier: model.TierPatch, Digests: []string{"sha256:run"}, FixedIDs: []string{"CVE-2026-0009"}}
	require.NoError(t, s.PutSuggestionApplied(ctx, key, sg, cands, applied))

	got, ok, err := s.GetSuggestion(ctx, key, repo)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, OwnerSuggestion{OwnerKey: key, Suggestion: sg, Candidates: cands, Applied: applied}, got)

	require.NoError(t, s.MarkSuggestionsStale(ctx, []SuggestionKey{{key, repo}, {"Deployment/x/y", repo}}))
	got, _, err = s.GetSuggestion(ctx, key, repo)
	require.NoError(t, err)
	require.True(t, got.Stale)
	require.Equal(t, applied, got.Applied, "marking stale keeps the rest")

	has, err := s.OwnersWithSuggestions(ctx, []string{key, "Deployment/x/y"})
	require.NoError(t, err)
	require.Equal(t, map[string]bool{key: true}, has)

	require.NoError(t, s.PutSuggestion(ctx, key, sg, cands))
	got, _, err = s.GetSuggestion(ctx, key, repo)
	require.NoError(t, err)
	require.False(t, got.Stale, "storing it again makes it current")
	require.Nil(t, got.Applied)
}

func TestStore_OwnersToResolve(t *testing.T) {
	s := newStore(t)
	finding := func(owner model.OwnerRef, repo, id string, p model.Priority, fixable bool) model.Finding {
		return model.Finding{Fingerprint: model.FindingFingerprint("test", owner, repo, id), Owner: owner, ImageRepo: repo,
			AdvisoryID: id, State: model.StateOpen, Priority: p, FixAvailable: fixable}
	}
	web := model.OwnerRef{Kind: "Deployment", Namespace: "shop", Name: "web"}
	api := model.OwnerRef{Kind: "Deployment", Namespace: "shop", Name: "api"}
	low := model.OwnerRef{Kind: "Deployment", Namespace: "shop", Name: "low"}
	nofix := model.OwnerRef{Kind: "Deployment", Namespace: "shop", Name: "nofix"}
	cluster := model.OwnerRef{Kind: model.OwnerKindCluster, Name: "test"}
	nodes := model.NodesOwner("test")
	cnpg := model.OwnerRef{Kind: model.OwnerKindCluster, Namespace: "db", Name: "pg"} // a workload of kind Cluster
	excepted := finding(api, "ghcr.io/b", "CVE-2026-0006", model.PriorityUrgent, true)
	excepted.State = model.StateExcepted
	require.NoError(t, s.ApplyFindings(ctx, []model.Finding{
		finding(web, "ghcr.io/a", "CVE-2026-0001", model.PriorityHigh, true),
		finding(api, "ghcr.io/a", "CVE-2026-0002", model.PriorityMedium, true),
		excepted,
		finding(low, "ghcr.io/a", "CVE-2026-0003", model.PriorityLow, true),
		finding(nofix, "ghcr.io/a", "CVE-2026-0004", model.PriorityHigh, false),
		finding(cluster, "kubernetes", "CVE-2026-0005", model.PriorityHigh, false),
		finding(nodes, model.HostRepo, "CVE-2026-0007", model.PriorityHigh, true),
		finding(cnpg, "ghcr.io/c", "CVE-2026-0008", model.PriorityHigh, false),
	}, nil))
	sg := func(repo string) model.Suggestion {
		return model.Suggestion{Repo: repo, Tier: model.TierNone, ComputedAt: t0}
	}
	require.NoError(t, s.PutSuggestion(ctx, web.Key(), sg("ghcr.io/a"), nil))

	got, err := s.OwnersToResolve(ctx)
	require.NoError(t, err)
	require.Equal(t, []string{cluster.Key(), api.Key()}, got)

	require.NoError(t, s.PutSuggestion(ctx, api.Key(), sg("ghcr.io/a"), nil))
	require.NoError(t, s.PutSuggestion(ctx, cluster.Key(), sg("kubernetes"), nil))
	got, err = s.OwnersToResolve(ctx)
	require.NoError(t, err)
	require.Empty(t, got)

	require.NoError(t, s.MarkSuggestionsStale(ctx, []SuggestionKey{{web.Key(), "ghcr.io/a"}}))
	got, err = s.OwnersToResolve(ctx)
	require.NoError(t, err)
	require.Equal(t, []string{web.Key()}, got)
}
