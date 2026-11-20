package store

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

func TestUnmatchedImages(t *testing.T) {
	s := newStore(t)
	at := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	for _, img := range []model.Image{
		{Digest: "sha256:a", Status: model.ImageCatalogued},
		{Digest: "sha256:b", Status: model.ImageCatalogued},
		{Digest: "sha256:c", Status: model.ImagePending},
	} {
		require.NoError(t, s.UpsertImage(ctx, img))
	}
	require.NoError(t, s.MarkUnmatched(ctx, "sha256:b", at))
	require.NoError(t, s.MarkUnmatched(ctx, "sha256:a", at.Add(time.Minute)))
	require.NoError(t, s.MarkUnmatched(ctx, "sha256:c", at))    // not catalogued: not listed
	require.NoError(t, s.MarkUnmatched(ctx, "sha256:gone", at)) // no image: dropped

	n, err := s.BeginMatch(ctx, "sha256:b")
	require.NoError(t, err)
	require.Equal(t, 1, n)
	n, err = s.BeginMatch(ctx, "sha256:b")
	require.NoError(t, err)
	require.Equal(t, 2, n)
	n, err = s.BeginMatch(ctx, "sha256:none")
	require.NoError(t, err)
	require.Zero(t, n)

	got, err := s.UnmatchedImages(ctx)
	require.NoError(t, err)
	require.Equal(t, []UnmatchedImage{{Digest: "sha256:b", Attempts: 2}, {Digest: "sha256:a"}}, got)

	ds, err := s.UnmatchedDigests(ctx, []string{"sha256:b", "sha256:none", "sha256:a"})
	require.NoError(t, err)
	require.Equal(t, []string{"sha256:a", "sha256:b"}, ds)

	require.NoError(t, s.MarkMatched(ctx, "sha256:b"))
	require.NoError(t, s.MarkUnmatched(ctx, "sha256:a", at)) // catalogued again: attempts reset
	got, err = s.UnmatchedImages(ctx)
	require.NoError(t, err)
	require.Equal(t, []UnmatchedImage{{Digest: "sha256:a"}}, got)

	ds, err = s.UnmatchedDigests(ctx, []string{"sha256:b", "sha256:a"})
	require.NoError(t, err)
	require.Equal(t, []string{"sha256:a"}, ds)
	ds, err = s.UnmatchedDigests(ctx, nil)
	require.NoError(t, err)
	require.Empty(t, ds)
}

func TestAcquisitionsInflight(t *testing.T) {
	s := newStore(t)
	at := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	stale, err := s.BeginAcquire(ctx, "sha256:a", at)
	require.NoError(t, err)
	require.False(t, stale)
	// Never ended: the next begin finds the previous attempt.
	stale, err = s.BeginAcquire(ctx, "sha256:a", at.Add(time.Minute))
	require.NoError(t, err)
	require.True(t, stale)
	require.NoError(t, s.EndAcquire(ctx, "sha256:a"))
	stale, err = s.BeginAcquire(ctx, "sha256:a", at)
	require.NoError(t, err)
	require.False(t, stale)
}

func TestOwnersOfExpiredQuarantine(t *testing.T) {
	s := newStore(t)
	now := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	for _, img := range []model.Image{
		{Digest: "sha256:failed-expired", Status: model.ImageCatalogFailed, QuarantinedUntil: now.Add(-time.Second)},
		{Digest: "sha256:failed-current", Status: model.ImageCatalogFailed, QuarantinedUntil: now.Add(time.Hour)},
		{Digest: "unknown:x:1", Status: model.ImageUnresolvable, QuarantinedUntil: now},
		{Digest: "sha256:ok", Status: model.ImageCatalogued},
	} {
		require.NoError(t, s.UpsertImage(ctx, img))
	}
	for key, digest := range map[string]string{
		"Deployment/a/x": "sha256:failed-expired", "Deployment/a/y": "sha256:failed-current",
		"CronJob/b/z": "unknown:x:1", "Deployment/c/w": "sha256:ok",
	} {
		parts := strings.SplitN(key, "/", 3)
		require.NoError(t, s.UpsertOwner(ctx, model.Owner{Ref: model.OwnerRef{Kind: parts[0], Namespace: parts[1], Name: parts[2]},
			Containers: []model.ContainerUse{{Name: "app", Digest: digest}}}))
	}
	got, err := s.OwnersOfExpiredQuarantine(ctx, now)
	require.NoError(t, err)
	require.Equal(t, []string{"CronJob/b/z", "Deployment/a/x"}, got)
}

func TestOwnersOfAgentImages(t *testing.T) {
	s := newStore(t)
	for _, img := range []model.Image{
		{Digest: "sha256:a", Status: model.ImageCatalogued, Source: "agent"},
		{Digest: "nodegroup:x", Status: model.ImageCatalogued, Source: "agent"},
		{Digest: "sha256:b", Status: model.ImageCatalogued, Source: "registry"},
		{Digest: "sha256:c", Status: model.ImagePending, Source: "agent"},
	} {
		require.NoError(t, s.UpsertImage(ctx, img))
	}
	for _, o := range []struct {
		ref    model.OwnerRef
		digest string
	}{
		{model.OwnerRef{Kind: "Pod", Namespace: "apps", Name: "web"}, "sha256:a"},
		{model.NodesOwner("prod"), "nodegroup:x"},
		{model.OwnerRef{Kind: "Pod", Namespace: "apps", Name: "db"}, "sha256:b"},
		{model.OwnerRef{Kind: "Pod", Namespace: "apps", Name: "new"}, "sha256:c"},
	} {
		require.NoError(t, s.UpsertOwner(ctx, model.Owner{Ref: o.ref, Containers: []model.ContainerUse{{Name: "app", Digest: o.digest}}}))
	}
	got, err := s.OwnersOfAgentImages(ctx)
	require.NoError(t, err)
	require.Equal(t, []string{"Pod/apps/web"}, got)
}

// FC-4: a new controller version lifts what crashes and stalls of the previous one counted against
// images and node host inventories, and keeps deterministic failures quarantined; the same version
// starting again changes nothing.
func TestResetCrashQuarantines_OnVersionChange(t *testing.T) {
	s := newStore(t)
	now := time.Date(2026, 11, 20, 7, 10, 0, 0, time.UTC)
	until := now.Add(24 * time.Hour)
	failed := func(digest, reason string) model.Image {
		return model.Image{Digest: digest, Repo: "ghcr.io/example/" + digest[7:], Status: model.ImageCatalogFailed, StatusReason: reason,
			Attempts: 2, QuarantinedUntil: until}
	}
	images := []model.Image{
		failed("sha256:stopped", "the controller stopped while processing the image"),
		failed("sha256:catstopped", "cataloguer stopped while processing the image"),
		failed("sha256:match", "matching the image did not complete"),
		failed("sha256:timeout", "cataloguer timed out after 10m0s"),
		failed("sha256:decode", "decoding SBOM"),
		failed("sha256:large", "SBOM of 70000000 bytes is larger than the 67108864 byte limit"),
		failed("sha256:scratch", "image unpacked beyond the cataloguer scratch limit"),
		{Digest: "sha256:unresolvable", Repo: "ghcr.io/example/private", Status: model.ImageUnresolvable, StatusReason: "stopped while processing",
			QuarantinedUntil: until},
	}
	for _, img := range images {
		require.NoError(t, s.UpsertImage(ctx, img))
	}
	job := func(digest, node, reason string) {
		t.Helper()
		for range 2 {
			_, err := s.RecordAgentJobFailure(ctx, digest, node, reason, now, 2, 24*time.Hour)
			require.NoError(t, err)
		}
	}
	job("nodehost:worker-1", "worker-1", "the controller stopped while processing the host inventory")
	job("nodehost:worker-2", "worker-2", "decoding SBOM: unexpected end of JSON input")
	job("nodehost:worker-3", "worker-3", "preparing the host inventory: panic: runtime error")
	job("sha256:agent-expired", "worker-1", "the node agent sent no result before the request expired")
	job("sha256:agent-oom", "worker-2", "catalog: cataloguer OOMKilled")
	job("sha256:agent-large", "worker-2", "SBOM of 70000000 bytes is larger than the 67108864 byte limit")
	for _, n := range []string{"worker-1", "worker-2"} {
		_, err := s.AcceptAgentReport(ctx, AgentReport{Node: n, BootID: "b", StartedAt: now, Seq: 1, At: now})
		require.NoError(t, err)
	}
	require.NoError(t, s.SetAgentError(ctx, "worker-1",
		"host inventory quarantined until 2026-11-21T07:10:00Z: the controller stopped while processing the host inventory"))
	require.NoError(t, s.SetAgentError(ctx, "worker-2", "host inventory quarantined until 2026-11-21T07:10:00Z: decoding SBOM: unexpected end"))
	// An image a crash interrupted mid-acquisition, whose earlier crash was counted; and one whose
	// counted failure was the image's own (no acquisition in flight).
	require.NoError(t, s.UpsertImage(ctx, model.Image{Digest: "sha256:inflight", Repo: "ghcr.io/example/inflight",
		Status: model.ImagePending, Attempts: 1}))
	require.NoError(t, s.UpsertImage(ctx, model.Image{Digest: "sha256:counted", Repo: "ghcr.io/example/counted",
		Status: model.ImagePending, Attempts: 1}))
	_, err := s.BeginAcquire(ctx, "sha256:inflight", now)
	require.NoError(t, err)
	_, err = s.BeginAcquire(ctx, "nodehost:worker-1", now)
	require.NoError(t, err)
	require.NoError(t, s.UpsertImage(ctx, model.Image{Digest: "sha256:unmatched", Repo: "ghcr.io/example/unmatched", Status: model.ImageCatalogued}))
	require.NoError(t, s.MarkUnmatched(ctx, "sha256:unmatched", now))
	for range 2 {
		_, err := s.BeginMatch(ctx, "sha256:unmatched")
		require.NoError(t, err)
	}

	r, changed, err := s.ResetCrashQuarantines(ctx, "v0.0.1-rc.7")
	require.NoError(t, err)
	require.True(t, changed, "no version was stored")
	require.Equal(t, CrashReset{Images: 4, Jobs: 3, Inflight: 2, Attempts: 1, Matches: 1, Errors: 1}, r)
	require.Equal(t, 12, r.Cleared())
	for digest, attempts := range map[string]int{"sha256:inflight": 0, "sha256:counted": 1} {
		img, _, err := s.GetImage(ctx, digest)
		require.NoError(t, err)
		require.Equal(t, model.ImagePending, img.Status, digest)
		require.Equal(t, attempts, img.Attempts, "%s: only an interrupted acquisition's attempts are reset", digest)
	}

	for _, d := range []string{"sha256:stopped", "sha256:catstopped", "sha256:match", "sha256:timeout"} {
		img, ok, err := s.GetImage(ctx, d)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, model.ImagePending, img.Status, d)
		require.Empty(t, img.StatusReason, d)
		require.Zero(t, img.Attempts, d)
		require.True(t, img.QuarantinedUntil.IsZero(), d)
	}
	for _, d := range []string{"sha256:decode", "sha256:large", "sha256:scratch"} {
		img, _, err := s.GetImage(ctx, d)
		require.NoError(t, err)
		require.Equal(t, model.ImageCatalogFailed, img.Status, "a deterministic failure stays quarantined: %s", d)
		require.True(t, img.QuarantinedUntil.Equal(until), d)
	}
	unresolvable, _, err := s.GetImage(ctx, "sha256:unresolvable")
	require.NoError(t, err)
	require.Equal(t, model.ImageUnresolvable, unresolvable.Status)

	for digest, kept := range map[string]bool{"nodehost:worker-1": false, "nodehost:worker-2": true, "nodehost:worker-3": true,
		"sha256:agent-expired": false, "sha256:agent-oom": false, "sha256:agent-large": true} {
		j, ok, err := s.AgentJobOf(ctx, digest)
		require.NoError(t, err)
		require.Equal(t, kept, ok, digest)
		if kept {
			require.True(t, j.QuarantinedUntil.Equal(until), digest)
		}
	}
	agents, err := s.AgentNodes(ctx)
	require.NoError(t, err)
	require.Len(t, agents, 2)
	require.Empty(t, agents[0].LastError, "worker-1: the lifted quarantine is no longer named")
	require.Contains(t, agents[1].LastError, "decoding SBOM", "worker-2")
	stale, err := s.BeginAcquire(ctx, "sha256:inflight", now)
	require.NoError(t, err)
	require.False(t, stale, "the previous controller's in-flight record does not count as a crash")
	un, err := s.UnmatchedImages(ctx)
	require.NoError(t, err)
	require.Equal(t, []UnmatchedImage{{Digest: "sha256:unmatched"}}, un)

	// The same version starting again: a crash of this build still counts.
	require.NoError(t, s.UpsertImage(ctx, failed("sha256:again", "the controller stopped while processing the image")))
	r, changed, err = s.ResetCrashQuarantines(ctx, "v0.0.1-rc.7")
	require.NoError(t, err)
	require.False(t, changed)
	require.Equal(t, CrashReset{Previous: "v0.0.1-rc.7"}, r)
	again, _, err := s.GetImage(ctx, "sha256:again")
	require.NoError(t, err)
	require.Equal(t, model.ImageCatalogFailed, again.Status)

	r, changed, err = s.ResetCrashQuarantines(ctx, "v0.0.1")
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, "v0.0.1-rc.7", r.Previous)
	require.Equal(t, 1, r.Images)
}
