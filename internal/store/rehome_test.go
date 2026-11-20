package store

import (
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

var grpA = model.NodeGroupDigestPrefix + strings.Repeat("a", 64)

// TestRehome_MovesFindingsLedgerAndOwnersAtomically (Review Focus 3).
func TestRehome_MovesFindingsLedgerAndOwnersAtomically(t *testing.T) {
	s := newStore(t)
	rt := model.OwnerRef{Kind: model.OwnerKindContainerRuntime, Name: "containerd"}
	nodes := model.NodesOwner("prod")
	const rtDigest = "runtime:containerd@2.1.4"
	nodesOwner := model.Owner{Ref: nodes, Containers: []model.ContainerUse{{Name: "g", Kind: model.ContainerRegular,
		ImageRef: "g", Repo: model.HostRepo, Digest: grpA}}}
	require.NoError(t, s.UpsertOwner(ctx, model.Owner{Ref: rt, Containers: []model.ContainerUse{{Name: "containerd",
		Kind: model.ContainerRegular, ImageRef: "containerd://2.1.4", Repo: "containerd", Digest: rtDigest}}}))
	require.NoError(t, s.PutSuggestion(ctx, rt.Key(), model.Suggestion{Repo: "containerd", FromTag: "2.1.4", ToTag: "2.1.5"}, nil))
	fp := func(o model.OwnerRef, repo, adv string) string { return model.FindingFingerprint("prod", o, repo, adv) }
	f := func(o model.OwnerRef, repo, adv string, st model.FindingState, p model.Priority) model.Finding {
		return model.Finding{Fingerprint: fp(o, repo, adv), Owner: o, ImageRepo: repo, AdvisoryID: adv, State: st, Priority: p}
	}
	open1 := f(rt, "containerd", "CVE-2026-0001", model.StateOpen, model.PriorityHigh)    // to a free fingerprint
	exc2 := f(rt, "containerd", "CVE-2026-0002", model.StateExcepted, model.PriorityHigh) // replaces a resolved row
	res2 := f(nodes, model.HostRepo, "CVE-2026-0002", model.StateResolved, model.PriorityMedium)
	open3 := f(rt, "containerd", "CVE-2026-0003", model.StateOpen, model.PriorityHigh) // target already open
	keep3 := f(nodes, model.HostRepo, "CVE-2026-0003", model.StateOpen, model.PriorityUrgent)
	old4 := f(rt, "containerd", "CVE-2026-0004", model.StateResolved, model.PriorityLow) // not moved
	require.NoError(t, s.ApplyFindings(ctx, []model.Finding{open1, exc2, res2, open3, keep3, old4}, nil))
	require.NoError(t, s.CommitNotify(ctx, NotifyCommit{Target: "u1", Ledger: []LedgerEntry{
		ledgerEntry(open1.Fingerprint, model.PriorityHigh, model.StateOpen),
		ledgerEntry(open3.Fingerprint, model.PriorityHigh, model.StateOpen),
		ledgerEntry(keep3.Fingerprint, model.PriorityUrgent, model.StateOpen)}}))
	move := func(old model.Finding) FindingMove {
		return FindingMove{OldFingerprint: old.Fingerprint, NewFingerprint: fp(nodes, model.HostRepo, old.AdvisoryID),
			Owner: nodes, ImageRepo: model.HostRepo}
	}
	moves := []FindingMove{move(open1), move(exc2), move(open3)}

	// A failing move rolls the whole call back.
	bad := append(slices.Clone(moves), FindingMove{OldFingerprint: old4.Fingerprint, NewFingerprint: "", Owner: nodes, ImageRepo: model.HostRepo})
	require.Error(t, s.Rehome(ctx, &nodesOwner, bad, []string{rt.Key()}))
	_, ok, _ := s.GetOwner(ctx, nodes.Key())
	require.False(t, ok)
	_, ok, _ = s.GetOwner(ctx, rt.Key())
	require.True(t, ok)
	got, _ := s.FindingsByFingerprint(ctx, []string{open1.Fingerprint})
	require.Contains(t, got, open1.Fingerprint)

	require.NoError(t, s.Rehome(ctx, &nodesOwner, moves, []string{rt.Key()}))
	got, err := s.FindingsByFingerprint(ctx, []string{open1.Fingerprint, open3.Fingerprint, old4.Fingerprint,
		fp(nodes, model.HostRepo, "CVE-2026-0001"), fp(nodes, model.HostRepo, "CVE-2026-0002"), keep3.Fingerprint})
	require.NoError(t, err)
	n1 := got[fp(nodes, model.HostRepo, "CVE-2026-0001")]
	require.Equal(t, nodes, n1.Owner)
	require.Equal(t, model.HostRepo, n1.ImageRepo)
	require.Equal(t, model.StateOpen, n1.State)
	require.Equal(t, model.PriorityHigh, n1.Priority)
	require.NotContains(t, got, open1.Fingerprint)
	require.Equal(t, model.StateExcepted, got[fp(nodes, model.HostRepo, "CVE-2026-0002")].State) // resolved row replaced
	require.NotContains(t, got, open3.Fingerprint)
	require.Equal(t, model.PriorityUrgent, got[keep3.Fingerprint].Priority) // taken target kept
	require.Equal(t, rt, got[old4.Fingerprint].Owner)                       // resolved: not moved
	byOwner, _ := s.ListFindings(ctx, FindingFilter{OwnerKey: nodes.Key()})
	require.Len(t, byOwner, 3)

	l, _ := s.Ledger(ctx, "u1", []string{fp(nodes, model.HostRepo, "CVE-2026-0001"), open1.Fingerprint, open3.Fingerprint, keep3.Fingerprint})
	require.Equal(t, model.PriorityHigh, l[fp(nodes, model.HostRepo, "CVE-2026-0001")].MaxPriority)
	require.NotContains(t, l, open1.Fingerprint)
	require.NotContains(t, l, open3.Fingerprint)
	require.Equal(t, model.PriorityUrgent, l[keep3.Fingerprint].MaxPriority) // target keeps its ledger

	_, ok, _ = s.GetOwner(ctx, rt.Key())
	require.False(t, ok)
	keys, _ := s.OwnersForDigests(ctx, []string{rtDigest, grpA})
	require.Equal(t, []string{nodes.Key()}, keys)
	_, ok, _ = s.GetSuggestion(ctx, rt.Key(), "containerd")
	require.False(t, ok)
}
