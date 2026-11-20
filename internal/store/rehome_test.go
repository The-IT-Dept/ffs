package store

import (
	"slices"
	"strings"
	"testing"
	"time"

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

// TestRehome_LedgerKeepsTheHigherPriority (F73): a move onto a fingerprint whose target already has a
// ledger row (its finding resolved, or gone) merges the two rows as an alias re-key does. The higher
// max_priority is kept, so the move never lowers what a target was told and a repeat escalation alert
// cannot follow; the state and time come from the row updated last.
func TestRehome_LedgerKeepsTheHigherPriority(t *testing.T) {
	s := newStore(t)
	require.NoError(t, s.PutNotifyTarget(ctx, "uid-a", "a", ""))
	require.NoError(t, s.PutNotifyTarget(ctx, "uid-b", "b", ""))
	rt := model.OwnerRef{Kind: model.OwnerKindContainerRuntime, Name: "containerd"}
	nodes := model.NodesOwner("test")
	fp := func(o model.OwnerRef, repo, adv string) string { return model.FindingFingerprint("test", o, repo, adv) }
	moved := model.Finding{Fingerprint: fp(rt, "containerd", "CVE-2026-0001"), Owner: rt, ImageRepo: "containerd",
		AdvisoryID: "CVE-2026-0001", State: model.StateOpen, Priority: model.PriorityHigh}
	resolved := model.Finding{Fingerprint: fp(nodes, model.HostRepo, "CVE-2026-0001"), Owner: nodes, ImageRepo: model.HostRepo,
		AdvisoryID: "CVE-2026-0001", State: model.StateResolved, Priority: model.PriorityUrgent}
	require.NoError(t, s.ApplyFindings(ctx, []model.Finding{moved, resolved}, nil))
	entry := func(target, fp string, p model.Priority, st model.FindingState, at time.Time) LedgerEntry {
		return LedgerEntry{Target: target, Fingerprint: fp, MaxPriority: p, LastState: st, UpdatedAt: at}
	}
	// Target a was told urgent about the target fingerprint, later than high about the moved one; target
	// b was told high about the target fingerprint, earlier than urgent about the moved one.
	require.NoError(t, s.CommitNotify(ctx, NotifyCommit{Target: "uid-a", Ledger: []LedgerEntry{
		entry("uid-a", resolved.Fingerprint, model.PriorityUrgent, model.StateResolved, t0.Add(-time.Hour)),
		entry("uid-a", moved.Fingerprint, model.PriorityHigh, model.StateOpen, t0.Add(-2*time.Hour)),
	}}))
	require.NoError(t, s.CommitNotify(ctx, NotifyCommit{Target: "uid-b", Ledger: []LedgerEntry{
		entry("uid-b", resolved.Fingerprint, model.PriorityHigh, model.StateResolved, t0.Add(-2*time.Hour)),
		entry("uid-b", moved.Fingerprint, model.PriorityUrgent, model.StateOpen, t0.Add(-time.Hour)),
	}}))

	require.NoError(t, s.Rehome(ctx, nil, []FindingMove{{OldFingerprint: moved.Fingerprint, NewFingerprint: resolved.Fingerprint,
		Owner: nodes, ImageRepo: model.HostRepo}}, nil))
	got, err := s.FindingsByFingerprint(ctx, []string{moved.Fingerprint, resolved.Fingerprint})
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, model.StateOpen, got[resolved.Fingerprint].State, "the moved finding replaces the resolved one")

	a, err := s.Ledger(ctx, "uid-a", []string{moved.Fingerprint, resolved.Fingerprint})
	require.NoError(t, err)
	require.Len(t, a, 1, "the moved row merged into the target's")
	require.Equal(t, model.PriorityUrgent, a[resolved.Fingerprint].MaxPriority, "a move never lowers what a target was told")
	require.Equal(t, model.StateResolved, a[resolved.Fingerprint].LastState, "the state of the row updated last")
	require.True(t, a[resolved.Fingerprint].UpdatedAt.Equal(t0.Add(-time.Hour)))

	b, err := s.Ledger(ctx, "uid-b", []string{moved.Fingerprint, resolved.Fingerprint})
	require.NoError(t, err)
	require.Len(t, b, 1)
	require.Equal(t, model.PriorityUrgent, b[resolved.Fingerprint].MaxPriority, "the moved row's higher priority is kept")
	require.Equal(t, model.StateOpen, b[resolved.Fingerprint].LastState)
	require.True(t, b[resolved.Fingerprint].UpdatedAt.Equal(t0.Add(-time.Hour)))
}

// TestRehomeWithState_WritesStateWithTheMoves: the runtime cutover's state is written in the moves'
// transaction, rolled back with them, and from then on the retired ContainerRuntime owner is never stored
// again by UpsertOwner.
func TestRehomeWithState_WritesStateWithTheMoves(t *testing.T) {
	s := newStore(t)
	rt := model.Owner{Ref: model.OwnerRef{Kind: model.OwnerKindContainerRuntime, Name: "containerd"},
		Containers: []model.ContainerUse{{Name: "containerd", Kind: model.ContainerRegular, Repo: "containerd", Digest: "runtime:containerd@2.1.4"}}}
	nodes := model.Owner{Ref: model.NodesOwner("prod"), Containers: []model.ContainerUse{{Name: "g", Kind: model.ContainerRegular,
		Repo: model.HostRepo, Digest: grpA}}}
	require.NoError(t, s.UpsertOwner(ctx, rt))
	f := model.Finding{Fingerprint: "fp-rt", Owner: rt.Ref, ImageRepo: "containerd", AdvisoryID: "CVE-2026-0001", State: model.StateOpen}
	require.NoError(t, s.ApplyFindings(ctx, []model.Finding{f}, nil))
	retired := NodesState{AgentEnabled: true, RuntimeRetired: true, ChangedAt: t0, BaselineReadyAt: t0}

	bad := []FindingMove{{OldFingerprint: "fp-rt", NewFingerprint: "", Owner: nodes.Ref, ImageRepo: model.HostRepo}}
	require.Error(t, s.RehomeWithState(ctx, &nodes, bad, []string{rt.Ref.Key()}, retired))
	st, err := s.NodesState(ctx)
	require.NoError(t, err)
	require.Equal(t, NodesState{}, st, "a failed cutover leaves the state as it was")

	move := FindingMove{OldFingerprint: "fp-rt", NewFingerprint: "fp-nodes", Owner: nodes.Ref, ImageRepo: model.HostRepo}
	require.NoError(t, s.RehomeWithState(ctx, &nodes, []FindingMove{move}, []string{rt.Ref.Key()}, retired))
	st, err = s.NodesState(ctx)
	require.NoError(t, err)
	require.Equal(t, retired, st)
	_, ok, err := s.GetOwner(ctx, rt.Ref.Key())
	require.NoError(t, err)
	require.False(t, ok)

	// A flush that read the state before the cutover stores nothing; other owners are stored as before.
	require.NoError(t, s.UpsertOwner(ctx, rt))
	_, ok, err = s.GetOwner(ctx, rt.Ref.Key())
	require.NoError(t, err)
	require.False(t, ok, "the retired runtime owner is not stored")
	cnpg := model.Owner{Ref: model.OwnerRef{Kind: model.OwnerKindContainerRuntime, Namespace: "db", Name: "containerd"}}
	require.NoError(t, s.UpsertOwner(ctx, cnpg))
	_, ok, err = s.GetOwner(ctx, cnpg.Ref.Key())
	require.NoError(t, err)
	require.True(t, ok, "a namespaced owner of the same kind is not the runtime owner")

	retired.RuntimeRetired = false // cut back: the owner is stored again
	require.NoError(t, s.RehomeWithState(ctx, nil, nil, nil, retired))
	require.NoError(t, s.UpsertOwner(ctx, rt))
	_, ok, err = s.GetOwner(ctx, rt.Ref.Key())
	require.NoError(t, err)
	require.True(t, ok)
}
