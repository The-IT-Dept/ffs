package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

func TestTransitionsCursorDurable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ffs.db")
	s, err := Open(ctx, path)
	require.NoError(t, err)
	require.NoError(t, s.ApplyFindings(ctx, []model.Finding{fd("fp-1", model.StateOpen, model.PriorityHigh)},
		[]model.Transition{tr("fp-1", "", model.StateOpen), tr("fp-1", model.StateOpen, model.StateOpen), tr("fp-2", "", model.StateOpen)}))
	all, _ := s.TransitionsAfter(ctx, 0, 100)
	require.Len(t, all, 3)
	require.Less(t, all[0].ID, all[1].ID)
	require.NoError(t, s.SetCursor(ctx, "notify", all[1].ID))
	require.NoError(t, s.Close())

	s, err = Open(ctx, path)
	require.NoError(t, err)
	reopened := s
	t.Cleanup(func() { require.NoError(t, reopened.Close()) })
	cur, _ := s.Cursor(ctx, "notify")
	require.Equal(t, all[1].ID, cur)
	rest, _ := s.TransitionsAfter(ctx, cur, 100)
	require.Len(t, rest, 1)
	require.Equal(t, all[2].ID, rest[0].ID)
	require.Equal(t, "fp-2", rest[0].Fingerprint)
	require.NoError(t, s.ApplyFindings(ctx, nil, []model.Transition{tr("fp-3", "", model.StateOpen)}))
	rest, _ = s.TransitionsAfter(ctx, cur, 100)
	require.Len(t, rest, 2)
	require.Greater(t, rest[1].ID, all[2].ID)
	other, _ := s.Cursor(ctx, "events")
	require.Zero(t, other)
}

func TestApplyFindings_Atomic(t *testing.T) {
	s := newStore(t)
	bad := tr("", "", model.StateOpen) // violates CHECK(fingerprint <> '') after the finding row was written in the same tx
	err := s.ApplyFindings(ctx, []model.Finding{fd("fp-1", model.StateOpen, model.PriorityUrgent)}, []model.Transition{tr("fp-1", "", model.StateOpen), bad})
	require.Error(t, err)
	fs, _ := s.ListFindings(ctx, FindingFilter{})
	require.Empty(t, fs)
	ts, _ := s.TransitionsAfter(ctx, 0, 0)
	require.Empty(t, ts)
}

func TestFindings_Queries(t *testing.T) {
	s := newStore(t)
	web := fd("fp-4", model.StateOpen, model.PriorityLow)
	web.Owner = model.OwnerRef{Kind: "Deployment", Namespace: "web", Name: "web"}
	web.AdvisoryID = "CVE-2026-0002"
	require.NoError(t, s.ApplyFindings(ctx, []model.Finding{
		fd("fp-1", model.StateOpen, model.PriorityHigh),
		fd("fp-2", model.StateExcepted, model.PriorityUrgent),
		fd("fp-3", model.StateResolved, model.PriorityMedium),
		web,
	}, nil))

	open, _ := s.ListFindings(ctx, FindingFilter{States: []model.FindingState{model.StateOpen}, MinPriority: model.PriorityHigh})
	require.Equal(t, []string{"fp-1"}, fps(open))
	byNS, _ := s.ListFindings(ctx, FindingFilter{Namespace: "web"})
	require.Equal(t, []string{"fp-4"}, fps(byNS))
	ordered, _ := s.ListFindings(ctx, FindingFilter{})
	require.Equal(t, []string{"fp-2", "fp-1", "fp-3", "fp-4"}, fps(ordered)) // priority DESC
	page, _ := s.ListFindings(ctx, FindingFilter{Limit: 2, Offset: 1})
	require.Equal(t, []string{"fp-1", "fp-3"}, fps(page))
	mine, _ := s.FindingsForOwner(ctx, "Deployment/netbox/netbox")
	require.Len(t, mine, 3) // every state, so Diff can see regressions
	require.NoError(t, s.UpsertAdvisory(ctx, model.Advisory{ID: "CVE-2026-0001", Aliases: []string{"GHSA-aaaa-bbbb-cccc"}}))
	owners, _ := s.OwnersWithAdvisories(ctx, []string{"GHSA-aaaa-bbbb-cccc"})
	require.Equal(t, []string{"Deployment/netbox/netbox"}, owners) // open+excepted, resolved via alias
	byAlias, _ := s.ListFindings(ctx, FindingFilter{AdvisoryIDs: []string{"GHSA-aaaa-bbbb-cccc"}})
	require.Equal(t, []string{"fp-2", "fp-1", "fp-3"}, fps(byAlias))
	unknown, _ := s.OwnersWithAdvisories(ctx, []string{"CVE-2026-0002"})
	require.Equal(t, []string{"Deployment/web/web"}, unknown) // an id with no alias row matches itself
}

func TestPruneResolved(t *testing.T) {
	s := newStore(t)
	recent := t0.Add(-24 * time.Hour)
	fresh := fd("fp-new", model.StateResolved, model.PriorityLow)
	fresh.ResolvedAt = &recent
	require.NoError(t, s.ApplyFindings(ctx, []model.Finding{fresh, fd("fp-open", model.StateOpen, model.PriorityLow)},
		[]model.Transition{tr("fp-new", model.StateOpen, model.StateResolved), tr("fp-open", "", model.StateOpen)}))
	long := t0.Add(-100 * 24 * time.Hour)
	stale := fd("fp-old", model.StateResolved, model.PriorityLow)
	stale.ResolvedAt = &long
	staleTr := tr("fp-old", model.StateOpen, model.StateResolved)
	staleTr.At = long
	require.NoError(t, s.ApplyFindings(ctx, []model.Finding{stale}, []model.Transition{staleTr}))

	all, _ := s.TransitionsAfter(ctx, 0, 0)
	maxBefore := all[len(all)-1].ID
	n, err := s.PruneResolved(ctx, t0.Add(-90*24*time.Hour))
	require.NoError(t, err)
	require.Equal(t, 1, n)
	left, _ := s.ListFindings(ctx, FindingFilter{})
	require.ElementsMatch(t, []string{"fp-new", "fp-open"}, fps(left))
	kept, _ := s.TransitionsAfter(ctx, 0, 0)
	require.Len(t, kept, len(all)-1) // only fp-old's history went
	require.NoError(t, s.ApplyFindings(ctx, nil, []model.Transition{tr("fp-open", model.StateOpen, model.StateResolved)}))
	next, _ := s.TransitionsAfter(ctx, 0, 0)
	require.Greater(t, next[len(next)-1].ID, maxBefore) // AUTOINCREMENT: the pruned max id is never reused
}

func TestRekeyFindings(t *testing.T) {
	s := newStore(t)
	ghsa := fd("fp-ghsa", model.StateOpen, model.PriorityHigh)
	ghsa.AdvisoryID = "GHSA-aaaa-bbbb-cccc"
	ghsa.Matched = t0.Add(-time.Hour)
	dupOld := fd("fp-dup-old", model.StateOpen, model.PriorityHigh)
	dupOld.AdvisoryID = "GHSA-dddd-eeee-ffff"
	dupNew := fd("fp-dup-new", model.StateOpen, model.PriorityHigh)
	dupNew.AdvisoryID = "CVE-2026-0002"
	require.NoError(t, s.ApplyFindings(ctx, []model.Finding{ghsa, dupOld, dupNew}, []model.Transition{tr("fp-ghsa", "", model.StateOpen)}))

	require.NoError(t, s.RekeyFindings(ctx, []FindingRekey{
		{OldFingerprint: "fp-ghsa", NewFingerprint: "fp-cve", AdvisoryID: "CVE-2026-0001"},
		{OldFingerprint: "fp-dup-old", NewFingerprint: "fp-dup-new", AdvisoryID: "CVE-2026-0002"},
	}))

	fs, err := s.ListFindings(ctx, FindingFilter{})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"fp-cve", "fp-dup-new"}, fps(fs))
	byAdvisory, _ := s.ListFindings(ctx, FindingFilter{AdvisoryIDs: []string{"CVE-2026-0001"}})
	require.Len(t, byAdvisory, 1) // the advisory_id column moved too
	cve := byAdvisory[0]
	require.Equal(t, "fp-cve", cve.Fingerprint)
	require.Equal(t, "CVE-2026-0001", cve.AdvisoryID)
	require.True(t, cve.Matched.Equal(ghsa.Matched))

	ts, _ := s.TransitionsAfter(ctx, 0, 0)
	require.Len(t, ts, 1)
	require.Equal(t, "fp-ghsa", ts[0].Fingerprint) // history keeps the old fingerprint
}

func TestRekeyFindings_LedgerKeepsTheHigherPriority(t *testing.T) {
	s := newStore(t)
	require.NoError(t, s.PutNotifyTarget(ctx, "uid-a", "a", ""))
	require.NoError(t, s.PutNotifyTarget(ctx, "uid-b", "b", ""))
	entry := func(target, fp string, p model.Priority, st model.FindingState, at time.Time) LedgerEntry {
		return LedgerEntry{Target: target, Fingerprint: fp, MaxPriority: p, LastState: st, UpdatedAt: at}
	}
	// Target a was told urgent about the new fingerprint and high about the old one; target b high
	// about the new one, later, and urgent about the old one.
	require.NoError(t, s.CommitNotify(ctx, NotifyCommit{Target: "uid-a", Ledger: []LedgerEntry{
		entry("uid-a", "fp-new", model.PriorityUrgent, model.StateOpen, t0.Add(-2*time.Hour)),
		entry("uid-a", "fp-old", model.PriorityHigh, model.StateResolved, t0.Add(-time.Hour)),
	}}))
	require.NoError(t, s.CommitNotify(ctx, NotifyCommit{Target: "uid-b", Ledger: []LedgerEntry{
		entry("uid-b", "fp-new", model.PriorityHigh, model.StateOpen, t0.Add(-time.Hour)),
		entry("uid-b", "fp-old", model.PriorityUrgent, model.StateResolved, t0.Add(-2*time.Hour)),
		entry("uid-b", "fp-only-old", model.PriorityMedium, model.StateOpen, t0),
	}}))
	require.NoError(t, s.ApplyFindings(ctx, []model.Finding{fd("fp-old", model.StateOpen, model.PriorityHigh),
		fd("fp-new", model.StateOpen, model.PriorityHigh), fd("fp-only-old", model.StateOpen, model.PriorityHigh)}, nil))

	require.NoError(t, s.RekeyFindings(ctx, []FindingRekey{
		{OldFingerprint: "fp-old", NewFingerprint: "fp-new", AdvisoryID: "CVE-2026-0001"},
		{OldFingerprint: "fp-only-old", NewFingerprint: "fp-moved", AdvisoryID: "CVE-2026-0001"},
	}))

	a, err := s.Ledger(ctx, "uid-a", []string{"fp-old", "fp-new"})
	require.NoError(t, err)
	require.Len(t, a, 1, "the old row merged into the new one")
	require.Equal(t, model.PriorityUrgent, a["fp-new"].MaxPriority, "a re-key never lowers what a target was told")
	require.Equal(t, model.StateResolved, a["fp-new"].LastState, "the state of the row updated last")
	require.True(t, a["fp-new"].UpdatedAt.Equal(t0.Add(-time.Hour)))

	b, err := s.Ledger(ctx, "uid-b", []string{"fp-old", "fp-new", "fp-only-old", "fp-moved"})
	require.NoError(t, err)
	require.Len(t, b, 2)
	require.Equal(t, model.PriorityUrgent, b["fp-new"].MaxPriority, "the old row's higher priority is kept")
	require.Equal(t, model.StateOpen, b["fp-new"].LastState)
	require.True(t, b["fp-new"].UpdatedAt.Equal(t0.Add(-time.Hour)))
	require.Equal(t, entry("uid-b", "fp-moved", model.PriorityMedium, model.StateOpen, b["fp-moved"].UpdatedAt), b["fp-moved"],
		"a row with nothing to merge with moves as it was")
	require.True(t, b["fp-moved"].UpdatedAt.Equal(t0))
}
