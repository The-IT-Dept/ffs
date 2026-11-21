package notify_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/notify"
)

// digestHarness registers a target with a 09:00 Sydney digest at medium and sends its baseline at
// 10:00 AEDT on 19 Nov, so the first digest is due at 09:00 AEDT on 20 Nov.
func digestHarness(t *testing.T, includeResolved bool) *harness {
	t.Helper()
	sydney, err := time.LoadLocation("Australia/Sydney")
	require.NoError(t, err)
	h := newHarness(t)
	h.at("2026-11-19T10:00+11:00")
	h.target("ops", func(c *notify.TargetConfig) {
		c.Digest = notify.DigestConfig{Schedule: "0 9 * * *", Location: sydney, MinPriority: medium, IncludeResolved: includeResolved}
	})
	h.process()
	require.Len(t, h.sink.ofKind(notify.KindBaseline), 1)
	return h
}

// ids lists the advisory IDs of m's items with event ev, in message order.
func ids(m notify.Message, ev notify.Event) []string {
	var out []string
	for _, it := range m.Items {
		if it.Event == ev {
			out = append(out, it.AdvisoryID)
		}
	}
	return out
}

func onlyItem(t *testing.T, m notify.Message) notify.Item {
	t.Helper()
	require.Len(t, m.Items, 1)
	return m.Items[0]
}

func TestDigest_SectionsAtScheduleAndSkipWhenEmpty(t *testing.T) {
	h := digestHarness(t, true)
	h.at("2026-11-19T12:00+11:00")
	a := h.open(dep("shop", "a"), "CVE-A", medium)
	h.open(dep("shop", "b"), "CVE-B", low)
	c := h.open(dep("shop", "c"), "CVE-C", medium)
	e := h.open(dep("shop", "e"), "CVE-E", medium)
	h.process()
	assert.Empty(t, h.sink.ofKind(notify.KindImmediate))

	h.at("2026-11-20T08:59+11:00")
	h.process()
	assert.Empty(t, h.sink.ofKind(notify.KindDigest))
	h.at("2026-11-20T09:00+11:00")
	h.process()
	d1 := h.sink.lastOfKind(notify.KindDigest)
	assert.Equal(t, []string{"CVE-A", "CVE-C", "CVE-E"}, ids(d1, notify.EventDetected)) // B (low) excluded
	assert.Equal(t, "ffs digest for test: 3 new, 0 escalated, 0 fixes available, 0 resolved", d1.Title)
	require.NotNil(t, d1.Summary)
	assert.Equal(t, 3, d1.Summary.Workloads)
	assert.Equal(t, map[model.Priority]int{medium: 3}, d1.Summary.Counts)

	h.at("2026-11-20T12:00+11:00")
	h.move(c, model.StateOpen, high, model.TriggerPriorityChange)
	h.move(a, model.StateOpen, medium, model.TriggerFixAvailable)
	h.open(dep("shop", "d"), "CVE-D", urgent)
	h.process() // D is sent immediately
	require.Len(t, h.sink.ofKind(notify.KindImmediate), 1)
	h.move(e, model.StateResolved, medium, model.TriggerInventoryChange)
	h.process()
	assert.Len(t, h.sink.ofKind(notify.KindImmediate), 1) // E was never sent at the immediate level

	h.at("2026-11-21T09:00+11:00")
	h.process()
	d2 := h.sink.lastOfKind(notify.KindDigest)
	assert.Equal(t, "ffs digest for test: 0 new, 1 escalated, 1 fix available, 1 resolved", d2.Title)
	assert.Empty(t, ids(d2, notify.EventDetected)) // D already sent immediately
	assert.Equal(t, []string{"CVE-C"}, ids(d2, notify.EventEscalated))
	assert.Equal(t, []string{"CVE-A"}, ids(d2, notify.EventFixAvailable))
	assert.Equal(t, []string{"CVE-E"}, ids(d2, notify.EventResolved))
	assert.NotEqual(t, d1.ID, d2.ID)

	h.at("2026-11-22T09:00+11:00")
	h.process()
	assert.Len(t, h.sink.ofKind(notify.KindDigest), 2) // nothing changed → nothing sent
}

func TestDigest_IncludeResolvedFalse(t *testing.T) {
	h := digestHarness(t, false)
	h.at("2026-11-19T12:00+11:00")
	a := h.open(dep("shop", "a"), "CVE-A", medium)
	h.at("2026-11-20T09:00+11:00")
	h.process()
	assert.Equal(t, []string{"CVE-A"}, ids(h.sink.lastOfKind(notify.KindDigest), notify.EventDetected))

	h.at("2026-11-20T12:00+11:00")
	h.move(a, model.StateResolved, medium, model.TriggerInventoryChange)
	h.open(dep("shop", "b"), "CVE-B", medium)
	h.at("2026-11-21T09:00+11:00")
	h.process()
	d2 := h.sink.lastOfKind(notify.KindDigest)
	assert.Equal(t, []string{"CVE-B"}, ids(d2, notify.EventDetected))
	assert.Empty(t, ids(d2, notify.EventResolved)) // the resolved finding never appears
	l, err := h.st.Ledger(ctx, "uid-ops", []string{a})
	require.NoError(t, err)
	assert.Equal(t, model.StateResolved, l[a].LastState) // the ledger still records it

	h.at("2026-11-21T12:00+11:00")
	h.move(a, model.StateOpen, medium, model.TriggerInventoryChange)
	h.at("2026-11-22T09:00+11:00")
	h.process()
	assert.Equal(t, []string{"CVE-A"}, ids(h.sink.lastOfKind(notify.KindDigest), notify.EventReopened))
}

func TestDigest_GroupsGoStdlibPerVersion(t *testing.T) {
	h := digestHarness(t, true)
	h.at("2026-11-19T12:00+11:00")
	owner := dep("shop", "api")
	h.open(owner, "GO-2026-0001", medium, stdlib("1.22.5"))
	h.open(owner, "GO-2026-0002", medium, stdlib("1.22.12"))
	h.open(owner, "GO-2026-0003", medium, stdlib("1.22.7"))
	h.at("2026-11-20T09:00+11:00")
	h.process()

	it := onlyItem(t, h.sink.lastOfKind(notify.KindDigest))
	assert.Equal(t, "Go 1.22.3 standard library: 3 advisories, fixed in Go 1.22.12", it.Title)
	assert.Len(t, it.Grouped, 3)
	assert.Empty(t, it.AdvisoryID)
	assert.Equal(t, notify.EventDetected, it.Event)
	assert.Equal(t, medium, it.Priority)
	assert.Equal(t, []string{"1.22.12"}, it.FixedIn)
	assert.Equal(t, []model.OwnerRef{owner}, it.Owners)
}

// TestDigest_BaselineFindingsBelowThresholdStayOut pins F34: the baseline records low findings
// too, but their fixes and resolutions are not listed by a digest whose minimum is medium, so no
// digest goes out on a day when nothing at or above medium changed. Their ledger still moves.
func TestDigest_BaselineFindingsBelowThresholdStayOut(t *testing.T) {
	sydney, err := time.LoadLocation("Australia/Sydney")
	require.NoError(t, err)
	h := newHarness(t)
	h.at("2026-11-19T10:00+11:00")
	lowFix := h.open(dep("shop", "a"), "CVE-L1", low)
	lowGone := h.open(dep("shop", "b"), "CVE-L2", low)
	medFix := h.open(dep("shop", "c"), "CVE-M1", medium)
	h.target("ops", func(c *notify.TargetConfig) {
		c.Digest = notify.DigestConfig{Schedule: "0 9 * * *", Location: sydney, MinPriority: medium, IncludeResolved: true}
	})
	h.process()
	require.Len(t, h.sink.ofKind(notify.KindBaseline), 1)

	h.at("2026-11-19T12:00+11:00")
	h.move(lowFix, model.StateOpen, low, model.TriggerFixAvailable)
	h.move(lowGone, model.StateResolved, low, model.TriggerInventoryChange)
	h.at("2026-11-20T09:00+11:00")
	h.process()
	assert.Empty(t, h.sink.ofKind(notify.KindDigest), "nothing at or above medium changed")
	l, err := h.st.Ledger(ctx, "uid-ops", []string{lowGone})
	require.NoError(t, err)
	assert.Equal(t, model.StateResolved, l[lowGone].LastState, "the resolution is still recorded")

	h.at("2026-11-20T12:00+11:00")
	h.move(medFix, model.StateOpen, medium, model.TriggerFixAvailable)
	h.at("2026-11-21T09:00+11:00")
	h.process()
	d := h.sink.lastOfKind(notify.KindDigest)
	assert.Equal(t, "ffs digest for test: 0 new, 0 escalated, 1 fix available, 0 resolved", d.Title)
	assert.Equal(t, []string{"CVE-M1"}, ids(d, notify.EventFixAvailable))
}

// TestDigest_UpgradeAfterImmediateAlert pins F41: an urgent alert goes out before the upgrade
// resolver has scored candidates, so it cannot carry the suggested upgrade spec §6.10 asks for.
// The next digest lists the upgrade once announced, once, and it is never an alert of its own.
func TestDigest_UpgradeAfterImmediateAlert(t *testing.T) {
	h := digestHarness(t, true)
	h.at("2026-11-19T12:00+11:00")
	web, api := dep("shop", "web"), dep("shop", "api")
	fp := h.open(web, "CVE-U1", urgent)
	h.open(api, "CVE-U2", urgent) // alerted too, but no upgrade is announced for it
	h.process()
	imm := h.sink.ofKind(notify.KindImmediate)
	require.Len(t, imm, 2)
	for _, m := range imm {
		assert.Nil(t, m.Items[0].Suggestion, "the alert went out before any suggestion existed")
	}

	// The resolver stores the suggestion and announces it for the finding it fixes.
	h.at("2026-11-19T12:01+11:00")
	sg := model.Suggestion{Repo: "registry.example/app", FromTag: "1.0.0", ToTag: "1.0.1", ToDigest: "sha256:new",
		Tier: model.TierPatch, Fixes: map[model.Priority]int{urgent: 1}, FixedIDs: []string{"CVE-U1"}}
	require.NoError(t, h.st.PutSuggestion(ctx, web.Key(), sg, nil))
	require.NoError(t, h.st.AnnounceSuggestion(ctx, web.Key(), sg, []model.Transition{{Fingerprint: fp, Owner: web,
		AdvisoryID: "CVE-U1", FromState: model.StateOpen, ToState: model.StateOpen, FromPriority: urgent, ToPriority: urgent,
		Trigger: model.TriggerUpgradeAvailable, At: h.now}}))
	h.process()
	assert.Len(t, h.sink.ofKind(notify.KindImmediate), 2, "an upgrade is never an alert of its own")

	h.at("2026-11-20T09:00+11:00")
	h.process()
	d := h.sink.lastOfKind(notify.KindDigest)
	assert.Equal(t, "ffs digest for test: 0 new, 0 escalated, 0 fixes available, 0 resolved, 1 upgrade available", d.Title)
	it := onlyItem(t, d)
	assert.Equal(t, notify.EventUpgradeAvailable, it.Event)
	assert.Equal(t, "CVE-U1", it.AdvisoryID)
	assert.Equal(t, []model.OwnerRef{web}, it.Owners)
	require.NotNil(t, it.Suggestion)
	assert.Equal(t, "1.0.1", it.Suggestion.ToTag)
	assert.Equal(t, map[model.Priority]int{urgent: 1}, it.Suggestion.Fixes)

	h.at("2026-11-21T09:00+11:00")
	h.process()
	assert.Len(t, h.sink.ofKind(notify.KindDigest), 1, "the upgrade is listed once")
}

// TestDigest_UpgradeNotListedForUnreportedOrBelowThreshold keeps the upgrade section to findings
// the target was told about at a level it cares about.
func TestDigest_UpgradeNotListedForUnreportedOrBelowThreshold(t *testing.T) {
	h := newHarness(t)
	h.at("2026-11-19T00:00Z")
	owner := dep("shop", "web")
	low := h.open(owner, "CVE-LOW", model.PriorityLow) // in the baseline at low; the digest minimum is medium
	h.target("ops")
	h.process()

	sg := model.Suggestion{Repo: "registry.example/app", FromTag: "1.0.0", ToTag: "1.0.1", Tier: model.TierPatch,
		Fixes: map[model.Priority]int{model.PriorityLow: 1}, FixedIDs: []string{"CVE-LOW"}}
	require.NoError(t, h.st.PutSuggestion(ctx, owner.Key(), sg, nil))
	require.NoError(t, h.st.AnnounceSuggestion(ctx, owner.Key(), sg, []model.Transition{{Fingerprint: low, Owner: owner,
		AdvisoryID: "CVE-LOW", FromState: model.StateOpen, ToState: model.StateOpen, FromPriority: model.PriorityLow,
		ToPriority: model.PriorityLow, Trigger: model.TriggerUpgradeAvailable, At: h.now}}))
	h.at("2026-11-19T09:00Z")
	h.process()
	assert.Empty(t, h.sink.ofKind(notify.KindDigest))
}

// TestDigest_CountsFindingsLikeTheBaseline pins F97: the digest's summary counts findings, as the
// baseline's does, not advisory items: three workloads with one advisory and one with another are
// four findings in four workloads.
func TestDigest_CountsFindingsLikeTheBaseline(t *testing.T) {
	h := digestHarness(t, true)
	h.at("2026-11-19T12:00+11:00")
	for _, w := range []string{"a", "b", "c"} {
		h.open(dep("shop", w), "CVE-A", medium)
	}
	h.open(dep("shop", "d"), "CVE-B", high)
	h.at("2026-11-20T09:00+11:00")
	h.process()
	d := h.sink.lastOfKind(notify.KindDigest)
	require.Len(t, d.Items, 2)
	require.NotNil(t, d.Summary)
	assert.Equal(t, 4, d.Summary.Findings)
	assert.Equal(t, 4, d.Summary.Workloads)
	assert.Equal(t, map[model.Priority]int{medium: 3, high: 1}, d.Summary.Counts)
}

// TestDigest_TitleCountsFindings pins W37: the digest title counts findings, as its summary does, not
// the advisory items it lists: one advisory in three workloads is three new findings.
func TestDigest_TitleCountsFindings(t *testing.T) {
	h := digestHarness(t, true)
	h.at("2026-11-19T12:00+11:00")
	for _, w := range []string{"a", "b", "c"} {
		h.open(dep("shop", w), "CVE-A", medium)
	}
	h.open(dep("shop", "d"), "CVE-B", high)
	h.process()
	h.at("2026-11-20T09:00+11:00")
	h.process()
	d := h.sink.lastOfKind(notify.KindDigest)
	assert.Equal(t, []string{"CVE-B", "CVE-A"}, ids(d, notify.EventDetected))
	assert.Equal(t, "ffs digest for test: 4 new, 0 escalated, 0 fixes available, 0 resolved", d.Title)
	require.NotNil(t, d.Summary)
	assert.Equal(t, 4, d.Summary.Findings)
	assert.Equal(t, 4, d.Summary.Workloads)
}
