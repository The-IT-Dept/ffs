package notify_test

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/notify"
	"github.com/the-it-dept/ffs/internal/store"
)

const (
	urgent = model.PriorityUrgent
	high   = model.PriorityHigh
	medium = model.PriorityMedium
	low    = model.PriorityLow
)

var ctx = context.Background()

// fakeSink records the messages it sends. failNext makes the next n sends fail; cancelOnCall
// cancels a context on the n-th send from now, as a process dying mid-send would.
type fakeSink struct {
	mu        sync.Mutex
	sent      []notify.Message
	calls     int
	fails     int
	failErr   error
	cancelAt  int
	cancelCtx context.CancelFunc
}

func (s *fakeSink) Type() string { return "slack" }

func (s *fakeSink) Send(ctx context.Context, m notify.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.cancelCtx != nil && s.calls == s.cancelAt {
		s.cancelCtx()
		return ctx.Err()
	}
	if s.fails > 0 {
		s.fails--
		return s.failErr
	}
	s.sent = append(s.sent, m)
	return nil
}

func (s *fakeSink) failNext(n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fails, s.failErr = n, err
}

func (s *fakeSink) cancelOnCall(n int, cancel context.CancelFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cancelAt, s.cancelCtx = s.calls+n, cancel
}

func (s *fakeSink) ofKind(k notify.Kind) []notify.Message {
	var out []notify.Message
	for _, m := range s.sent {
		if m.Kind == k {
			out = append(out, m)
		}
	}
	return out
}

func (s *fakeSink) lastOfKind(k notify.Kind) notify.Message {
	ms := s.ofKind(k)
	if len(ms) == 0 {
		return notify.Message{}
	}
	return ms[len(ms)-1]
}

func (s *fakeSink) only(t *testing.T) notify.Message {
	t.Helper()
	require.Len(t, s.sent, 1)
	return s.sent[0]
}

type harness struct {
	t     *testing.T
	st    *store.Store
	eng   *notify.Engine
	opts  notify.Options
	sink  *fakeSink
	now   time.Time
	ready bool
	cfgs  map[string]notify.TargetConfig
}

func newHarness(t *testing.T, mut ...func(*notify.Options)) *harness {
	t.Helper()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "ffs.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	h := &harness{t: t, st: st, sink: &fakeSink{}, now: time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC), ready: true,
		cfgs: map[string]notify.TargetConfig{}}
	h.opts = notify.Options{Cluster: "test", DashboardURL: "https://ffs.example",
		Ready: func(context.Context) bool { return h.ready },
		Now:   func() time.Time { return h.now },
		Rand:  func() float64 { return 0.5 }}
	for _, m := range mut {
		m(&h.opts)
	}
	h.eng = notify.New(st, h.opts)
	return h
}

// target registers "uid-<name>" with the harness sink: immediate urgent, daily 09:00 UTC digest at
// medium with resolved findings, urgent allowed through quiet hours.
func (h *harness) target(name string, mut ...func(*notify.TargetConfig)) {
	h.t.Helper()
	c := notify.TargetConfig{UID: "uid-" + name, Name: name, Type: "slack", ConfigHash: "h1", ImmediateMin: urgent,
		Digest:                  notify.DigestConfig{Schedule: "0 9 * * *", Location: time.UTC, MinPriority: medium, IncludeResolved: true},
		AllowUrgentInQuietHours: true}
	for _, m := range mut {
		m(&c)
	}
	require.NoError(h.t, h.eng.Register(ctx, c, h.sink))
	h.cfgs[name] = c
}

func (h *harness) cfg(name string) notify.TargetConfig { return h.cfgs[name] }

func (h *harness) at(s string) {
	h.t.Helper()
	at, err := time.Parse("2006-01-02T15:04Z07:00", s)
	require.NoError(h.t, err)
	h.now = at.UTC()
}

func (h *harness) process() {
	h.t.Helper()
	require.NoError(h.t, h.eng.ProcessOnce(ctx))
	require.NoError(h.t, h.eng.DrainOnce(ctx))
}

func dep(ns, name string) model.OwnerRef {
	return model.OwnerRef{Kind: "Deployment", Namespace: ns, Name: name, UID: "u-" + ns + "-" + name}
}

func finding(owner model.OwnerRef, adv string, p model.Priority, opts ...func(*model.Finding)) model.Finding {
	f := model.Finding{
		Fingerprint: model.FindingFingerprint("test", owner, "registry.example/app", adv),
		Owner:       owner, ImageRepo: "registry.example/app", AdvisoryID: adv,
		Packages: []model.FindingPackage{{Name: "openssl", Ecosystem: "deb", Installed: "3.0.1", Fixed: []string{"3.0.2"}}},
		Severity: model.SeverityHigh, Priority: p, Reasons: []string{"reason for " + p.String()}, State: model.StateOpen,
	}
	for _, o := range opts {
		o(&f)
	}
	return f
}

func provisional(f *model.Finding) { f.Provisional = true }

func stdlib(fixed string) func(*model.Finding) {
	return func(f *model.Finding) {
		f.GoStdlib = true
		f.Packages = []model.FindingPackage{{Name: "stdlib", Ecosystem: "go-module", Installed: "go1.22.3", Path: "/app", Fixed: []string{fixed}}}
	}
}

func (h *harness) advisory(id string) {
	h.t.Helper()
	require.NoError(h.t, h.st.UpsertAdvisory(ctx, model.Advisory{ID: id, Title: "Title of " + id,
		Links: []string{"https://advisories.example/" + id}, Published: h.now.Add(-48 * time.Hour), Observed: h.now}))
}

// open upserts the owner and advisory and creates the finding with its transition.
func (h *harness) open(owner model.OwnerRef, adv string, p model.Priority, opts ...func(*model.Finding)) string {
	h.t.Helper()
	require.NoError(h.t, h.st.UpsertOwner(ctx, model.Owner{Ref: owner, UpdatedAt: h.now}))
	return h.batch(finding(owner, adv, p, opts...))[0]
}

// batch creates findings with their transitions in one ApplyFindings.
func (h *harness) batch(fs ...model.Finding) []string {
	h.t.Helper()
	seen := map[string]bool{}
	ts := make([]model.Transition, 0, len(fs))
	fps := make([]string, 0, len(fs))
	for i := range fs {
		if !seen[fs[i].AdvisoryID] {
			seen[fs[i].AdvisoryID] = true
			h.advisory(fs[i].AdvisoryID)
		}
		fs[i].Matched, fs[i].LastSeen = h.now, h.now
		f := fs[i]
		ts = append(ts, model.Transition{Fingerprint: f.Fingerprint, Owner: f.Owner, AdvisoryID: f.AdvisoryID,
			ToState: model.StateOpen, ToPriority: f.Priority, Trigger: model.TriggerNewAdvisory, Provisional: f.Provisional, At: h.now})
		fps = append(fps, f.Fingerprint)
	}
	require.NoError(h.t, h.st.ApplyFindings(ctx, fs, ts))
	return fps
}

// move applies one transition of the finding fp to state and priority.
func (h *harness) move(fp string, to model.FindingState, p model.Priority, trig model.Trigger) {
	h.t.Helper()
	got, err := h.st.FindingsByFingerprint(ctx, []string{fp})
	require.NoError(h.t, err)
	f, ok := got[fp]
	require.True(h.t, ok, fp)
	tr := model.Transition{Fingerprint: fp, Owner: f.Owner, AdvisoryID: f.AdvisoryID, FromState: f.State, ToState: to,
		FromPriority: f.Priority, ToPriority: p, Trigger: trig, Provisional: f.Provisional, At: h.now}
	f.State, f.Priority, f.LastSeen = to, p, h.now
	f.ResolvedAt = nil
	if to == model.StateResolved {
		at := h.now
		f.ResolvedAt = &at
	}
	if trig == model.TriggerFixAvailable {
		f.FixAvailable = true
	}
	require.NoError(h.t, h.st.ApplyFindings(ctx, []model.Finding{f}, []model.Transition{tr}))
}

// advisories lists the advisory of every immediate message sent by the sinks.
func advisories(sent ...[]notify.Message) []string {
	var out []string
	for _, ms := range sent {
		for _, m := range ms {
			if m.Kind == notify.KindImmediate {
				out = append(out, m.Items[0].AdvisoryID)
			}
		}
	}
	return out
}

func byAdvisory(t *testing.T, ms []notify.Message, id string) notify.Message {
	t.Helper()
	for _, m := range ms {
		if len(m.Items) > 0 && m.Items[0].AdvisoryID == id {
			return m
		}
	}
	require.Failf(t, "no message", "for %s", id)
	return notify.Message{}
}

func TestNotify_BaselineOnFirstSight(t *testing.T) {
	h := newHarness(t)
	h.open(dep("shop", "web"), "CVE-2026-0001", urgent)
	h.open(dep("shop", "api"), "CVE-2026-0001", urgent)
	h.open(dep("shop", "api"), "CVE-2026-0002", high)
	h.open(dep("ops", "cron"), "CVE-2026-0003", medium)
	require.NoError(t, h.st.UpsertOwner(ctx, model.Owner{Ref: model.OwnerRef{Kind: "Cluster", Name: "test"}}))
	h.target("ops")
	h.process()

	m := h.sink.only(t)
	assert.Equal(t, notify.KindBaseline, m.Kind)
	assert.Equal(t, "ffs is watching 3 workloads: 2 urgent, 1 high", m.Title)
	require.NotEmpty(t, m.Items)
	assert.Equal(t, "CVE-2026-0001", m.Items[0].AdvisoryID)
	assert.Len(t, m.Items[0].Owners, 2)
	assert.LessOrEqual(t, len(m.Items), 10)
	require.NotNil(t, m.Summary)
	assert.Equal(t, 3, m.Summary.Workloads)
	assert.Equal(t, map[model.Priority]int{urgent: 2, high: 1, medium: 1}, m.Summary.Counts)
	assert.Equal(t, "ops", m.TargetName)
	assert.Equal(t, "test", m.Cluster)

	h.process()
	assert.Len(t, h.sink.sent, 1) // no transitions → nothing
}

func TestNotify_BaselineWaitsForReady(t *testing.T) {
	h := newHarness(t)
	h.ready = false
	h.target("ops")
	for i := range 3 {
		h.open(dep("a", fmt.Sprintf("x%d", i)), fmt.Sprintf("CVE-2026-000%d", i), urgent)
	}
	h.process()
	assert.Empty(t, h.sink.sent)
	cur, err := h.st.Cursor(ctx, "notify:uid-ops")
	require.NoError(t, err)
	assert.Zero(t, cur)

	h.ready = true
	h.process()
	m := h.sink.only(t)
	assert.Equal(t, notify.KindBaseline, m.Kind)
	assert.Equal(t, "ffs is watching 3 workloads: 3 urgent, 0 high", m.Title)
}

func TestNotify_GroupsByAdvisory(t *testing.T) {
	h := newHarness(t)
	h.target("ops")
	h.process() // baseline
	fs := make([]model.Finding, 0, 301)
	for i := range 300 {
		fs = append(fs, finding(dep("apps", fmt.Sprintf("svc-%03d", i)), "CVE-2026-41873", urgent))
	}
	h.batch(append(fs, finding(dep("apps", "svc-000"), "CVE-2026-50000", urgent))...)
	h.process()

	imm := h.sink.ofKind(notify.KindImmediate)
	require.Len(t, imm, 2)
	m := byAdvisory(t, imm, "CVE-2026-41873") // send order between equal-priority messages is not pinned
	require.Len(t, m.Items, 1)
	it := m.Items[0]
	assert.Len(t, it.Owners, 300)
	assert.Equal(t, "New urgent finding: CVE-2026-41873 affects 300 workloads", m.Title)
	assert.Contains(t, it.Links, "https://ffs.example/vulnerabilities/CVE-2026-41873")
	assert.Contains(t, it.Links, "https://advisories.example/CVE-2026-41873")
	assert.Equal(t, notify.EventDetected, it.Event)
	assert.Equal(t, "Title of CVE-2026-41873", it.Title)
	assert.Equal(t, urgent, it.Priority)
	assert.Equal(t, []string{"reason for urgent"}, it.Reasons)
	assert.Len(t, it.Packages, 1) // the same package in every workload
	assert.Equal(t, []string{"3.0.2"}, it.FixedIn)
	assert.True(t, slices.IsSortedFunc(it.Owners, func(a, b model.OwnerRef) int { return strings.Compare(a.Key(), b.Key()) }))
	m2 := byAdvisory(t, imm, "CVE-2026-50000")
	assert.Equal(t, "New urgent finding: CVE-2026-50000 affects 1 workload", m2.Title)
}

func TestNotify_RestartDoesNotResend(t *testing.T) {
	h := newHarness(t)
	h.target("ops")
	h.process() // baseline
	h.batch(finding(dep("a", "x"), "CVE-A", urgent), finding(dep("a", "x"), "CVE-B", urgent), finding(dep("a", "x"), "CVE-C", urgent))
	require.NoError(t, h.eng.ProcessOnce(ctx))
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	h.sink.cancelOnCall(2, cancel) // Send 1 succeeds and is recorded; Send 2 cancels cctx and returns ctx.Err() (process dies)
	_ = h.eng.DrainOnce(cctx)
	require.Len(t, h.sink.ofKind(notify.KindImmediate), 1)

	e2 := notify.New(h.st, h.opts)
	sink2 := &fakeSink{}
	require.NoError(t, e2.Register(ctx, h.cfg("ops"), sink2))
	require.NoError(t, e2.ProcessOnce(ctx))
	require.NoError(t, e2.DrainOnce(ctx))
	require.NoError(t, e2.ProcessOnce(ctx))
	require.NoError(t, e2.DrainOnce(ctx))
	assert.ElementsMatch(t, []string{"CVE-A", "CVE-B", "CVE-C"}, advisories(h.sink.sent, sink2.sent)) // each exactly once
	assert.Empty(t, sink2.ofKind(notify.KindBaseline))
}

func TestNotify_NeverTwice(t *testing.T) {
	h := newHarness(t)
	h.target("ops")
	h.process() // baseline at 00:00 UTC; the first digest is due at 09:00
	fp := h.open(dep("a", "x"), "CVE-2026-0001", urgent)
	h.process()
	require.Len(t, h.sink.ofKind(notify.KindImmediate), 1)

	h.move(fp, model.StateOpen, high, model.TriggerPriorityChange)
	h.process()
	h.move(fp, model.StateOpen, urgent, model.TriggerPriorityChange)
	h.process()
	h.move(fp, model.StateOpen, urgent, model.TriggerFixAvailable)
	h.process()
	assert.Len(t, h.sink.ofKind(notify.KindImmediate), 1)

	h.at("2026-11-19T09:00Z")
	h.process()
	d := h.sink.lastOfKind(notify.KindDigest)
	require.Len(t, d.Items, 1) // the fix is the digest's only news
	assert.Equal(t, notify.EventFixAvailable, d.Items[0].Event)
	assert.Equal(t, "ffs digest for test: 0 new, 0 escalated, 1 fix available, 0 resolved", d.Title)

	h.move(fp, model.StateOpen, urgent, model.TriggerUpgradeAvailable)
	h.process()
	h.at("2026-11-20T09:00Z")
	h.process()
	assert.Len(t, h.sink.ofKind(notify.KindImmediate), 1)
	assert.Len(t, h.sink.ofKind(notify.KindDigest), 1)
}

func TestNotify_EscalationAboveLedgerRenotifies(t *testing.T) {
	h := newHarness(t)
	h.target("ops", func(c *notify.TargetConfig) { c.ImmediateMin = high })
	h.process()
	fp := h.open(dep("a", "x"), "CVE-2026-0001", high)
	h.process()
	imm := h.sink.ofKind(notify.KindImmediate)
	require.Len(t, imm, 1)
	assert.Equal(t, notify.EventDetected, imm[0].Items[0].Event)
	assert.Equal(t, "New high finding: CVE-2026-0001 affects 1 workload", imm[0].Title)

	h.move(fp, model.StateOpen, urgent, model.TriggerPriorityChange)
	h.process()
	imm = h.sink.ofKind(notify.KindImmediate)
	require.Len(t, imm, 2)
	assert.Equal(t, notify.EventEscalated, imm[1].Items[0].Event)
	assert.Equal(t, "Escalated to urgent: CVE-2026-0001 affects 1 workload", imm[1].Title)
}

func TestNotify_ResolveThenReopenRenotifies(t *testing.T) {
	h := newHarness(t)
	h.target("ops")
	h.process()
	fp := h.open(dep("a", "x"), "CVE-2026-0001", urgent)
	h.process()
	require.Len(t, h.sink.ofKind(notify.KindImmediate), 1)

	h.move(fp, model.StateResolved, urgent, model.TriggerInventoryChange)
	h.process()
	imm := h.sink.ofKind(notify.KindImmediate)
	require.Len(t, imm, 2)
	assert.Equal(t, notify.EventResolved, imm[1].Items[0].Event)
	assert.Equal(t, "Resolved: CVE-2026-0001 no longer affects 1 workload", imm[1].Title)

	h.move(fp, model.StateOpen, urgent, model.TriggerInventoryChange)
	h.process()
	imm = h.sink.ofKind(notify.KindImmediate)
	require.Len(t, imm, 3)
	assert.Equal(t, notify.EventReopened, imm[2].Items[0].Event)
	assert.Equal(t, "Reopened (urgent): CVE-2026-0001 affects 1 workload", imm[2].Title)
}

func TestNotify_ExceptedThenExpiredReopens(t *testing.T) {
	h := newHarness(t)
	h.target("ops")
	h.process()
	fp := h.open(dep("a", "x"), "CVE-2026-0001", urgent)
	h.process()
	h.move(fp, model.StateExcepted, urgent, model.TriggerInventoryChange)
	h.process()
	require.Len(t, h.sink.ofKind(notify.KindImmediate), 1) // excepting sends nothing
	l, err := h.st.Ledger(ctx, "uid-ops", []string{fp})
	require.NoError(t, err)
	assert.Equal(t, model.StateExcepted, l[fp].LastState)

	h.move(fp, model.StateOpen, urgent, model.TriggerExceptionExpired)
	h.process()
	imm := h.sink.ofKind(notify.KindImmediate)
	require.Len(t, imm, 2)
	assert.Equal(t, notify.EventReopened, imm[1].Items[0].Event)
}

func TestNotify_WithdrawnNeverSentStaysSilent(t *testing.T) {
	h := newHarness(t)
	h.target("ops", func(c *notify.TargetConfig) { c.ImmediateMin = high })
	h.process()
	fp := h.open(dep("a", "x"), "CVE-2026-0001", high, provisional) // provisional high: not sent
	h.process()
	h.move(fp, model.StateResolved, high, model.TriggerWithdrawn)
	h.at("2026-11-19T09:00Z")
	h.process()
	assert.Empty(t, h.sink.ofKind(notify.KindImmediate))
	assert.Empty(t, h.sink.ofKind(notify.KindDigest)) // created and withdrawn between digests: never told, nothing to say

	sent := h.open(dep("a", "y"), "CVE-2026-0002", urgent, provisional)
	h.process()
	h.move(sent, model.StateResolved, urgent, model.TriggerWithdrawn)
	h.process()
	imm := h.sink.ofKind(notify.KindImmediate)
	require.Len(t, imm, 2)
	assert.Equal(t, notify.EventResolved, imm[1].Items[0].Event)
	assert.Equal(t, "withdrawn", imm[1].Items[0].Reasons[0])
}

func TestNotify_ProvisionalImmediateOnlyWhenUrgent(t *testing.T) {
	h := newHarness(t)
	h.target("ops", func(c *notify.TargetConfig) { c.ImmediateMin = high })
	h.process()
	h.open(dep("a", "x"), "CVE-2026-0001", high, provisional)
	h.process()
	assert.Empty(t, h.sink.ofKind(notify.KindImmediate))

	h.open(dep("a", "x"), "CVE-2026-0002", urgent, provisional)
	h.process()
	imm := h.sink.ofKind(notify.KindImmediate)
	require.Len(t, imm, 1)
	assert.True(t, imm[0].Items[0].Provisional)
	assert.Equal(t, "CVE-2026-0002", imm[0].Items[0].AdvisoryID)
}

// quietHarness registers a target with quiet hours 22:00-07:00 Sydney time, sends its baseline at
// 00:00 UTC, then moves the clock to 23:30 AEDT.
func quietHarness(t *testing.T, allowUrgent bool) *harness {
	h := newHarness(t)
	h.target("ops", func(c *notify.TargetConfig) {
		c.ImmediateMin = high
		c.AllowUrgentInQuietHours = allowUrgent
		c.QuietHours = []notify.TimeInterval{{Times: []notify.TimeRange{{StartTime: "22:00", EndTime: "24:00"}, {StartTime: "00:00", EndTime: "07:00"}},
			Location: "Australia/Sydney"}}
	})
	h.process()
	h.now = time.Date(2026, 11, 19, 12, 30, 0, 0, time.UTC) // 23:30 AEDT
	return h
}

func TestNotify_QuietHoursHoldUntilWindowEnd(t *testing.T) {
	h := quietHarness(t, true)
	h.open(dep("a", "x"), "CVE-H", high)
	h.process()
	assert.Empty(t, h.sink.ofKind(notify.KindImmediate))
	h.now = time.Date(2026, 11, 19, 19, 59, 0, 0, time.UTC) // 06:59 AEDT
	h.process()
	assert.Empty(t, h.sink.ofKind(notify.KindImmediate))
	h.now = time.Date(2026, 11, 19, 20, 0, 0, 0, time.UTC) // 07:00 AEDT
	h.process()
	assert.Len(t, h.sink.ofKind(notify.KindImmediate), 1)

	h = quietHarness(t, true)
	h.open(dep("a", "x"), "CVE-U", urgent)
	h.process()
	assert.Len(t, h.sink.ofKind(notify.KindImmediate), 1) // urgent goes through

	h = quietHarness(t, false)
	h.open(dep("a", "x"), "CVE-U", urgent)
	h.process()
	assert.Empty(t, h.sink.ofKind(notify.KindImmediate))
	h.now = time.Date(2026, 11, 19, 20, 0, 0, 0, time.UTC)
	h.process()
	assert.Len(t, h.sink.ofKind(notify.KindImmediate), 1)
}

func TestNotify_NamespaceFilter(t *testing.T) {
	h := newHarness(t)
	h.target("ops", func(c *notify.TargetConfig) { c.NamespaceMatch = func(ns string) bool { return ns == "team-a" } })
	h.open(dep("team-b", "x"), "CVE-2026-0009", urgent) // before the baseline: not counted
	h.process()
	assert.Equal(t, "ffs is watching 0 workloads: 0 urgent, 0 high", h.sink.only(t).Title)

	h.open(dep("team-b", "x"), "CVE-2026-0001", urgent)
	h.process()
	assert.Empty(t, h.sink.ofKind(notify.KindImmediate))
	h.open(model.OwnerRef{Kind: "Cluster", Name: "test"}, "CVE-2026-0002", urgent)
	h.process()
	assert.Empty(t, h.sink.ofKind(notify.KindImmediate))
	h.open(dep("team-a", "x"), "CVE-2026-0003", urgent)
	h.process()
	imm := h.sink.ofKind(notify.KindImmediate)
	require.Len(t, imm, 1)
	assert.Equal(t, "CVE-2026-0003", imm[0].Items[0].AdvisoryID)
}

func TestNotify_PausedAdvancesWithoutSending(t *testing.T) {
	h := newHarness(t)
	paused := func(c *notify.TargetConfig) { c.Paused = true }
	h.target("ops", paused)
	h.process()
	assert.Empty(t, h.sink.sent) // no baseline while paused

	h.target("ops")
	h.process() // baseline
	h.target("ops", paused)
	h.open(dep("a", "x"), "CVE-2026-0001", urgent)
	h.process()
	assert.Empty(t, h.sink.ofKind(notify.KindImmediate))

	h.target("ops")
	h.process()
	assert.Empty(t, h.sink.ofKind(notify.KindImmediate)) // the old transition is never sent
	h.open(dep("a", "y"), "CVE-2026-0002", urgent)
	h.process()
	imm := h.sink.ofKind(notify.KindImmediate)
	require.Len(t, imm, 1)
	assert.Equal(t, "CVE-2026-0002", imm[0].Items[0].AdvisoryID)
}

func TestNotify_FeedStaleOncePerEpisode(t *testing.T) {
	h := newHarness(t, func(o *notify.Options) { o.FeedStaleAfter = map[string]time.Duration{"osv": 2 * time.Hour} })
	h.target("ops", func(c *notify.TargetConfig) { c.NotifyOnFeedStale = true })
	h.target("quiet")
	h.process() // baselines
	require.NoError(t, h.st.PutFeedState(ctx, store.FeedState{Name: "osv", LastSuccess: h.now.Add(-3 * time.Hour)}))
	h.process()
	stale := h.sink.ofKind(notify.KindFeedStale)
	require.Len(t, stale, 1)
	assert.Equal(t, "ops", stale[0].TargetName) // the target without the flag gets nothing
	assert.Equal(t, "Feed osv has not synced successfully since 2026-11-18 21:00 UTC", stale[0].Title)
	require.Len(t, stale[0].Feeds, 1)
	assert.True(t, stale[0].Feeds[0].Stale)
	assert.Equal(t, 2*time.Hour, stale[0].Feeds[0].StaleAfter)

	h.process()
	assert.Len(t, h.sink.ofKind(notify.KindFeedStale), 1)

	require.NoError(t, h.st.PutFeedState(ctx, store.FeedState{Name: "osv", LastSuccess: h.now}))
	h.process()
	assert.Len(t, h.sink.ofKind(notify.KindFeedStale), 1)
	h.now = h.now.Add(3 * time.Hour)
	h.process()
	assert.Len(t, h.sink.ofKind(notify.KindFeedStale), 2)
	for _, m := range h.sink.ofKind(notify.KindFeedStale) {
		assert.Equal(t, "ops", m.TargetName)
	}
}

func TestNotify_UnregisterAndRetainDeleteState(t *testing.T) {
	h := newHarness(t)
	h.target("ops")
	h.target("dev")
	h.process()
	require.NoError(t, h.eng.Unregister(ctx, "ops"))
	_, ok, err := h.eng.Status(ctx, "uid-ops")
	require.NoError(t, err)
	assert.False(t, ok)

	require.NoError(t, h.eng.Retain(ctx, []string{"uid-other"}))
	_, ok, _ = h.eng.Status(ctx, "uid-dev")
	assert.False(t, ok)
	h.open(dep("a", "x"), "CVE-2026-0001", urgent)
	h.process()
	assert.Len(t, h.sink.sent, 2) // the two baselines; nothing after the targets went
}
