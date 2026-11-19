package events

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
	"github.com/the-it-dept/ffs/internal/testenv"
)

var self = &corev1.ObjectReference{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "ffs", Name: "ffs", UID: "s1"}

type harness struct {
	st  *store.Store
	rec *testenv.Recorder
	em  *Emitter
}

func newHarness(t *testing.T, s *corev1.ObjectReference) *harness {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "ffs.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	rec := &testenv.Recorder{}
	return &harness{st: st, rec: rec, em: New(Options{Store: st, Recorder: rec, Config: config.EventsConfig{MinPriority: "high"}, Self: s, Log: logr.Discard()})}
}

// seed stores a finding for the transition's fingerprint and the transition itself.
func (h *harness) seed(t *testing.T, tr model.Transition, pkg *model.FindingPackage) {
	t.Helper()
	tr.Fingerprint = model.FindingFingerprint("c", tr.Owner, "repo", tr.AdvisoryID)
	f := model.Finding{Fingerprint: tr.Fingerprint, Owner: tr.Owner, ImageRepo: "repo", AdvisoryID: tr.AdvisoryID,
		State: tr.ToState, Priority: tr.ToPriority, Provisional: tr.Provisional}
	if pkg != nil {
		f.Packages = []model.FindingPackage{*pkg}
	}
	require.NoError(t, h.st.ApplyFindings(context.Background(), []model.Finding{f}, []model.Transition{tr}))
}

func create(o model.OwnerRef, id string, p model.Priority) model.Transition {
	return model.Transition{Owner: o, AdvisoryID: id, ToState: model.StateOpen, ToPriority: p, Trigger: model.TriggerNewAdvisory, At: time.Now()}
}

func (h *harness) byReason(reason string) []testenv.RecordedEvent {
	var out []testenv.RecordedEvent
	for _, e := range h.rec.Snapshot() {
		if e.Reason == reason {
			out = append(out, e)
		}
	}
	return out
}

func TestEvents_OnePerOwnerPerBatch(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, self)
	for i := 0; i < 300; i++ {
		h.seed(t, create(model.OwnerRef{Kind: "Deployment", Namespace: "web", Name: fmt.Sprintf("app-%03d", i), UID: "u"}, "CVE-2026-41873", model.PriorityUrgent), nil)
	}
	api := model.OwnerRef{Kind: "Deployment", Namespace: "web", Name: "api", UID: "api-uid"}
	h.seed(t, create(api, "CVE-2026-2003", model.PriorityHigh), &model.FindingPackage{Name: "php", Installed: "8.3.14", Fixed: []string{"8.3.16"}})
	h.seed(t, create(api, "CVE-2026-41873", model.PriorityUrgent), &model.FindingPackage{Name: "php", Installed: "8.3.14", Fixed: []string{"8.3.16"}})
	h.seed(t, create(api, "CVE-2026-2002", model.PriorityHigh), &model.FindingPackage{Name: "php", Installed: "8.3.14", Fixed: []string{"8.3.16"}})
	h.seed(t, model.Transition{Owner: api, AdvisoryID: "CVE-2026-2004", FromState: model.StateOpen, ToState: model.StateOpen,
		FromPriority: model.PriorityHigh, ToPriority: model.PriorityUrgent, Trigger: model.TriggerPriorityChange}, nil)
	h.seed(t, model.Transition{Owner: api, AdvisoryID: "CVE-2026-2005", FromState: model.StateOpen, ToState: model.StateResolved,
		FromPriority: model.PriorityHigh, Trigger: model.TriggerInventoryChange}, nil)
	h.seed(t, create(api, "CVE-2026-2006", model.PriorityMedium), nil)

	require.NoError(t, h.em.Drain(ctx))
	require.Len(t, h.rec.Snapshot(), 303)
	wantRef := &corev1.ObjectReference{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "web", Name: "api", UID: types.UID("api-uid")}
	var apiEvents []testenv.RecordedEvent
	for _, e := range h.rec.Snapshot() {
		if e.Regarding.(*corev1.ObjectReference).Name == "api" {
			apiEvents = append(apiEvents, e)
		}
	}
	require.Len(t, apiEvents, 3)
	d, esc, res := h.byReason(ReasonDetected), h.byReason(ReasonEscalated), h.byReason(ReasonResolved)
	require.Len(t, res, 1)
	require.Len(t, esc, 1)
	require.Equal(t, "1 escalated: CVE-2026-2004 (high -> urgent)", esc[0].Note)
	require.Equal(t, "Warning", esc[0].Type)
	require.Equal(t, "1 resolved: CVE-2026-2005", res[0].Note)
	require.Equal(t, "Normal", res[0].Type)
	for _, e := range apiEvents {
		require.Equal(t, wantRef, e.Regarding)
		require.Equal(t, "Evaluate", e.Action)
	}
	var apiDetected testenv.RecordedEvent
	for _, e := range d {
		if e.Regarding.(*corev1.ObjectReference).Name == "api" {
			apiDetected = e
		}
	}
	require.Equal(t, "3 new: CVE-2026-41873 (urgent, php 8.3.14 -> 8.3.16), CVE-2026-2002 (high, php 8.3.14 -> 8.3.16), CVE-2026-2003 (high, php 8.3.14 -> 8.3.16)", apiDetected.Note)
	require.Equal(t, "Warning", apiDetected.Type)

	last, err := h.st.TransitionsAfter(ctx, 0, 100000)
	require.NoError(t, err)
	cur, err := h.st.Cursor(ctx, CursorName)
	require.NoError(t, err)
	require.Equal(t, last[len(last)-1].ID, cur)
	require.NoError(t, h.em.Drain(ctx))
	require.Len(t, h.rec.Snapshot(), 303)
}

func TestEvents_BatchesOf500AndNoteCap(t *testing.T) {
	h := newHarness(t, self)
	o := model.OwnerRef{Kind: "Deployment", Namespace: "web", Name: "big"}
	for i := 0; i < 600; i++ {
		h.seed(t, create(o, fmt.Sprintf("CVE-2026-%05d", i), model.PriorityHigh), &model.FindingPackage{Name: "libfoo", Installed: "1.0", Fixed: []string{"1.1"}})
	}
	require.NoError(t, h.em.Drain(context.Background()))
	ev := h.byReason(ReasonDetected)
	require.Len(t, ev, 2)
	require.LessOrEqual(t, len(ev[0].Note), MaxNoteBytes)
	require.True(t, strings.HasPrefix(ev[0].Note, "500 new: "))
	i := strings.LastIndex(ev[0].Note, " and ")
	require.Positive(t, i)
	var more int
	_, err := fmt.Sscanf(ev[0].Note[i:], " and %d more", &more)
	require.NoError(t, err)
	listed := strings.Count(ev[0].Note[:i], "CVE-2026-")
	require.Equal(t, 500, listed+more)
	require.True(t, strings.HasPrefix(ev[1].Note, "100 new: "))
}

func TestEvents_ClusterSubjectsOnFFSDeployment(t *testing.T) {
	h := newHarness(t, self)
	h.seed(t, create(model.OwnerRef{Kind: "Cluster", Name: "prod"}, "CVE-2026-1111", model.PriorityHigh),
		&model.FindingPackage{Name: "kubernetes", Installed: "1.35.0", Fixed: []string{"1.35.2"}})
	h.seed(t, create(model.OwnerRef{Kind: "ContainerRuntime", Name: "containerd"}, "CVE-2026-1112", model.PriorityHigh), nil)
	require.NoError(t, h.em.Drain(context.Background()))
	ev := h.rec.Snapshot()
	require.Len(t, ev, 2)
	for _, e := range ev {
		require.Equal(t, self, e.Regarding)
	}
	require.Equal(t, "Kubernetes: 1 new: CVE-2026-1111 (high, kubernetes 1.35.0 -> 1.35.2)", ev[0].Note)
	require.Equal(t, "Container runtime containerd: 1 new: CVE-2026-1112 (high)", ev[1].Note)

	h2 := newHarness(t, nil)
	h2.seed(t, create(model.OwnerRef{Kind: "Cluster", Name: "prod"}, "CVE-2026-1111", model.PriorityHigh), nil)
	require.NoError(t, h2.em.Drain(context.Background()))
	require.Empty(t, h2.rec.Snapshot())
	cur, err := h2.st.Cursor(context.Background(), CursorName)
	require.NoError(t, err)
	require.Positive(t, cur)
	h2.em.FeedStale("osv", time.Time{}, time.Hour)
	require.Empty(t, h2.rec.Snapshot())
}

func TestEvents_SkipsExceptedAndUnknownKinds(t *testing.T) {
	h := newHarness(t, self)
	o := model.OwnerRef{Kind: "Deployment", Namespace: "web", Name: "api"}
	tr := func(id string, from, to model.FindingState, fp, tp model.Priority, trig model.Trigger) model.Transition {
		return model.Transition{Owner: o, AdvisoryID: id, FromState: from, ToState: to, FromPriority: fp, ToPriority: tp, Trigger: trig}
	}
	h.seed(t, tr("CVE-2026-0001", model.StateOpen, model.StateExcepted, model.PriorityUrgent, model.PriorityUrgent, model.TriggerPriorityChange), nil)
	h.seed(t, tr("CVE-2026-0002", model.StateExcepted, model.StateResolved, model.PriorityUrgent, model.PriorityUrgent, model.TriggerWithdrawn), nil)
	h.seed(t, tr("CVE-2026-0003", model.StateOpen, model.StateOpen, model.PriorityUrgent, model.PriorityHigh, model.TriggerPriorityChange), nil)
	h.seed(t, tr("CVE-2026-0004", model.StateOpen, model.StateOpen, model.PriorityUrgent, model.PriorityUrgent, model.TriggerFixAvailable), nil)
	h.seed(t, create(model.OwnerRef{Kind: "Rollout", Namespace: "web", Name: "r"}, "CVE-2026-0005", model.PriorityUrgent), nil)
	require.NoError(t, h.em.Drain(context.Background()))
	require.Empty(t, h.rec.Snapshot())

	h.seed(t, tr("CVE-2026-0006", model.StateExcepted, model.StateOpen, model.PriorityUrgent, model.PriorityUrgent, model.TriggerExceptionExpired), nil)
	prov := create(o, "CVE-2026-3001", model.PriorityUrgent)
	prov.Provisional = true
	h.seed(t, prov, &model.FindingPackage{Name: "openssl", Installed: "3.0.13-1"})
	require.NoError(t, h.em.Drain(context.Background()))
	ev := h.rec.Snapshot()
	require.Len(t, ev, 1)
	require.Equal(t, "2 new: CVE-2026-0006 (urgent), CVE-2026-3001 (urgent, provisional, openssl 3.0.13-1, no fix yet)", ev[0].Note)
}

func TestEvents_FeedStale(t *testing.T) {
	h := newHarness(t, self)
	h.em.FeedStale("osv", time.Date(2026, 11, 19, 9, 0, 0, 0, time.UTC), 2*time.Hour)
	h.em.FeedStale("kev", time.Time{}, 24*time.Hour)
	ev := h.rec.Snapshot()
	require.Len(t, ev, 2)
	for _, e := range ev {
		require.Equal(t, "Warning", e.Type)
		require.Equal(t, ReasonFeedStale, e.Reason)
		require.Equal(t, self, e.Regarding)
	}
	require.Equal(t, "Feed osv has not synced since 2026-11-19T09:00:00Z (stale after 2h0m0s). Findings may be out of date.", ev[0].Note)
	require.Equal(t, "Feed kev has never synced (stale after 24h0m0s). Findings may be out of date.", ev[1].Note)
}
