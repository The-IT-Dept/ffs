package notify_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	ffsv1alpha1 "github.com/the-it-dept/ffs/api/v1alpha1"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/notify"
	"github.com/the-it-dept/ffs/internal/store"
)

const hookURL = "https://hooks.slack.com/services/SECRET/TOKEN/X"

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(s))
	require.NoError(t, ffsv1alpha1.AddToScheme(s))
	return s
}

func alertTarget(typ, secret string) *ffsv1alpha1.AlertTarget {
	return &ffsv1alpha1.AlertTarget{
		ObjectMeta: metav1.ObjectMeta{Name: "ops", UID: types.UID("uid-ops"), Generation: 1},
		Spec:       ffsv1alpha1.AlertTargetSpec{Type: typ, SecretRef: ffsv1alpha1.SecretReference{Name: secret}},
	}
}

func secretOf(name string, data map[string]string) *corev1.Secret {
	s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "ffs", Name: name}, Data: map[string][]byte{}}
	for k, v := range data {
		s.Data[k] = []byte(v)
	}
	return s
}

type recordingFactory struct {
	calls []notify.SinkConfig
	types []string
	sinks []*fakeSink
}

func (f *recordingFactory) New(typ string, cfg notify.SinkConfig) (notify.Sink, error) {
	f.calls, f.types = append(f.calls, cfg), append(f.types, typ)
	s := &fakeSink{}
	f.sinks = append(f.sinks, s)
	return s, nil
}

type recHarness struct {
	r       *notify.TargetReconciler
	c       client.Client
	st      *store.Store
	eng     *notify.Engine
	base    *harness
	factory *recordingFactory
	updates int
}

func newRecHarness(t *testing.T, objs ...client.Object) *recHarness {
	t.Helper()
	h := newHarness(t)
	rh := &recHarness{st: h.st, eng: h.eng, base: h, factory: &recordingFactory{}}
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).WithObjects(objs...).WithStatusSubresource(&ffsv1alpha1.AlertTarget{}).
		WithInterceptorFuncs(interceptor.Funcs{SubResourceUpdate: func(ctx context.Context, c client.Client, sub string, o client.Object, opts ...client.SubResourceUpdateOption) error {
			rh.updates++
			return c.SubResource(sub).Update(ctx, o, opts...)
		}}).Build()
	rh.c = c
	rh.r = &notify.TargetReconciler{Client: c, Secrets: c, Engine: h.eng, Namespace: "ffs", Cluster: "test", NewSink: rh.factory.New}
	return rh
}

func (h *recHarness) reconcile(t *testing.T) *ffsv1alpha1.AlertTarget {
	t.Helper()
	res, err := h.r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "ops"}})
	require.NoError(t, err)
	assert.Equal(t, time.Minute, res.RequeueAfter)
	var at ffsv1alpha1.AlertTarget
	require.NoError(t, h.c.Get(ctx, types.NamespacedName{Name: "ops"}, &at))
	return &at
}

func assertCondition(t *testing.T, at *ffsv1alpha1.AlertTarget, typ string, status metav1.ConditionStatus, reason string) *metav1.Condition {
	t.Helper()
	c := meta.FindStatusCondition(at.Status.Conditions, typ)
	require.NotNil(t, c, "condition %s", typ)
	assert.Equal(t, status, c.Status)
	assert.Equal(t, reason, c.Reason)
	assert.NotContains(t, c.Message, "SECRET")
	assert.NotContains(t, c.Message, "hooks.slack.com")
	return c
}

func TestTargetConfigFrom_Defaults(t *testing.T) {
	at := alertTarget("slack", "slack-ops")
	sec := secretOf("slack-ops", map[string]string{"url": "https://hooks.slack.com/services/X"})
	cfg, sc, err := notify.TargetConfigFrom(at, sec, nil)
	require.NoError(t, err)
	assert.Equal(t, model.PriorityUrgent, cfg.ImmediateMin)
	assert.Equal(t, notify.DigestConfig{Schedule: "0 9 * * *", Location: time.UTC, MinPriority: model.PriorityMedium, IncludeResolved: true}, cfg.Digest)
	assert.True(t, cfg.AllowUrgentInQuietHours)
	assert.Nil(t, cfg.NamespaceMatch)
	assert.Equal(t, "https://hooks.slack.com/services/X", sc.URL)
	assert.Len(t, cfg.ConfigHash, 16)
	assert.Equal(t, "uid-ops", cfg.UID)

	at.Spec.SecretRef = ffsv1alpha1.SecretReference{Name: "hook", URLKey: "endpoint", SigningSecretKey: "key"}
	sec = secretOf("hook", map[string]string{"endpoint": "https://e.example/x", "key": "whsec_abc"})
	cfg2, sc, err := notify.TargetConfigFrom(at, sec, nil)
	require.NoError(t, err)
	assert.Equal(t, "https://e.example/x", sc.URL)
	assert.Equal(t, "whsec_abc", sc.SigningSecret)
	assert.NotEqual(t, cfg.ConfigHash, cfg2.ConfigHash)
}

func TestTargetConfigFrom_QuietHoursAndOverrides(t *testing.T) {
	at := alertTarget("slack", "s")
	no := false
	at.Spec.Immediate.MinPriority = "high"
	at.Spec.Digest = ffsv1alpha1.DigestSpec{Schedule: "30 7 * * 1", TimeZone: "Australia/Sydney", MinPriority: "low", IncludeResolved: &no}
	at.Spec.QuietHours = &ffsv1alpha1.QuietHours{AllowUrgent: &no, Intervals: []ffsv1alpha1.TimeInterval{
		{Times: []ffsv1alpha1.TimeRange{{StartTime: "22:00", EndTime: "24:00"}}, Weekdays: []string{"monday:friday"}, Location: "UTC"}}}
	at.Spec.AllowPrivate, at.Spec.Paused, at.Spec.NotifyOnFeedStale = true, true, true
	cfg, sc, err := notify.TargetConfigFrom(at, secretOf("s", map[string]string{"url": "https://x"}), func(string) bool { return true })
	require.NoError(t, err)
	assert.Equal(t, model.PriorityHigh, cfg.ImmediateMin)
	assert.Equal(t, "Australia/Sydney", cfg.Digest.Location.String())
	assert.Equal(t, model.PriorityLow, cfg.Digest.MinPriority)
	assert.False(t, cfg.Digest.IncludeResolved)
	assert.False(t, cfg.AllowUrgentInQuietHours)
	require.Len(t, cfg.QuietHours, 1)
	assert.Equal(t, []notify.TimeRange{{StartTime: "22:00", EndTime: "24:00"}}, cfg.QuietHours[0].Times)
	assert.True(t, cfg.Paused && cfg.NotifyOnFeedStale && sc.AllowPrivate)
	assert.NotNil(t, cfg.NamespaceMatch)
}

func TestTargetReconciler_Registers(t *testing.T) {
	h := newRecHarness(t, alertTarget("slack", "slack-ops"), secretOf("slack-ops", map[string]string{"url": hookURL}))
	at := h.reconcile(t)
	st, ok, err := h.eng.Status(ctx, "uid-ops")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "ops", st.Name)
	assert.Equal(t, []string{"slack"}, h.factory.types)
	assert.Equal(t, "test", h.factory.calls[0].Cluster)
	assert.Equal(t, hookURL, h.factory.calls[0].URL)
	assertCondition(t, at, "Ready", metav1.ConditionTrue, "Registered")
	assert.EqualValues(t, 1, at.Status.ObservedGeneration)
}

func TestTargetReconciler_InvalidSpecSetsCondition(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*ffsv1alpha1.AlertTarget)
		secret *corev1.Secret
		typ    string
		reason string
	}{
		{"missing secret", nil, nil, "slack", "SecretNotFound"},
		{"no url key", nil, secretOf("s", map[string]string{"other": hookURL}), "slack", "SecretInvalid"},
		{"webhook without signing secret", nil, secretOf("s", map[string]string{"url": hookURL}), "webhook", "SecretInvalid"},
		{"bad schedule", func(a *ffsv1alpha1.AlertTarget) { a.Spec.Digest.Schedule = "61 * * * *" }, secretOf("s", map[string]string{"url": hookURL}), "slack", "InvalidSpec"},
		{"bad zone", func(a *ffsv1alpha1.AlertTarget) { a.Spec.Digest.TimeZone = "Mars/Base" }, secretOf("s", map[string]string{"url": hookURL}), "slack", "InvalidSpec"},
		{"bad priority", func(a *ffsv1alpha1.AlertTarget) { a.Spec.Immediate.MinPriority = "severe" }, secretOf("s", map[string]string{"url": hookURL}), "slack", "InvalidSpec"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			at := alertTarget(c.typ, "s")
			if c.mutate != nil {
				c.mutate(at)
			}
			objs := []client.Object{at}
			if c.secret != nil {
				objs = append(objs, c.secret)
			}
			h := newRecHarness(t, objs...)
			got := h.reconcile(t)
			cond := assertCondition(t, got, "Ready", metav1.ConditionFalse, c.reason)
			assert.NotEmpty(t, cond.Message)
			assert.Empty(t, h.factory.calls)
		})
	}
}

func TestTargetReconciler_StatusFromEngine(t *testing.T) {
	h := newRecHarness(t, alertTarget("slack", "s"), secretOf("s", map[string]string{"url": hookURL}))
	h.reconcile(t)
	attempt := func(state store.DeliveryState, disable bool) {
		require.NoError(t, h.st.RecordAttempt(ctx, store.DeliveryAttempt{ID: "d", Target: "uid-ops", At: time.Date(2026, 11, 19, 1, 2, 3, 0, time.UTC),
			State: state, Error: "HTTP 500", Disable: disable, DisableReason: "endpoint returned 410"}))
	}

	attempt(store.DeliverySent, false)
	at := h.reconcile(t)
	require.NotNil(t, at.Status.LastDelivery)
	assert.True(t, at.Status.LastDelivery.Time.Equal(time.Date(2026, 11, 19, 1, 2, 3, 0, time.UTC)))
	assertCondition(t, at, "Ready", metav1.ConditionTrue, "Registered")

	for range 3 {
		attempt(store.DeliveryPending, false)
	}
	at = h.reconcile(t)
	assertCondition(t, at, "Ready", metav1.ConditionFalse, "DeliveryFailing")
	assert.Equal(t, "HTTP 500", at.Status.LastError)

	before := h.updates
	h.reconcile(t)
	assert.Equal(t, before, h.updates, "an unchanged status must not be written")

	attempt(store.DeliveryFailed, true)
	at = h.reconcile(t)
	assertCondition(t, at, "Ready", metav1.ConditionFalse, "EndpointGone")

	// Paused wins over delivery state for a target that is not disabled.
	h2 := newRecHarness(t, alertTarget("slack", "s"), secretOf("s", map[string]string{"url": hookURL}))
	var cur ffsv1alpha1.AlertTarget
	require.NoError(t, h2.c.Get(ctx, types.NamespacedName{Name: "ops"}, &cur))
	cur.Spec.Paused = true
	require.NoError(t, h2.c.Update(ctx, &cur))
	assertCondition(t, h2.reconcile(t), "Ready", metav1.ConditionTrue, "Paused")
}

func TestTargetReconciler_DeleteUnregisters(t *testing.T) {
	at := alertTarget("slack", "s")
	h := newRecHarness(t, at, secretOf("s", map[string]string{"url": hookURL}))
	h.reconcile(t)
	_, ok, err := h.st.NotifyTarget(ctx, "uid-ops")
	require.NoError(t, err)
	require.True(t, ok)

	require.NoError(t, h.c.Delete(ctx, at))
	res, err := h.r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: "ops"}})
	require.NoError(t, err)
	assert.Zero(t, res.RequeueAfter)
	_, ok, err = h.st.NotifyTarget(ctx, "uid-ops")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestTargetReconciler_SecretChangeReenables(t *testing.T) {
	h := newRecHarness(t, alertTarget("slack", "s"), secretOf("s", map[string]string{"url": hookURL}))
	h.reconcile(t)
	require.NoError(t, h.st.RecordAttempt(ctx, store.DeliveryAttempt{ID: "d", Target: "uid-ops", State: store.DeliveryFailed, Disable: true, DisableReason: "gone"}))
	assertCondition(t, h.reconcile(t), "Ready", metav1.ConditionFalse, "EndpointGone")

	var sec corev1.Secret
	require.NoError(t, h.c.Get(ctx, types.NamespacedName{Namespace: "ffs", Name: "s"}, &sec))
	sec.Data["url"] = []byte(strings.Replace(hookURL, "TOKEN", "NEWTOKEN", 1))
	require.NoError(t, h.c.Update(ctx, &sec))
	assertCondition(t, h.reconcile(t), "Ready", metav1.ConditionTrue, "Registered")
}

func TestTargetReconciler_NamespaceMatch(t *testing.T) {
	at := alertTarget("slack", "s")
	ns := func(name string, labels map[string]string) *corev1.Namespace {
		return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
	}
	h := newRecHarness(t, ns("web", map[string]string{"team": "a"}), ns("db", map[string]string{"team": "b"}), ns("prod", nil))
	assert.Nil(t, h.r.NamespaceMatch(at))

	at.Spec.Namespaces = []string{"prod"}
	m := h.r.NamespaceMatch(at)
	assert.True(t, m("prod"))
	assert.False(t, m("web"))

	at.Spec.NamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"team": "a"}}
	m = h.r.NamespaceMatch(at)
	assert.True(t, m("prod"), "listed by name")
	assert.True(t, m("web"), "matches the selector")
	assert.False(t, m("db"))
	assert.False(t, m("missing"))
}

type failingReader struct{ client.Reader }

func (failingReader) Get(context.Context, client.ObjectKey, client.Object, ...client.GetOption) error {
	return errors.New("forbidden: boom")
}

func TestTargetReconciler_SecretReadErrorIsDistinct(t *testing.T) {
	h := newRecHarness(t, alertTarget("slack", "s"))
	h.r.Secrets = failingReader{h.c}
	got := h.reconcile(t)
	cond := assertCondition(t, got, "Ready", metav1.ConditionFalse, "SecretUnreadable")
	assert.Contains(t, cond.Message, "forbidden: boom")
	assert.Empty(t, h.factory.calls)
}

// TestTargetReconciler_BrokenSecretStopsDelivery pins F32: once the Secret is deleted or made
// invalid, nothing more goes to the endpoint the target had, and fixing the Secret resumes delivery
// from the target's cursor with its stored state intact.
func TestTargetReconciler_BrokenSecretStopsDelivery(t *testing.T) {
	h := newRecHarness(t, alertTarget("slack", "s"), secretOf("s", map[string]string{"url": hookURL}))
	assertCondition(t, h.reconcile(t), "Ready", metav1.ConditionTrue, "Registered")
	h.base.process() // baseline
	old := h.factory.sinks[len(h.factory.sinks)-1]
	require.Len(t, old.ofKind(notify.KindBaseline), 1)

	var sec corev1.Secret
	require.NoError(t, h.c.Get(ctx, types.NamespacedName{Namespace: "ffs", Name: "s"}, &sec))
	require.NoError(t, h.c.Delete(ctx, &sec))
	assertCondition(t, h.reconcile(t), "Ready", metav1.ConditionFalse, "SecretNotFound")
	h.base.open(dep("a", "x"), "CVE-2026-0001", urgent)
	h.base.process()
	assert.Empty(t, old.ofKind(notify.KindImmediate), "nothing goes to the old endpoint once the Secret is gone")

	require.NoError(t, h.c.Create(ctx, secretOf("s", map[string]string{"other": hookURL})))
	assertCondition(t, h.reconcile(t), "Ready", metav1.ConditionFalse, "SecretInvalid")
	h.base.process()
	assert.Empty(t, old.ofKind(notify.KindImmediate), "nor while the Secret is invalid")
	st, ok, err := h.eng.Status(ctx, "uid-ops")
	require.NoError(t, err)
	require.True(t, ok, "the stored state is kept")
	assert.False(t, st.BaselineAt.IsZero())

	require.NoError(t, h.c.Get(ctx, types.NamespacedName{Namespace: "ffs", Name: "s"}, &sec))
	sec.Data = map[string][]byte{"url": []byte(strings.Replace(hookURL, "TOKEN", "NEWTOKEN", 1))}
	require.NoError(t, h.c.Update(ctx, &sec))
	assertCondition(t, h.reconcile(t), "Ready", metav1.ConditionTrue, "Registered")
	h.base.process()
	fixed := h.factory.sinks[len(h.factory.sinks)-1]
	assert.Empty(t, fixed.ofKind(notify.KindBaseline), "no second baseline")
	assert.Equal(t, []string{"CVE-2026-0001"}, advisories(fixed.sent), "the alert held back is sent from the cursor")
	assert.Empty(t, old.ofKind(notify.KindImmediate))
}
