package crds

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/the-it-dept/ffs/api/v1alpha1"
	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/findings"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

// fakeEngine counts OnExceptionsChanged calls.
type fakeEngine struct{ calls int }

func (e *fakeEngine) OnExceptionsChanged(context.Context) error {
	e.calls++
	return nil
}

func newReconciler(t *testing.T, st *store.Store, now *time.Time) (*ExceptionReconciler, *fakeEngine) {
	t.Helper()
	needEnv(t)
	eng := &fakeEngine{}
	return &ExceptionReconciler{Client: env.Client, Store: st, Engine: eng, Config: config.Default(), Namespace: "ffs",
		Now: func() time.Time { return *now }}, eng
}

func acceptSpec(advisory string, expires time.Time) v1alpha1.ExceptionSpec {
	return v1alpha1.ExceptionSpec{Advisories: []string{advisory}, Reason: "accepted risk", Expires: metav1.NewTime(expires)}
}

// createException creates an Exception that the test deletes when it ends.
func createException(t *testing.T, namespace, name string, spec v1alpha1.ExceptionSpec) {
	t.Helper()
	ex := &v1alpha1.Exception{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}, Spec: spec}
	require.NoError(t, env.Client.Create(ctx, ex))
	t.Cleanup(func() { require.NoError(t, client.IgnoreNotFound(env.Client.Delete(ctx, ex))) })
}

func getException(t *testing.T, namespace, name string) v1alpha1.Exception {
	t.Helper()
	var ex v1alpha1.Exception
	require.NoError(t, env.Client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &ex))
	return ex
}

func reconcileException(t *testing.T, r *ExceptionReconciler, namespace, name string) reconcile.Result {
	t.Helper()
	res, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: types.NamespacedName{Namespace: namespace, Name: name}})
	require.NoError(t, err)
	return res
}

func rules(t *testing.T, st *store.Store) []findings.ExceptionRule {
	t.Helper()
	rs, err := st.ExceptionRules(ctx)
	require.NoError(t, err)
	return rs
}

func TestValidateException(t *testing.T) {
	maxDuration := 8760 * time.Hour
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	valid := func() v1alpha1.ExceptionSpec { return acceptSpec(cve, now.Add(720*time.Hour)) }
	for name, tc := range map[string]struct {
		mutate func(*v1alpha1.ExceptionSpec)
		max    time.Duration
		want   string
	}{
		"no reason":        {func(s *v1alpha1.ExceptionSpec) { s.Reason = "" }, maxDuration, "reason is required"},
		"no expires":       {func(s *v1alpha1.ExceptionSpec) { s.Expires = metav1.Time{} }, maxDuration, "expires is required"},
		"past one year":    {func(s *v1alpha1.ExceptionSpec) { s.Expires = metav1.NewTime(now.Add(8761 * time.Hour)) }, maxDuration, "expires must be at most 365 days from now"},
		"past thirty days": {func(s *v1alpha1.ExceptionSpec) { s.Expires = metav1.NewTime(now.Add(721 * time.Hour)) }, 720 * time.Hour, "expires must be at most 30 days from now"},
		"no criteria": {func(s *v1alpha1.ExceptionSpec) { s.Advisories = nil }, maxDuration,
			"at least one of advisories, packages, imageRepositories or owners is required"},
		"bad vexStatus": {func(s *v1alpha1.ExceptionSpec) { s.VEXStatus = "maybe" }, maxDuration,
			"vexStatus must be one of not_affected, affected, fixed, under_investigation"},
	} {
		spec := valid()
		tc.mutate(&spec)
		require.EqualError(t, ValidateException(spec, now, tc.max), tc.want, name)
	}

	require.NoError(t, ValidateException(valid(), now, maxDuration))
	expired := acceptSpec(cve, now.Add(-time.Hour))
	require.NoError(t, ValidateException(expired, now, maxDuration), "an expired exception is valid")
	vex := valid()
	vex.Packages, vex.VEXStatus = []string{"openssl"}, "not_affected"
	require.NoError(t, ValidateException(vex, now, maxDuration))
}

func TestExceptionReconciler_CachesRuleAndRecomputes(t *testing.T) {
	needEnv(t)
	st := newStore(t)
	seedAdvisory(t, st)
	now := t0
	r, eng := newReconciler(t, st, &now)
	expires := t0.Add(30 * 24 * time.Hour)
	createException(t, "web", "accept", acceptSpec(ghsa, expires))

	res := reconcileException(t, r, "web", "accept")
	require.Equal(t, []findings.ExceptionRule{{Namespace: "web", Name: "accept", AdvisoryIDs: []string{cve}, Expires: expires}}, rules(t, st))
	require.Equal(t, 1, eng.calls)
	ready := apimeta.FindStatusCondition(getException(t, "web", "accept").Status.Conditions, "Ready")
	require.NotNil(t, ready)
	require.Equal(t, metav1.ConditionTrue, ready.Status)
	require.Equal(t, "Active", ready.Reason)
	require.Positive(t, res.RequeueAfter)
	require.LessOrEqual(t, res.RequeueAfter, 2*time.Minute)

	reconcileException(t, r, "web", "accept")
	require.Equal(t, 1, eng.calls, "an unchanged rule does not recompute")

	createException(t, "ffs", "accept", acceptSpec(ghsa, expires))
	reconcileException(t, r, "ffs", "accept")
	got := rules(t, st)
	require.Len(t, got, 2)
	require.Equal(t, findings.ExceptionRule{Namespace: "ffs", Name: "accept", ClusterWide: true, AdvisoryIDs: []string{cve}, Expires: expires}, got[0])
	require.Equal(t, 2, eng.calls)
}

func TestExceptionReconciler_InvalidNotApplied(t *testing.T) {
	needEnv(t)
	st := newStore(t)
	now := t0
	r, eng := newReconciler(t, st, &now)
	createException(t, "web", "accept", acceptSpec(cve, t0.Add(30*24*time.Hour)))
	reconcileException(t, r, "web", "accept")
	require.Len(t, rules(t, st), 1)

	ex := getException(t, "web", "accept")
	ex.Spec.Expires = metav1.NewTime(t0.Add(400 * 24 * time.Hour))
	require.NoError(t, env.Client.Update(ctx, &ex))
	res := reconcileException(t, r, "web", "accept")
	require.Equal(t, reconcile.Result{RequeueAfter: time.Hour}, res, "an invalid exception is checked again within the hour")
	require.Empty(t, rules(t, st), "an invalid exception's rule is dropped")
	require.Equal(t, 2, eng.calls)

	got := getException(t, "web", "accept")
	ready := apimeta.FindStatusCondition(got.Status.Conditions, "Ready")
	require.NotNil(t, ready)
	require.Equal(t, metav1.ConditionFalse, ready.Status)
	require.Equal(t, "Invalid", ready.Reason)
	require.Equal(t, "expires must be at most 365 days from now", ready.Message)
	require.Equal(t, got.Generation, got.Status.ObservedGeneration)
}

// TestExceptionReconciler_InvalidRequeuedUntilValid (F54): an Exception whose expiry is too far ahead
// is requeued for when it comes within exceptions.maxDuration, and then applies, with no spec change.
func TestExceptionReconciler_InvalidRequeuedUntilValid(t *testing.T) {
	needEnv(t)
	st := newStore(t)
	now := t0
	r, _ := newReconciler(t, st, &now)
	createException(t, "web", "later", acceptSpec(cve, t0.Add(8760*time.Hour+30*time.Minute)))

	res := reconcileException(t, r, "web", "later")
	require.Equal(t, 30*time.Minute, res.RequeueAfter, "requeued for when the expiry comes within a year")
	require.Empty(t, rules(t, st))

	now = now.Add(res.RequeueAfter)
	res = reconcileException(t, r, "web", "later")
	require.Len(t, rules(t, st), 1, "it applies once its expiry is in range")
	require.Equal(t, 2*time.Minute, res.RequeueAfter)
	ready := apimeta.FindStatusCondition(getException(t, "web", "later").Status.Conditions, "Ready")
	require.NotNil(t, ready)
	require.Equal(t, "Active", ready.Reason)
}

func TestExceptionReconciler_StatusCounts(t *testing.T) {
	needEnv(t)
	st := newStore(t)
	seedAdvisory(t, st)
	excepted := openFinding(deployment("web", "a"), debianRepo, cve, model.PriorityHigh, t0)
	excepted.State, excepted.ExceptedBy = model.StateExcepted, "web/accept"
	urgent := openFinding(deployment("web", "b"), debianRepo, cve, model.PriorityUrgent, t0)
	apply(t, st, excepted, urgent)
	now := t0
	r, _ := newReconciler(t, st, &now)
	expires := t0.Add(30 * 24 * time.Hour)
	createException(t, "web", "accept", acceptSpec(cve, expires))

	reconcileException(t, r, "web", "accept")
	s := getException(t, "web", "accept").Status
	require.Equal(t, int32(1), s.MatchedFindings)
	require.Equal(t, int32(1), s.UrgentNotExcepted)
	require.False(t, s.Expired)
	cond := apimeta.FindStatusCondition(s.Conditions, "UrgentNotExcepted")
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionTrue, cond.Status)
	require.Equal(t, "UrgentRequiresAdmin", cond.Reason)
	require.Equal(t, "1 urgent findings match but were not excepted: urgent findings can only be excepted from the ffs namespace", cond.Message)

	resolved := t0.Add(time.Hour)
	urgent.State, urgent.ResolvedAt = model.StateResolved, &resolved
	apply(t, st, urgent)
	reconcileException(t, r, "web", "accept")
	s = getException(t, "web", "accept").Status
	require.Zero(t, s.UrgentNotExcepted)
	require.Nil(t, apimeta.FindStatusCondition(s.Conditions, "UrgentNotExcepted"))

	now = expires.Add(time.Second)
	res := reconcileException(t, r, "web", "accept")
	require.Equal(t, 2*time.Minute, res.RequeueAfter)
	s = getException(t, "web", "accept").Status
	require.True(t, s.Expired)
	ready := apimeta.FindStatusCondition(s.Conditions, "Ready")
	require.NotNil(t, ready)
	require.Equal(t, metav1.ConditionFalse, ready.Status)
	require.Equal(t, "Expired", ready.Reason)
}

func TestExceptionReconciler_ExpiredWhileDownRecomputes(t *testing.T) {
	needEnv(t)
	st := newStore(t)
	seedAdvisory(t, st)
	now := t0
	r, eng := newReconciler(t, st, &now)
	expires := t0.Add(24 * time.Hour)
	createException(t, "web", "accept", acceptSpec(cve, expires))
	reconcileException(t, r, "web", "accept")
	require.Equal(t, 1, eng.calls)
	excepted := openFinding(deployment("web", "a"), debianRepo, cve, model.PriorityHigh, t0)
	excepted.State, excepted.ExceptedBy = model.StateExcepted, "web/accept"
	apply(t, st, excepted)

	// ffs restarts after the expiry: the cached rule is identical, but the finding is still excepted.
	now = expires.Add(time.Hour)
	r, eng = newReconciler(t, st, &now)
	reconcileException(t, r, "web", "accept")
	require.Equal(t, 1, eng.calls, "an expired rule that still excepts findings recomputes")
	s := getException(t, "web", "accept").Status
	require.True(t, s.Expired)
	require.Equal(t, int32(1), s.MatchedFindings)
	reconcileException(t, r, "web", "accept")
	require.Equal(t, 1, eng.calls, "the requeue does not repeat the recompute for the same expiry")

	excepted.State, excepted.ExceptedBy = model.StateOpen, ""
	apply(t, st, excepted)
	reconcileException(t, r, "web", "accept")
	require.Equal(t, 1, eng.calls)
	require.Zero(t, getException(t, "web", "accept").Status.MatchedFindings)

	// A restart once the findings reopened does not recompute.
	r, eng = newReconciler(t, st, &now)
	reconcileException(t, r, "web", "accept")
	require.Zero(t, eng.calls, "an expired rule that excepts nothing does not recompute")
}

func TestExceptionReconciler_DeletedRemovesRule(t *testing.T) {
	needEnv(t)
	st := newStore(t)
	now := t0
	r, eng := newReconciler(t, st, &now)
	createException(t, "web", "accept", acceptSpec(cve, t0.Add(24*time.Hour)))
	reconcileException(t, r, "web", "accept")
	require.Equal(t, 1, eng.calls)

	ex := getException(t, "web", "accept")
	require.NoError(t, env.Client.Delete(ctx, &ex))
	reconcileException(t, r, "web", "accept")
	require.Empty(t, rules(t, st))
	require.Equal(t, 2, eng.calls)
	reconcileException(t, r, "web", "accept")
	require.Equal(t, 2, eng.calls, "a missing Exception with no cached rule does not recompute")

	_, err := st.PutExceptionRule(ctx, findings.ExceptionRule{Namespace: "web", Name: "ghost", Packages: []string{"openssl"},
		Expires: t0.Add(time.Hour)})
	require.NoError(t, err)
	require.NoError(t, r.PruneCache(ctx))
	require.Empty(t, rules(t, st), "a rule without an Exception is pruned")
	require.Equal(t, 3, eng.calls)
}

// filterRecorder records the finding filters the reconciler reads with.
type filterRecorder struct {
	*store.Store
	filters []store.FindingFilter
}

func (s *filterRecorder) ListFindings(ctx context.Context, f store.FindingFilter) ([]model.Finding, error) {
	s.filters = append(s.filters, f)
	return s.Store.ListFindings(ctx, f)
}

// TestExceptionReconciler_ReadsOnlyWhatItCounts pins the cost of a reconcile (F36): it decodes
// only the open urgent findings of the Exception's namespace, never every open and excepted
// finding, and an expired Exception that excepts nothing is not requeued forever.
func TestExceptionReconciler_ReadsOnlyWhatItCounts(t *testing.T) {
	needEnv(t)
	st := newStore(t)
	seedAdvisory(t, st)
	excepted := openFinding(deployment("web", "a"), debianRepo, cve, model.PriorityHigh, t0)
	excepted.State, excepted.ExceptedBy = model.StateExcepted, "web/accept"
	urgent := openFinding(deployment("web", "b"), debianRepo, cve, model.PriorityUrgent, t0)
	high := openFinding(deployment("web", "c"), debianRepo, cve, model.PriorityHigh, t0)
	apply(t, st, excepted, urgent, high)
	now := t0
	r, _ := newReconciler(t, st, &now)
	rec := &filterRecorder{Store: st}
	r.Store = rec
	expires := t0.Add(24 * time.Hour)
	createException(t, "web", "accept", acceptSpec(cve, expires))

	res := reconcileException(t, r, "web", "accept")
	require.Equal(t, 2*time.Minute, res.RequeueAfter)
	s := getException(t, "web", "accept").Status
	require.Equal(t, int32(1), s.MatchedFindings)
	require.Equal(t, int32(1), s.UrgentNotExcepted)
	require.NotEmpty(t, rec.filters)
	for _, f := range rec.filters {
		require.Equal(t, []model.FindingState{model.StateOpen}, f.States, "only open findings are read")
		require.Equal(t, model.PriorityUrgent, f.MinPriority, "only urgent findings are read")
		require.Equal(t, "web", f.Namespace, "only the Exception's namespace is read")
	}

	// Expired and still excepting a finding: requeued until the engine reopens it.
	now = expires.Add(time.Second)
	rec.filters = nil
	res = reconcileException(t, r, "web", "accept")
	require.Equal(t, 2*time.Minute, res.RequeueAfter)
	require.Empty(t, rec.filters, "an expired Exception excepts nothing new, so no urgent finding is read")

	// Expired and excepting nothing: final, not requeued.
	excepted.State, excepted.ExceptedBy = model.StateOpen, ""
	apply(t, st, excepted)
	res = reconcileException(t, r, "web", "accept")
	require.Zero(t, res.RequeueAfter)
	s = getException(t, "web", "accept").Status
	require.True(t, s.Expired)
	require.Zero(t, s.MatchedFindings)
}
