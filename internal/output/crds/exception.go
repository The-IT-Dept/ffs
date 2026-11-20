package crds

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/the-it-dept/ffs/api/v1alpha1"
	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/findings"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

const (
	conditionReady             = "Ready"
	conditionUrgentNotExcepted = "UrgentNotExcepted"
	reasonActive               = "Active"
	reasonExpired              = "Expired"
	reasonInvalid              = "Invalid"
	reasonUrgentRequiresAdmin  = "UrgentRequiresAdmin"

	// exceptionResync refreshes an Exception's status counts, which move with findings. An expired
	// Exception that excepts nothing is not refreshed: nothing can change its counts any more.
	exceptionResync = 2 * time.Minute
)

// vexStatuses are the accepted values of spec.vexStatus, besides "".
var vexStatuses = []string{"not_affected", "affected", "fixed", "under_investigation"}

// ExceptionStore is the part of the store the Exception reconciler uses.
type ExceptionStore interface {
	Canonical(ctx context.Context, id string) (string, error)
	PutExceptionRule(ctx context.Context, r findings.ExceptionRule) (changed bool, err error)
	DeleteExceptionRule(ctx context.Context, namespace, name string) (deleted bool, err error)
	ExceptionRules(ctx context.Context) ([]findings.ExceptionRule, error)
	CountExceptedBy(ctx context.Context, key string) (int, error)
	ListFindings(ctx context.Context, f store.FindingFilter) ([]model.Finding, error)
	Advisories(ctx context.Context, ids []string) (map[string]model.Advisory, error)
}

// ExceptionReconciler caches each valid Exception as a findings.ExceptionRule, asks the engine to
// recompute when the cached rules change or an expired rule still excepts findings, and reports
// what the Exception matches in its status.
type ExceptionReconciler struct {
	Client client.Client
	Store  ExceptionStore
	Engine interface {
		OnExceptionsChanged(ctx context.Context) error
	}
	Config    config.Config
	Namespace string // ffs install namespace: Exceptions here apply cluster-wide
	Now       func() time.Time

	// recomputeOwed is set when the cached rules changed but OnExceptionsChanged failed, so the
	// next reconcile retries the call even though the cache no longer reports a change.
	recomputeOwed atomic.Bool

	expiryMu sync.Mutex
	// expiryRecomputed maps a rule key to the expiry this process already asked the engine to
	// reopen findings for, so an expired rule triggers at most one recompute per expiry.
	expiryRecomputed map[string]time.Time
}

// ValidateException checks what the CRD schema cannot: reason, expires at most maxDuration from
// now, at least one criterion and the VEX status. An Exception that already expired is valid.
func ValidateException(spec v1alpha1.ExceptionSpec, now time.Time, maxDuration time.Duration) error {
	switch {
	case strings.TrimSpace(spec.Reason) == "":
		return errors.New("reason is required")
	case spec.Expires.IsZero():
		return errors.New("expires is required")
	case spec.Expires.After(now.Add(maxDuration)):
		return fmt.Errorf("expires must be at most %s from now", durationText(maxDuration))
	case len(spec.Advisories) == 0 && len(spec.Packages) == 0 && len(spec.ImageRepositories) == 0 && len(spec.Owners) == 0:
		return errors.New("at least one of advisories, packages, imageRepositories or owners is required")
	case spec.VEXStatus != "" && !slices.Contains(vexStatuses, spec.VEXStatus):
		return errors.New("vexStatus must be one of not_affected, affected, fixed, under_investigation")
	}
	return nil
}

// durationText renders a maximum duration as whole days ("365 days") when it is one.
func durationText(d time.Duration) string {
	const day = 24 * time.Hour
	switch {
	case d == day:
		return "1 day"
	case d > 0 && d%day == 0:
		return fmt.Sprintf("%d days", d/day)
	}
	return d.String()
}

// Reconcile caches or drops one Exception's rule and refreshes its status. A valid Exception is
// requeued at its expiry or within 2 minutes, whichever is sooner, so its counts stay current; one
// that has expired and excepts nothing is not requeued.
// The engine recomputes when the cached rule changed or was dropped, and once per expiry when an
// expired rule still excepts findings (see reopenExpired); never merely because of the requeue.
func (r *ExceptionReconciler) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	var ex v1alpha1.Exception
	if err := r.Client.Get(ctx, req.NamespacedName, &ex); err != nil {
		if !apierrors.IsNotFound(err) {
			return reconcile.Result{}, err
		}
		return reconcile.Result{}, r.forget(ctx, req.Namespace, req.Name)
	}
	now := r.now()
	if verr := ValidateException(ex.Spec, now, r.Config.Exceptions.MaxDuration); verr != nil {
		if err := r.forget(ctx, ex.Namespace, ex.Name); err != nil {
			return reconcile.Result{}, err
		}
		st := v1alpha1.ExceptionStatus{ObservedGeneration: ex.Generation, Conditions: slices.Clone(ex.Status.Conditions)}
		apimeta.RemoveStatusCondition(&st.Conditions, conditionUrgentNotExcepted)
		setCondition(&st, conditionReady, metav1.ConditionFalse, reasonInvalid, verr.Error(), now)
		return reconcile.Result{}, r.writeStatus(ctx, &ex, st)
	}

	rule, err := r.rule(ctx, &ex)
	if err != nil {
		return reconcile.Result{}, err
	}
	changed, err := r.Store.PutExceptionRule(ctx, rule)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("cache exception rule: %w", err)
	}
	if err := r.rulesChanged(ctx, changed); err != nil {
		return reconcile.Result{}, err
	}
	st, err := r.status(ctx, &ex, rule, now)
	if err != nil {
		return reconcile.Result{}, err
	}
	if err := r.reopenExpired(ctx, rule, st, changed); err != nil {
		return reconcile.Result{}, err
	}
	if err := r.writeStatus(ctx, &ex, st); err != nil {
		return reconcile.Result{}, err
	}
	if st.Expired && st.MatchedFindings == 0 {
		return reconcile.Result{}, nil // final: it can except nothing, and nothing it excepts is left to reopen
	}
	requeue := exceptionResync
	if left := rule.Expires.Sub(now); left > 0 && left < requeue {
		requeue = left
	}
	return reconcile.Result{RequeueAfter: requeue}, nil
}

// SetupWithManager registers the reconciler for Exception spec changes.
func (r *ExceptionReconciler) SetupWithManager(m manager.Manager) error {
	return builder.ControllerManagedBy(m).
		For(&v1alpha1.Exception{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Named("ffs-exception").
		Complete(r)
}

// PruneCache drops every cached rule whose Exception no longer exists, such as one deleted while
// ffs was not running. Run it once at startup.
func (r *ExceptionReconciler) PruneCache(ctx context.Context) error {
	// Rules are read before the resources, so a rule cached for an Exception created meanwhile
	// is never mistaken for an orphan.
	rules, err := r.Store.ExceptionRules(ctx)
	if err != nil {
		return fmt.Errorf("crds: read cached exception rules: %w", err)
	}
	var list v1alpha1.ExceptionList
	if err := r.Client.List(ctx, &list); err != nil {
		return fmt.Errorf("crds: list exceptions: %w", err)
	}
	live := map[types.NamespacedName]bool{}
	for _, ex := range list.Items {
		live[types.NamespacedName{Namespace: ex.Namespace, Name: ex.Name}] = true
	}
	var deleted bool
	for _, rule := range rules {
		if live[types.NamespacedName{Namespace: rule.Namespace, Name: rule.Name}] {
			continue
		}
		d, err := r.Store.DeleteExceptionRule(ctx, rule.Namespace, rule.Name)
		if err != nil {
			return fmt.Errorf("crds: drop exception rule %s: %w", rule.Key(), err)
		}
		deleted = deleted || d
	}
	return r.rulesChanged(ctx, deleted)
}

// forget drops the cached rule of an Exception.
func (r *ExceptionReconciler) forget(ctx context.Context, namespace, name string) error {
	deleted, err := r.Store.DeleteExceptionRule(ctx, namespace, name)
	if err != nil {
		return fmt.Errorf("drop exception rule: %w", err)
	}
	r.expiryMu.Lock()
	delete(r.expiryRecomputed, findings.ExceptionRule{Namespace: namespace, Name: name}.Key())
	r.expiryMu.Unlock()
	return r.rulesChanged(ctx, deleted)
}

// reopenExpired asks the engine to recompute when rule has expired but findings are still excepted
// by it. That happens when the rule expired while ffs was down: the cached rule is unchanged, so
// PutExceptionRule reports no change, and the engine's expiry check only sees expiries after it
// started. The call is made once per rule expiry in this process (the engine retries owners whose
// recompute fails), so the 2-minute requeue never repeats it; changed means rulesChanged already
// made it.
func (r *ExceptionReconciler) reopenExpired(ctx context.Context, rule findings.ExceptionRule, st v1alpha1.ExceptionStatus,
	changed bool) error {
	if !st.Expired || st.MatchedFindings == 0 {
		return nil
	}
	r.expiryMu.Lock()
	defer r.expiryMu.Unlock()
	if done, ok := r.expiryRecomputed[rule.Key()]; ok && done.Equal(rule.Expires) {
		return nil
	}
	if !changed {
		if err := r.Engine.OnExceptionsChanged(ctx); err != nil {
			return fmt.Errorf("recompute after exception expiry: %w", err)
		}
	}
	if r.expiryRecomputed == nil {
		r.expiryRecomputed = map[string]time.Time{}
	}
	r.expiryRecomputed[rule.Key()] = rule.Expires
	return nil
}

// rulesChanged calls OnExceptionsChanged when the cached rules changed, or when an earlier call
// for a change failed.
func (r *ExceptionReconciler) rulesChanged(ctx context.Context, changed bool) error {
	if !changed && !r.recomputeOwed.Load() {
		return nil
	}
	if err := r.Engine.OnExceptionsChanged(ctx); err != nil {
		r.recomputeOwed.Store(true)
		return fmt.Errorf("recompute after exception change: %w", err)
	}
	r.recomputeOwed.Store(false)
	return nil
}

// rule builds the cached rule of a valid Exception, with advisory ids resolved to canonical ids.
func (r *ExceptionReconciler) rule(ctx context.Context, ex *v1alpha1.Exception) (findings.ExceptionRule, error) {
	var ids []string
	for _, id := range ex.Spec.Advisories {
		c, err := r.Store.Canonical(ctx, id)
		if err != nil {
			return findings.ExceptionRule{}, fmt.Errorf("resolve advisory %q: %w", id, err)
		}
		if !slices.Contains(ids, c) {
			ids = append(ids, c)
		}
	}
	return findings.ExceptionRule{
		Namespace:      ex.Namespace,
		Name:           ex.Name,
		ClusterWide:    ex.Namespace == r.Namespace,
		AdvisoryIDs:    ids,
		Packages:       ex.Spec.Packages,
		ImageRepoGlobs: ex.Spec.ImageRepositories,
		Owners:         ex.Spec.Owners,
		Expires:        ex.Spec.Expires.UTC(),
		VEXStatus:      ex.Spec.VEXStatus,
	}, nil
}

// status computes the status of a valid Exception: the findings it excepts, the open urgent
// findings it matches but may not except (it is not cluster-wide), and whether it expired. Only
// those rows are read: the excepted count comes from an index, and the urgent candidates are the
// open urgent findings of the Exception's own namespace, so a reconcile never decodes every finding.
func (r *ExceptionReconciler) status(ctx context.Context, ex *v1alpha1.Exception, rule findings.ExceptionRule,
	now time.Time) (v1alpha1.ExceptionStatus, error) {
	st := v1alpha1.ExceptionStatus{Expired: !now.Before(rule.Expires), ObservedGeneration: ex.Generation,
		Conditions: slices.Clone(ex.Status.Conditions)}
	matched, err := r.Store.CountExceptedBy(ctx, rule.Key())
	if err != nil {
		return v1alpha1.ExceptionStatus{}, fmt.Errorf("count excepted findings: %w", err)
	}
	st.MatchedFindings = int32(min(matched, math.MaxInt32))
	if !rule.ClusterWide && !st.Expired {
		urgent, err := r.Store.ListFindings(ctx, store.FindingFilter{States: []model.FindingState{model.StateOpen},
			MinPriority: model.PriorityUrgent, Namespace: rule.Namespace})
		if err != nil {
			return v1alpha1.ExceptionStatus{}, fmt.Errorf("list urgent findings: %w", err)
		}
		if len(urgent) > 0 {
			ids := make([]string, 0, len(urgent))
			for _, f := range urgent {
				ids = append(ids, f.AdvisoryID)
			}
			advs, err := r.Store.Advisories(ctx, ids)
			if err != nil {
				return v1alpha1.ExceptionStatus{}, fmt.Errorf("load advisories: %w", err)
			}
			for _, f := range urgent {
				if rule.Matches(f, advs[f.AdvisoryID].Aliases, now) {
					st.UrgentNotExcepted++
				}
			}
		}
	}

	expires := rule.Expires.Format(time.RFC3339)
	if st.Expired {
		setCondition(&st, conditionReady, metav1.ConditionFalse, reasonExpired, "The exception expired at "+expires+".", now)
	} else {
		setCondition(&st, conditionReady, metav1.ConditionTrue, reasonActive, "The exception applies until "+expires+".", now)
	}
	if st.UrgentNotExcepted > 0 {
		setCondition(&st, conditionUrgentNotExcepted, metav1.ConditionTrue, reasonUrgentRequiresAdmin,
			fmt.Sprintf("%d urgent findings match but were not excepted: urgent findings can only be excepted from the %s namespace",
				st.UrgentNotExcepted, r.Namespace), now)
	} else {
		apimeta.RemoveStatusCondition(&st.Conditions, conditionUrgentNotExcepted)
	}
	return st, nil
}

// writeStatus updates the Exception's status when it differs from st.
func (r *ExceptionReconciler) writeStatus(ctx context.Context, ex *v1alpha1.Exception, st v1alpha1.ExceptionStatus) error {
	if equality.Semantic.DeepEqual(ex.Status, st) {
		return nil
	}
	ex.Status = st
	if err := r.Client.Status().Update(ctx, ex); err != nil {
		return fmt.Errorf("update exception status: %w", err)
	}
	return nil
}

// setCondition sets a condition at the status's generation. The transition time moves only when
// the condition's status changes.
func setCondition(st *v1alpha1.ExceptionStatus, typ string, status metav1.ConditionStatus, reason, msg string, now time.Time) {
	apimeta.SetStatusCondition(&st.Conditions, metav1.Condition{Type: typ, Status: status, Reason: reason, Message: msg,
		ObservedGeneration: st.ObservedGeneration, LastTransitionTime: metav1.NewTime(now)})
}

func (r *ExceptionReconciler) now() time.Time {
	if r.Now == nil {
		return time.Now().UTC()
	}
	return r.Now().UTC()
}
