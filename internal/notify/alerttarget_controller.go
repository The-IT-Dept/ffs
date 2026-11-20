package notify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/robfig/cron/v3"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	ffsv1alpha1 "github.com/the-it-dept/ffs/api/v1alpha1"
	"github.com/the-it-dept/ffs/internal/model"
)

const (
	defaultURLKey     = "url"
	defaultSigningKey = "signingSecret"
	defaultSchedule   = "0 9 * * *"
	failingThreshold  = 3
	requeueEvery      = time.Minute
	readyCondition    = "Ready"
)

// SinkConfig is what a SinkFactory needs to build a sink for one AlertTarget.
type SinkConfig struct {
	Name, URL, SigningSecret, Cluster string
	AllowPrivate                      bool
	// Blocked returns, on each send, the address ranges refused unless AllowPrivate is set, besides
	// the built-in private ones; nil means none.
	Blocked func(ctx context.Context) []netip.Prefix
}

// SinkFactory builds the sink for a target of type typ. Its errors must not contain the URL.
type SinkFactory func(typ string, cfg SinkConfig) (Sink, error)

// SpecError is an AlertTarget or Secret problem, shown as the Ready condition's reason and message.
// Reason is InvalidSpec or SecretInvalid.
type SpecError struct{ Reason, Msg string }

func (e *SpecError) Error() string { return e.Msg }

func invalidSpec(format string, a ...any) *SpecError {
	return &SpecError{Reason: "InvalidSpec", Msg: fmt.Sprintf(format, a...)}
}

func secretInvalid(format string, a ...any) *SpecError {
	return &SpecError{Reason: "SecretInvalid", Msg: fmt.Sprintf(format, a...)}
}

// secretKeys returns the Secret keys of the URL and the signing secret, with the defaults.
func secretKeys(ref ffsv1alpha1.SecretReference) (urlKey, signingKey string) {
	urlKey, signingKey = ref.URLKey, ref.SigningSecretKey
	if urlKey == "" {
		urlKey = defaultURLKey
	}
	if signingKey == "" {
		signingKey = defaultSigningKey
	}
	return urlKey, signingKey
}

// parsePriority parses a spec priority, def when empty.
func parsePriority(field, s string, def model.Priority) (model.Priority, error) {
	if s == "" {
		return def, nil
	}
	p, err := model.ParsePriority(s)
	if err != nil {
		return model.PriorityNone, invalidSpec("%s: %v", field, err)
	}
	return p, nil
}

// TargetConfigFrom builds the engine config and the sink config of at from its Secret sec, with the
// spec defaults filled in. nsMatch limits the target to namespaces; nil means all. Its error is a
// *SpecError and never contains the endpoint.
func TargetConfigFrom(at *ffsv1alpha1.AlertTarget, sec *corev1.Secret, nsMatch func(string) bool) (TargetConfig, SinkConfig, error) {
	sp := at.Spec
	urlKey, signingKey := secretKeys(sp.SecretRef)
	if sec == nil {
		return TargetConfig{}, SinkConfig{}, secretInvalid("the Secret was not provided")
	}
	endpoint := strings.TrimSpace(string(sec.Data[urlKey]))
	if endpoint == "" {
		return TargetConfig{}, SinkConfig{}, secretInvalid("Secret %s has no %q key", sec.Name, urlKey)
	}
	signing := strings.TrimSpace(string(sec.Data[signingKey]))
	if sp.Type == "webhook" && signing == "" {
		return TargetConfig{}, SinkConfig{}, secretInvalid("Secret %s has no %q key; webhook targets need a signing secret", sec.Name, signingKey)
	}

	immediateMin, err := parsePriority("spec.immediate.minPriority", sp.Immediate.MinPriority, model.PriorityUrgent)
	if err != nil {
		return TargetConfig{}, SinkConfig{}, err
	}
	digestMin, err := parsePriority("spec.digest.minPriority", sp.Digest.MinPriority, model.PriorityMedium)
	if err != nil {
		return TargetConfig{}, SinkConfig{}, err
	}
	schedule := sp.Digest.Schedule
	if schedule == "" {
		schedule = defaultSchedule
	}
	if _, err := cron.ParseStandard(schedule); err != nil {
		return TargetConfig{}, SinkConfig{}, invalidSpec("spec.digest.schedule: %v", err)
	}
	loc := time.UTC
	if tz := sp.Digest.TimeZone; tz != "" {
		if loc, err = time.LoadLocation(tz); err != nil {
			return TargetConfig{}, SinkConfig{}, invalidSpec("spec.digest.timeZone: unknown time zone %q", tz)
		}
	}
	includeResolved := sp.Digest.IncludeResolved == nil || *sp.Digest.IncludeResolved

	cfg := TargetConfig{
		UID: string(at.UID), Name: at.Name, Type: sp.Type,
		ImmediateMin:            immediateMin,
		Digest:                  DigestConfig{Schedule: schedule, Location: loc, MinPriority: digestMin, IncludeResolved: includeResolved},
		NamespaceMatch:          nsMatch,
		AllowUrgentInQuietHours: true,
		NotifyOnFeedStale:       sp.NotifyOnFeedStale,
		Paused:                  sp.Paused,
	}
	if q := sp.QuietHours; q != nil {
		if q.AllowUrgent != nil {
			cfg.AllowUrgentInQuietHours = *q.AllowUrgent
		}
		for i, iv := range q.Intervals {
			ti := TimeInterval{Weekdays: iv.Weekdays, DaysOfMonth: iv.DaysOfMonth, Months: iv.Months, Years: iv.Years, Location: iv.Location}
			for _, t := range iv.Times {
				ti.Times = append(ti.Times, TimeRange{StartTime: t.StartTime, EndTime: t.EndTime})
			}
			if err := ti.Validate(); err != nil {
				return TargetConfig{}, SinkConfig{}, invalidSpec("spec.quietHours.intervals[%d]: %v", i, err)
			}
			cfg.QuietHours = append(cfg.QuietHours, ti)
		}
	}

	spec, err := json.Marshal(sp)
	if err != nil {
		return TargetConfig{}, SinkConfig{}, invalidSpec("spec: %v", err)
	}
	h := sha256.New()
	for _, part := range [][]byte{spec, []byte(endpoint), []byte(signing)} {
		_, _ = h.Write(part)
		_, _ = h.Write([]byte{0})
	}
	cfg.ConfigHash = hex.EncodeToString(h.Sum(nil))[:16]

	return cfg, SinkConfig{Name: at.Name, URL: endpoint, SigningSecret: signing, AllowPrivate: sp.AllowPrivate}, nil
}

// TargetReconciler registers each AlertTarget with the Engine and reports its status.
type TargetReconciler struct {
	Client client.Client
	// Secrets reads Secrets uncached: ffs holds get on them but not list or watch.
	Secrets   client.Reader
	Engine    *Engine
	Namespace string
	Cluster   string
	NewSink   SinkFactory
	// Blocked is passed to every sink as SinkConfig.Blocked.
	Blocked func(ctx context.Context) []netip.Prefix
	Log     logr.Logger
}

// Reconcile registers the AlertTarget req names, or forgets it when it is gone. A target that
// cannot be registered (its Secret is missing, unreadable or invalid, or its spec is invalid) is
// detached, so nothing goes on being sent to the endpoint it had before; its stored state is kept.
func (r *TargetReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var at ffsv1alpha1.AlertTarget
	if err := r.Client.Get(ctx, req.NamespacedName, &at); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, r.Engine.Unregister(ctx, req.Name)
		}
		return ctrl.Result{}, err
	}

	cond := r.register(ctx, &at)
	if cond != nil {
		r.Engine.Detach(string(at.UID))
	}
	if cond == nil {
		// Registered: the Engine's stored state decides the condition.
		c, err := r.engineCondition(ctx, &at)
		if err != nil {
			return ctrl.Result{}, err
		}
		cond = &c
	} else if st, ok, err := r.Engine.Status(ctx, string(at.UID)); err != nil {
		return ctrl.Result{}, err
	} else if ok {
		at.Status.LastError = st.LastError
		if !st.LastDeliveryAt.IsZero() {
			t := metav1.NewTime(st.LastDeliveryAt.UTC().Truncate(time.Second))
			at.Status.LastDelivery = &t
		}
	}
	return ctrl.Result{RequeueAfter: requeueEvery}, r.updateStatus(ctx, &at, *cond)
}

// register builds and registers the target. It returns nil when registered, else the False
// condition that explains why not.
func (r *TargetReconciler) register(ctx context.Context, at *ffsv1alpha1.AlertTarget) *metav1.Condition {
	var sec corev1.Secret
	key := types.NamespacedName{Namespace: r.Namespace, Name: at.Spec.SecretRef.Name}
	if err := r.Secrets.Get(ctx, key, &sec); err != nil {
		if apierrors.IsNotFound(err) {
			return notReady("SecretNotFound", fmt.Sprintf("Secret %s was not found in namespace %s", key.Name, r.Namespace))
		}
		ctrl.LoggerFrom(ctx).Error(err, "reading AlertTarget secret", "secret", key.String())
		return notReady("SecretUnreadable", fmt.Sprintf("Secret %s could not be read: %v", key.Name, err))
	}
	cfg, sc, err := TargetConfigFrom(at, &sec, r.namespaceMatch(at))
	if err != nil {
		var se *SpecError
		if errors.As(err, &se) {
			return notReady(se.Reason, se.Msg)
		}
		return notReady("InvalidSpec", err.Error())
	}
	cfg.NamespaceGone = r.namespaceGone(at)
	sc.Cluster, sc.Blocked = r.Cluster, r.Blocked
	// A resync with nothing changed keeps the registered sink, and with it its idle connections.
	sink, ok := r.Engine.sinkFor(cfg.UID, cfg.ConfigHash)
	if !ok {
		if sink, err = r.NewSink(at.Spec.Type, sc); err != nil {
			return notReady("SecretInvalid", err.Error())
		}
	}
	if err := r.Engine.Register(ctx, cfg, sink); err != nil {
		return notReady("InvalidSpec", err.Error())
	}
	return nil
}

func notReady(reason, msg string) *metav1.Condition {
	return &metav1.Condition{Status: metav1.ConditionFalse, Reason: reason, Message: msg}
}

// engineCondition derives the Ready condition of a registered target from the Engine's state.
func (r *TargetReconciler) engineCondition(ctx context.Context, at *ffsv1alpha1.AlertTarget) (metav1.Condition, error) {
	st, ok, err := r.Engine.Status(ctx, string(at.UID))
	if err != nil {
		return metav1.Condition{}, err
	}
	c := metav1.Condition{Status: metav1.ConditionTrue, Reason: "Registered", Message: "Registered for delivery"}
	switch {
	case ok && st.Disabled:
		c = *notReady("EndpointGone", cmpOr(st.DisabledReason, "The endpoint is no longer accepting alerts"))
	case at.Spec.Paused:
		c.Reason, c.Message = "Paused", "Deliveries are paused"
	case ok && st.ConsecutiveFailures >= failingThreshold:
		c = *notReady("DeliveryFailing", fmt.Sprintf("%d consecutive delivery failures: %s", st.ConsecutiveFailures, st.LastError))
	}
	if ok && !st.LastDeliveryAt.IsZero() {
		t := metav1.NewTime(st.LastDeliveryAt.UTC().Truncate(time.Second))
		at.Status.LastDelivery = &t
	} else {
		at.Status.LastDelivery = nil
	}
	if ok {
		at.Status.LastError = st.LastError
	}
	return c, nil
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// updateStatus sets the Ready condition and writes the status only when it changed.
func (r *TargetReconciler) updateStatus(ctx context.Context, at *ffsv1alpha1.AlertTarget, c metav1.Condition) error {
	var old ffsv1alpha1.AlertTarget
	if err := r.Client.Get(ctx, client.ObjectKeyFromObject(at), &old); err != nil {
		return client.IgnoreNotFound(err)
	}
	next := old.Status.DeepCopy()
	next.LastDelivery, next.LastError = at.Status.LastDelivery, at.Status.LastError
	next.ObservedGeneration = at.Generation
	c.Type, c.ObservedGeneration = readyCondition, at.Generation
	meta.SetStatusCondition(&next.Conditions, c)
	if equality.Semantic.DeepEqual(old.Status, *next) {
		return nil
	}
	old.Status = *next
	return client.IgnoreNotFound(r.Client.Status().Update(ctx, &old))
}

// namespaceMatch limits at to spec.namespaces or namespaces whose labels match its selector; nil
// when neither is set.
func (r *TargetReconciler) namespaceMatch(at *ffsv1alpha1.AlertTarget) func(string) bool {
	names, sel := slices.Clone(at.Spec.Namespaces), at.Spec.NamespaceSelector
	if len(names) == 0 && sel == nil {
		return nil
	}
	var selector labels.Selector
	if sel != nil {
		var err error
		if selector, err = metav1.LabelSelectorAsSelector(sel); err != nil {
			selector = labels.Nothing()
		}
	}
	return func(ns string) bool {
		if slices.Contains(names, ns) {
			return true
		}
		if selector == nil {
			return false
		}
		var n corev1.Namespace
		if err := r.Client.Get(context.Background(), types.NamespacedName{Name: ns}, &n); err != nil {
			return false
		}
		return selector.Matches(labels.Set(n.Labels))
	}
}

// namespaceGone reports, for a target with a namespace selector, that a namespace has been
// deleted, so the resolutions of findings sent from it still reach the target; nil without a
// selector, since spec.namespaces matches by name whether the namespace exists or not.
func (r *TargetReconciler) namespaceGone(at *ffsv1alpha1.AlertTarget) func(string) bool {
	if at.Spec.NamespaceSelector == nil {
		return nil
	}
	return func(ns string) bool {
		var n corev1.Namespace
		return apierrors.IsNotFound(r.Client.Get(context.Background(), types.NamespacedName{Name: ns}, &n))
	}
}

// SetupWithManager registers the reconciler and, on the leader, a one-off cleanup of notification
// state belonging to AlertTargets deleted while ffs was not running.
func (r *TargetReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := ctrl.NewControllerManagedBy(mgr).For(&ffsv1alpha1.AlertTarget{}).Named("alerttarget").Complete(r); err != nil {
		return err
	}
	return mgr.Add(manager.RunnableFunc(func(ctx context.Context) error {
		if !mgr.GetCache().WaitForCacheSync(ctx) {
			return nil // shutting down
		}
		return r.startupRetain(ctx)
	}))
}

// startupRetain deletes the stored state of AlertTargets that no longer exist, once at start. A
// failure is logged, not returned: the state is left until the next start, which is not worth
// stopping the manager for.
func (r *TargetReconciler) startupRetain(ctx context.Context) error {
	if err := r.retainLive(ctx); err != nil && ctx.Err() == nil {
		r.Log.Error(err, "deleting the notification state of deleted AlertTargets failed")
	}
	return nil
}

// retainLive deletes the stored state of every target that is not a current AlertTarget.
func (r *TargetReconciler) retainLive(ctx context.Context) error {
	var list ffsv1alpha1.AlertTargetList
	if err := r.Client.List(ctx, &list); err != nil {
		return fmt.Errorf("listing AlertTargets: %w", err)
	}
	uids := make([]string, len(list.Items))
	for i := range list.Items {
		uids[i] = string(list.Items[i].UID)
	}
	return r.Engine.Retain(ctx, uids)
}
