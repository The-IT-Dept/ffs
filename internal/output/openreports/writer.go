package openreports

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/go-logr/logr"
	orv1alpha1 "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/discovery"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/output/settle"
	"github.com/the-it-dept/ffs/internal/store"
)

const (
	orGroupVersion = "openreports.io/v1alpha1"
	wgGroupVersion = "wgpolicyk8s.io/v1alpha2"

	detectTTL     = 10 * time.Minute
	defaultResync = 60 * time.Second
	// listEvery is how often the writer lists its reports again; in between, it reads them from what
	// it last listed and wrote (reportCache).
	listEvery = 10 * time.Minute
)

// Options configures a Writer.
type Options struct {
	Namespace string           // ffs install namespace; home of reports for cluster-level subjects
	Changed   <-chan struct{}  // engine change signal
	Resync    time.Duration    // default 60s
	Now       func() time.Time // nil = time.Now
}

// Writer keeps one Report per owner (and optionally a PolicyReport mirror) in step with the store.
// It is a leader-only Runnable.
type Writer struct {
	c    client.Client
	r    client.Reader
	disc discovery.ServerResourcesInterfaceWithContext
	st   *store.Store
	cfg  config.OpenReportsConfig
	o    Options
	now  func() time.Time

	mu         sync.Mutex
	detectedAt time.Time
	hasOR      bool
	hasWG      bool

	reports, policyReports reportCache // used by ReconcileOnce only, which Start runs one at a time
}

// reportCache is the writer's view of the reports it manages of one kind, keyed "namespace/name":
// a full LIST at most every listEvery, kept current by the writer's own writes. A write that fails
// on a stale view (a create that finds the report, an update that finds it changed or gone) drops
// the view, so the next reconcile lists. A report someone else deletes comes back after the next
// list.
type reportCache struct {
	listedAt time.Time
	objs     map[string]client.Object
}

// New returns a Writer. r must be a non-caching reader: an informer on an absent CRD would block.
// The writer lists through r at start and every 10 minutes, and keeps its own view in between.
func New(c client.Client, r client.Reader, disc discovery.ServerResourcesInterfaceWithContext, st *store.Store, cfg config.OpenReportsConfig, o Options) *Writer {
	if o.Resync <= 0 {
		o.Resync = defaultResync
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Writer{c: c, r: r, disc: disc, st: st, cfg: cfg, o: o, now: o.Now}
}

// NeedLeaderElection reports that the writer runs on the leader only.
func (w *Writer) NeedLeaderElection() bool { return true }

// Start reconciles a second after a Changed signal (settle.Wait) and every Resync until ctx is done.
func (w *Writer) Start(ctx context.Context) error {
	log := logr.FromContextOrDiscard(ctx)
	if log.GetSink() == nil {
		log = logf.Log
	}
	log = log.WithName("openreports")
	ctx = logr.NewContext(ctx, log)
	tick := time.NewTicker(w.o.Resync)
	defer tick.Stop()
	for {
		if err := w.ReconcileOnce(ctx); err != nil && ctx.Err() == nil {
			log.Error(err, "writing OpenReports failed")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-w.o.Changed:
			if !settle.Wait(ctx, w.o.Changed, settle.Window) {
				return nil
			}
		case <-tick.C:
		}
	}
}

// detect reports whether the OpenReports and PolicyReport CRDs are served, cached for 10 minutes.
func (w *Writer) detect(ctx context.Context) (hasOR, hasWG bool, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.detectedAt.IsZero() && w.now().Sub(w.detectedAt) < detectTTL {
		return w.hasOR, w.hasWG, nil
	}
	hasOR, err = w.served(ctx, orGroupVersion, "Report")
	if err != nil {
		return false, false, err
	}
	if w.cfg.WGPolicy {
		if hasWG, err = w.served(ctx, wgGroupVersion, "PolicyReport"); err != nil {
			return false, false, err
		}
	}
	w.detectedAt, w.hasOR, w.hasWG = w.now(), hasOR, hasWG
	return hasOR, hasWG, nil
}

func (w *Writer) served(ctx context.Context, gv, kind string) (bool, error) {
	l, err := w.disc.ServerResourcesForGroupVersionWithContext(ctx, gv)
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("discover %s: %w", gv, err)
	}
	for _, r := range l.APIResources {
		if r.Kind == kind {
			return true, nil
		}
	}
	return false, nil
}

// ReconcileOnce brings the Reports (and PolicyReports) in line with the open findings. A discovery
// failure is returned in mode auto; in mode on it is logged, Reports are written anyway, the
// PolicyReport mirror waits, and discovery is tried again on the next reconcile.
func (w *Writer) ReconcileOnce(ctx context.Context) error {
	if w.cfg.Mode == "off" {
		return nil
	}
	hasOR, hasWG, err := w.detect(ctx)
	if err != nil {
		if w.cfg.Mode != "on" {
			return err
		}
		logr.FromContextOrDiscard(ctx).Error(err, "discovering the report kinds failed; writing Reports (openReports.mode on) and trying again next time")
		hasOR, hasWG = false, false
	}
	writeOR := hasOR || w.cfg.Mode == "on"
	if !writeOR && !hasWG {
		return nil
	}
	reports, err := w.desired(ctx)
	if err != nil {
		return err
	}
	// Both sets are built before any write: Create fills resourceVersion into the Report.
	wantOR := map[string]client.Object{}
	wantWG := map[string]client.Object{}
	var errs []error
	for _, rep := range reports {
		k := rep.Namespace + "/" + rep.Name
		wantOR[k] = rep
		if hasWG {
			pr, err := policyReport(rep)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			wantWG[k] = pr
		}
	}
	if hasWG {
		errs = append(errs, w.sync(ctx, &w.policyReports, wantWG, w.listPolicyReports))
	}
	if writeOR {
		errs = append(errs, w.sync(ctx, &w.reports, wantOR, w.listReports))
	}
	return errors.Join(errs...)
}

// desired builds the Report of every owner that has a finding at medium priority or above. Only
// those findings are read.
func (w *Writer) desired(ctx context.Context) ([]*orv1alpha1.Report, error) {
	fs, err := w.st.ListFindings(ctx, store.FindingFilter{States: []model.FindingState{model.StateOpen}, MinPriority: model.PriorityMedium})
	if err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}
	owners, err := w.st.ListOwners(ctx)
	if err != nil {
		return nil, fmt.Errorf("list owners: %w", err)
	}
	byOwner := map[string][]model.Finding{}
	var order []string
	ids := map[string]bool{}
	for _, f := range fs {
		k := f.Owner.Key()
		if _, ok := byOwner[k]; !ok {
			order = append(order, k)
		}
		byOwner[k] = append(byOwner[k], f)
		ids[f.AdvisoryID] = true
	}
	var idList []string
	for id := range ids {
		idList = append(idList, id)
	}
	advs, err := w.st.Advisories(ctx, idList)
	if err != nil {
		return nil, fmt.Errorf("load advisories: %w", err)
	}
	known := map[string]model.Owner{}
	for _, o := range owners {
		known[o.Ref.Key()] = o
	}
	var out []*orv1alpha1.Report
	for _, k := range order {
		o, ok := known[k]
		if !ok {
			o = model.Owner{Ref: byOwner[k][0].Owner}
		}
		if rep, ok := BuildReport(o, byOwner[k], advs, w.cfg.MaxResults, w.o.Namespace); ok {
			out = append(out, rep)
		}
	}
	return out, nil
}

func (w *Writer) listReports(ctx context.Context) ([]client.Object, error) {
	var l orv1alpha1.ReportList
	if err := w.r.List(ctx, &l, client.MatchingLabels{LabelManagedBy: "ffs"}); err != nil {
		return nil, fmt.Errorf("list Reports: %w", err)
	}
	out := make([]client.Object, len(l.Items))
	for i := range l.Items {
		out[i] = &l.Items[i]
	}
	return out, nil
}

func (w *Writer) listPolicyReports(ctx context.Context) ([]client.Object, error) {
	var l unstructured.UnstructuredList
	l.SetAPIVersion(wgGroupVersion)
	l.SetKind("PolicyReportList")
	if err := w.r.List(ctx, &l, client.MatchingLabels{LabelManagedBy: "ffs"}); err != nil {
		return nil, fmt.Errorf("list PolicyReports: %w", err)
	}
	out := make([]client.Object, len(l.Items))
	for i := range l.Items {
		out[i] = &l.Items[i]
	}
	return out, nil
}

// sync creates the missing objects in want, updates those whose content hash differs and deletes
// the managed ones that are no longer wanted. Keys are "namespace/name". The managed objects come
// from rc, listed again when it is older than listEvery. A write that fails because the view was
// stale is logged at V(1), not returned, and drops the view, so the next reconcile lists.
func (w *Writer) sync(ctx context.Context, rc *reportCache, want map[string]client.Object, list func(context.Context) ([]client.Object, error)) error {
	if rc.objs == nil || w.now().Sub(rc.listedAt) >= listEvery {
		have, err := list(ctx)
		if err != nil {
			return err
		}
		rc.objs = make(map[string]client.Object, len(have))
		for _, o := range have {
			rc.objs[o.GetNamespace()+"/"+o.GetName()] = o
		}
		rc.listedAt = w.now()
	}
	log := logr.FromContextOrDiscard(ctx)
	var errs []error
	stale := false
	fail := func(verb, k string, err error) {
		if (verb == "create" && apierrors.IsAlreadyExists(err)) || (verb == "update" && (apierrors.IsConflict(err) || apierrors.IsNotFound(err))) {
			stale = true
			log.V(1).Info("a report changed since it was listed; the next reconcile lists again", "report", k, "action", verb,
				"error", err.Error())
			return
		}
		errs = append(errs, fmt.Errorf("%s %s: %w", verb, k, err))
	}
	for _, k := range slices.Sorted(maps.Keys(want)) {
		obj := want[k]
		cur, ok := rc.objs[k]
		switch {
		case !ok:
			if err := w.c.Create(ctx, obj); err != nil {
				fail("create", k, err)
				continue
			}
			rc.objs[k] = obj
		case cur.GetAnnotations()[AnnotationContentHash] != obj.GetAnnotations()[AnnotationContentHash]:
			obj.SetResourceVersion(cur.GetResourceVersion())
			if err := w.c.Update(ctx, obj); err != nil {
				fail("update", k, err)
				continue
			}
			rc.objs[k] = obj
		}
	}
	for _, k := range slices.Sorted(maps.Keys(rc.objs)) {
		if _, ok := want[k]; ok {
			continue
		}
		if err := w.c.Delete(ctx, rc.objs[k]); client.IgnoreNotFound(err) != nil {
			fail("delete", k, err)
			continue
		}
		delete(rc.objs, k)
	}
	if stale {
		rc.objs = nil
	}
	return errors.Join(errs...)
}

// policyReport mirrors rep as a wgpolicyk8s PolicyReport. v1alpha2 has no top-level source or
// configuration; the per-result shape is identical.
func policyReport(rep *orv1alpha1.Report) (*unstructured.Unstructured, error) {
	m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(rep)
	if err != nil {
		return nil, fmt.Errorf("convert Report %s/%s: %w", rep.Namespace, rep.Name, err)
	}
	delete(m, "source")
	delete(m, "configuration")
	u := &unstructured.Unstructured{Object: m}
	u.SetAPIVersion(wgGroupVersion)
	u.SetKind("PolicyReport")
	return u, nil
}
