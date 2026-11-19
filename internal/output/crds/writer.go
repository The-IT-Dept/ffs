// Package crds writes Finding and Vulnerability resources from the store and reconciles Exception
// resources into the store's rule cache (spec §6.8).
package crds

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/time/rate"
	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/the-it-dept/ffs/api/v1alpha1"
	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

// Labels and annotations on the resources the writer manages, and the reason of its cap Event.
const (
	LabelManagedBy          = "app.kubernetes.io/managed-by" // value "ffs"
	LabelPriority           = "ffs.theitdept.au/priority"
	AnnotationContentHash   = "ffs.theitdept.au/content-hash"
	AnnotationFingerprint   = "ffs.theitdept.au/fingerprint"
	ReasonFindingCapReached = "FindingCapReached"
)

const (
	managedByFFS   = "ffs"
	capAction      = "WriteResources"
	resyncInterval = 60 * time.Second
	writesPerSec   = 20
	writeBurst     = 20
)

// FindingCRsDropped is the number of open findings at or above crd.minPriority that the last Sync
// left out because of crd.maxFindings.
var FindingCRsDropped = prometheus.NewGauge(prometheus.GaugeOpts{
	Name: "ffs_finding_crs_dropped",
	Help: "Open findings at or above crd.minPriority not written as Finding resources because of crd.maxFindings.",
})

func init() { ctrlmetrics.Registry.MustRegister(FindingCRsDropped) }

// WriterStore is the part of the store the writer reads.
type WriterStore interface {
	ListFindings(ctx context.Context, f store.FindingFilter) ([]model.Finding, error)
	ListOwners(ctx context.Context) ([]model.Owner, error)
	Advisories(ctx context.Context, ids []string) (map[string]model.Advisory, error)
}

// WriterOptions configures a Writer.
type WriterOptions struct {
	Client    client.Client
	Store     WriterStore
	Config    config.Config
	Namespace string                  // ffs install namespace, which holds cluster-level Findings
	Self      *corev1.ObjectReference // ffs Deployment; nil → no cap Event
	Recorder  events.EventRecorder
	Changed   <-chan struct{}
}

// Writer keeps the Finding and Vulnerability resources in step with the open findings in the store.
type Writer struct {
	o       WriterOptions
	limiter *rate.Limiter

	mu          sync.Mutex // serialises Sync
	lastDropped int
}

// NewWriter returns a Writer. Add it to the manager as a leader-only Runnable.
func NewWriter(o WriterOptions) *Writer {
	return &Writer{o: o, limiter: rate.NewLimiter(writesPerSec, writeBurst)}
}

// NeedLeaderElection reports that only the leader writes resources.
func (w *Writer) NeedLeaderElection() bool { return true }

// Start runs Sync once, then on every Changed signal and every 60s, until ctx is done. Sync
// errors are logged, never returned.
func (w *Writer) Start(ctx context.Context) error {
	log := ctrllog.FromContext(ctx).WithName("crds")
	tick := time.NewTicker(resyncInterval)
	defer tick.Stop()
	for {
		if err := w.Sync(ctx); err != nil && ctx.Err() == nil {
			log.Error(err, "writing Finding and Vulnerability resources failed")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-w.o.Changed:
		case <-tick.C:
		}
	}
}

// desiredCR is a resource to write: metadata and status set, plus the content hash of its status.
type desiredCR struct {
	obj  client.Object
	hash string
}

// crKind is one resource kind the writer owns.
type crKind struct {
	name      string
	list      client.ObjectList
	setStatus func(dst, src client.Object)
}

// Sync writes one Finding per open finding at or above crd.minPriority, up to crd.maxFindings,
// and one Vulnerability per advisory with a Finding; it deletes every other resource it manages.
// Writes happen only when a status's content hash changed. A failed write is logged and Sync
// carries on; the failures are returned together.
func (w *Writer) Sync(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	minPriority, err := model.ParsePriority(w.o.Config.CRD.MinPriority)
	if err != nil {
		return fmt.Errorf("crds: crd.minPriority: %w", err)
	}
	open, err := w.o.Store.ListFindings(ctx, store.FindingFilter{States: []model.FindingState{model.StateOpen}})
	if err != nil {
		return fmt.Errorf("crds: list open findings: %w", err)
	}
	byAdvisory := map[string][]model.Finding{}
	for _, f := range open {
		byAdvisory[f.AdvisoryID] = append(byAdvisory[f.AdvisoryID], f)
	}
	advs, err := w.o.Store.Advisories(ctx, slices.Sorted(maps.Keys(byAdvisory)))
	if err != nil {
		return fmt.Errorf("crds: load advisories: %w", err)
	}
	ownerList, err := w.o.Store.ListOwners(ctx)
	if err != nil {
		return fmt.Errorf("crds: list owners: %w", err)
	}
	owners := make(map[string]model.Owner, len(ownerList))
	for _, o := range ownerList {
		owners[o.Ref.Key()] = o
	}

	keep, dropped := w.selectFindings(open, minPriority)
	w.reportCap(dropped)

	var findingCRs, vulnCRs []desiredCR
	vulnWritten := map[string]bool{} // advisory ids with a desired Vulnerability
	for _, f := range keep {
		st := findingStatus(w.o.Config.ClusterName, f, owners[f.Owner.Key()], advs[f.AdvisoryID])
		findingCRs = append(findingCRs, desiredCR{obj: &v1alpha1.Finding{
			ObjectMeta: metav1.ObjectMeta{Name: FindingName(f.Owner, f.AdvisoryID), Namespace: w.namespaceOf(f),
				Labels:      map[string]string{LabelManagedBy: managedByFFS, LabelPriority: st.Priority},
				Annotations: map[string]string{AnnotationFingerprint: f.Fingerprint}},
			Status: st,
		}, hash: findingHash(st)})

		if vulnWritten[f.AdvisoryID] {
			continue
		}
		vulnWritten[f.AdvisoryID] = true
		vst := vulnerabilityStatus(f.AdvisoryID, advs[f.AdvisoryID], byAdvisory[f.AdvisoryID])
		vulnCRs = append(vulnCRs, desiredCR{obj: &v1alpha1.Vulnerability{
			ObjectMeta: metav1.ObjectMeta{Name: VulnerabilityName(f.AdvisoryID),
				Labels: map[string]string{LabelManagedBy: managedByFFS, LabelPriority: vst.HighestPriority}},
			Status: vst,
		}, hash: contentHash(vst)})
	}

	return errors.Join(
		w.apply(ctx, crKind{name: "Finding", list: &v1alpha1.FindingList{}, setStatus: func(dst, src client.Object) {
			dst.(*v1alpha1.Finding).Status = *src.(*v1alpha1.Finding).Status.DeepCopy()
		}}, findingCRs),
		w.apply(ctx, crKind{name: "Vulnerability", list: &v1alpha1.VulnerabilityList{}, setStatus: func(dst, src client.Object) {
			dst.(*v1alpha1.Vulnerability).Status = *src.(*v1alpha1.Vulnerability).Status.DeepCopy()
		}}, vulnCRs),
	)
}

// selectFindings returns the open findings to write as resources, highest priority first, and how
// many eligible findings the cap left out. Findings at or above minPriority are ranked by
// priority, then earliest matched, then fingerprint. When two findings share a resource name (one owner running
// two affected repositories), the higher-ranked one is written; the other stays in the API.
func (w *Writer) selectFindings(open []model.Finding, minPriority model.Priority) (keep []model.Finding, dropped int) {
	var eligible []model.Finding
	for _, f := range open {
		if f.Priority >= minPriority {
			eligible = append(eligible, f)
		}
	}
	slices.SortFunc(eligible, func(a, b model.Finding) int {
		return cmp.Or(cmp.Compare(b.Priority, a.Priority), a.Matched.Compare(b.Matched), cmp.Compare(a.Fingerprint, b.Fingerprint))
	})
	seen := map[string]bool{}
	eligible = slices.DeleteFunc(eligible, func(f model.Finding) bool {
		k := w.namespaceOf(f) + "/" + FindingName(f.Owner, f.AdvisoryID)
		if seen[k] {
			return true
		}
		seen[k] = true
		return false
	})
	keep = eligible[:min(len(eligible), max(w.o.Config.CRD.MaxFindings, 0))]
	return keep, len(eligible) - len(keep)
}

// reportCap publishes the dropped count, with a Warning Event on the ffs Deployment whenever a
// non-zero count changes.
func (w *Writer) reportCap(dropped int) {
	FindingCRsDropped.Set(float64(dropped))
	if dropped > 0 && dropped != w.lastDropped && w.o.Self != nil && w.o.Recorder != nil {
		w.o.Recorder.Eventf(w.o.Self, nil, corev1.EventTypeWarning, ReasonFindingCapReached, capAction,
			"Finding resources are capped at %d (crd.maxFindings); %d lower-priority findings are not written as resources and remain available in the API.",
			w.o.Config.CRD.MaxFindings, dropped)
	}
	w.lastDropped = dropped
}

// namespaceOf is the namespace of a finding's resource: the owner's, or the ffs namespace for
// cluster-level owners.
func (w *Writer) namespaceOf(f model.Finding) string {
	if f.Owner.Namespace == "" {
		return w.o.Namespace
	}
	return f.Owner.Namespace
}

// apply makes the managed resources of one kind match desired. Desired and existing resources are
// both keyed by objectKey here, so a cluster-scoped resource ("/name") matches its existing copy.
func (w *Writer) apply(ctx context.Context, k crKind, desiredCRs []desiredCR) error {
	log := ctrllog.FromContext(ctx).WithName("crds")
	desired := make(map[string]desiredCR, len(desiredCRs))
	for _, d := range desiredCRs {
		desired[objectKey(d.obj)] = d
	}
	if err := w.o.Client.List(ctx, k.list, client.MatchingLabels{LabelManagedBy: managedByFFS}); err != nil {
		return fmt.Errorf("crds: list %s resources: %w", k.name, err)
	}
	items, err := apimeta.ExtractList(k.list)
	if err != nil {
		return fmt.Errorf("crds: read %s list: %w", k.name, err)
	}
	var errs []error
	fail := func(verb, key string, err error) {
		if err == nil {
			return
		}
		log.Error(err, "writing a resource failed", "kind", k.name, "resource", key, "action", verb)
		errs = append(errs, fmt.Errorf("crds: %s %s %s: %w", verb, k.name, key, err))
	}
	existing := map[string]bool{}
	for _, item := range items {
		obj, ok := item.(client.Object)
		if !ok {
			continue
		}
		key := objectKey(obj)
		existing[key] = true
		d, ok := desired[key]
		switch {
		case !ok:
			fail("delete", key, w.write(ctx, func() error { return client.IgnoreNotFound(w.o.Client.Delete(ctx, obj)) }))
		case obj.GetAnnotations()[AnnotationContentHash] != d.hash:
			k.setStatus(obj, d.obj)
			fail("update", key, w.writeStatus(ctx, obj, d))
		}
	}
	for _, key := range slices.Sorted(maps.Keys(desired)) {
		if existing[key] {
			continue
		}
		d := desired[key]
		obj, _ := d.obj.DeepCopyObject().(client.Object) // a deep copy keeps the concrete type
		if err := w.write(ctx, func() error { return w.o.Client.Create(ctx, obj) }); err != nil {
			fail("create", key, err)
			continue
		}
		k.setStatus(obj, d.obj) // Create drops status: the status subresource is written separately
		fail("create", key, w.writeStatus(ctx, obj, d))
	}
	return errors.Join(errs...)
}

// writeStatus writes obj's status, then patches the labels and annotations of d, content hash
// included. The hash goes last, so a failed status write is retried on the next Sync.
func (w *Writer) writeStatus(ctx context.Context, obj client.Object, d desiredCR) error {
	if err := w.write(ctx, func() error { return w.o.Client.Status().Update(ctx, obj) }); err != nil {
		return err
	}
	annotations := maps.Clone(d.obj.GetAnnotations())
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations[AnnotationContentHash] = d.hash
	patch, err := json.Marshal(map[string]any{"metadata": map[string]any{
		"labels": d.obj.GetLabels(), "annotations": annotations}})
	if err != nil {
		return err
	}
	return w.write(ctx, func() error { return w.o.Client.Patch(ctx, obj, client.RawPatch(types.MergePatchType, patch)) })
}

// write runs one API write under the writer's rate limit.
func (w *Writer) write(ctx context.Context, fn func() error) error {
	if err := w.limiter.Wait(ctx); err != nil {
		return err
	}
	return fn()
}

// objectKey identifies a resource as "namespace/name" ("/name" when cluster-scoped).
func objectKey(o client.Object) string {
	return client.ObjectKeyFromObject(o).String()
}
