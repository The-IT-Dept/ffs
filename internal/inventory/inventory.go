package inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/discovery"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/sbom"
	"github.com/the-it-dept/ffs/internal/store"
)

// EngineHooks receives inventory changes; satisfied by *engine.Engine.
type EngineHooks interface {
	OnOwnersChanged(ctx context.Context, keys []string) error
	OnImageCatalogued(ctx context.Context, digest string) error
}

// Enqueuer queues SBOM acquisition; satisfied by *sbom.Acquirer.
type Enqueuer interface{ Enqueue(r sbom.Request) }

// Workload is what the context resolver sees of an owner.
type Workload struct {
	Ref            model.OwnerRef
	ServiceAccount string
	Pods           []*corev1.Pod           // live pods of the owner (transformed); empty when not running
	Template       *corev1.PodTemplateSpec // workload template; nil for bare pods
}

// ContextResolver derives an owner's exposure, privilege and service-account power.
type ContextResolver interface {
	Context(ctx context.Context, w *Workload) (model.WorkloadContext, error)
}

// Options configures an Inventory.
type Options struct {
	Client      client.Reader // manager cache
	Version     discovery.ServerVersionInterface
	Store       *store.Store
	Normalizer  *Normalizer
	Resolver    IndexResolver // template and image-volume tag resolution
	Context     ContextResolver
	Hooks       EngineHooks
	Acquirer    Enqueuer
	ClusterName string
	Debounce    time.Duration // default 2s
	TagTTL      time.Duration // default 6h
	VersionPoll time.Duration // default 10m
	// RetryPoll is how often the owners of images whose catalogFailed or unresolvable quarantine
	// has ended are flushed again, so those images are retried; default 1h.
	RetryPoll time.Duration
	Now       func() time.Time
}

const (
	clusterKey = "cluster"
	// reportKey is a batch key with no object behind it: it retries reporting the owners a failed
	// OnOwnersChanged left unreported.
	reportKey = "report"
	// maxRetryBackoff caps the backoff of a key whose flush keeps failing.
	maxRetryBackoff = 5 * time.Minute
)

// Inventory watches pods, workloads and nodes and keeps the stored owners, their images and the
// synthetic cluster-level owners up to date.
type Inventory struct {
	o      Options
	batch  *batcher
	retry  *retrier    // backs off keys whose flush failed
	cache  cache.Cache // set by Register
	access *accessCache
	synced atomic.Bool

	// Only Flush, which holds flushMu, touches these.
	flushMu      sync.Mutex
	podOwner     map[string]model.OwnerRef      // pod key → owner
	ownerPods    map[string]map[string]struct{} // owner key → pod keys
	enqueued     map[string]bool                // pending digests this process has handed to the acquirer
	catalogRetry map[string]bool                // synthetic digests whose OnImageCatalogued failed
	unreported   map[string]bool                // owner keys whose OnOwnersChanged failed

	mu             sync.Mutex
	known          map[string]bool // stored workload owner keys
	templateBacked map[string]bool // owners resolved from their template, re-resolved every TagTTL
	gitVersion     string          // last control-plane gitVersion from Version
}

// New returns an Inventory; Register and the manager start it.
func New(o Options) *Inventory {
	if o.Debounce <= 0 {
		o.Debounce = 2 * time.Second
	}
	if o.TagTTL <= 0 {
		o.TagTTL = 6 * time.Hour
	}
	if o.VersionPoll <= 0 {
		o.VersionPoll = 10 * time.Minute
	}
	if o.RetryPoll <= 0 {
		o.RetryPoll = time.Hour
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	inv := &Inventory{o: o, access: newAccessCache(o.TagTTL), podOwner: map[string]model.OwnerRef{}, ownerPods: map[string]map[string]struct{}{},
		enqueued: map[string]bool{}, catalogRetry: map[string]bool{}, unreported: map[string]bool{},
		known: map[string]bool{}, templateBacked: map[string]bool{}}
	inv.batch = newBatcher(o.Debounce, func(ctx context.Context, keys []string) {
		if err := inv.Flush(ctx, keys); err != nil {
			logf.FromContext(ctx).WithName("inventory").Error(err, "inventory flush failed")
		}
	})
	inv.retry = newRetrier(o.Debounce, maxRetryBackoff, inv.batch.Add)
	return inv
}

func (inv *Inventory) now() time.Time { return inv.o.Now() }

// Register adds event handlers to the manager's informers. Each event queues the object key;
// nodes and the kube-system/kube-proxy DaemonSet also queue "cluster".
func (inv *Inventory) Register(ctx context.Context, mgr manager.Manager) error {
	return inv.register(ctx, mgr.GetCache())
}

func (inv *Inventory) register(ctx context.Context, c cache.Cache) error {
	inv.cache = c
	rs := &metav1.PartialObjectMetadata{}
	rs.SetGroupVersionKind(appsv1.SchemeGroupVersion.WithKind("ReplicaSet"))
	for _, w := range []struct {
		obj  client.Object
		kind string
	}{
		{&corev1.Pod{}, "Pod"}, {&appsv1.Deployment{}, "Deployment"}, {&appsv1.StatefulSet{}, "StatefulSet"},
		{&appsv1.DaemonSet{}, "DaemonSet"}, {&batchv1.Job{}, "Job"}, {&batchv1.CronJob{}, "CronJob"}, {rs, "ReplicaSet"},
	} {
		if err := inv.addHandler(ctx, w.obj, inv.objectHandler(w.kind)); err != nil {
			return fmt.Errorf("inventory: %s informer: %w", w.kind, err)
		}
	}
	if err := inv.addHandler(ctx, &corev1.Node{}, inv.nodeHandler()); err != nil {
		return fmt.Errorf("inventory: Node informer: %w", err)
	}
	return nil
}

func (inv *Inventory) addHandler(ctx context.Context, obj client.Object, h toolscache.ResourceEventHandler) error {
	inf, err := inv.cache.GetInformer(ctx, obj)
	if err != nil {
		return err
	}
	_, err = inf.AddEventHandler(h)
	return err
}

func (inv *Inventory) objectHandler(kind string) toolscache.ResourceEventHandler {
	add := func(obj any) {
		if t, ok := obj.(toolscache.DeletedFinalStateUnknown); ok {
			obj = t.Obj
		}
		o, ok := obj.(metav1.Object)
		if !ok {
			return
		}
		inv.batch.Add(ownerKey(kind, o.GetNamespace(), o.GetName()))
		if kind == "DaemonSet" && o.GetNamespace() == "kube-system" && o.GetName() == "kube-proxy" {
			inv.batch.Add(clusterKey)
		}
	}
	return toolscache.ResourceEventHandlerFuncs{AddFunc: add, UpdateFunc: func(_, n any) { add(n) }, DeleteFunc: add}
}

// nodeHandler queues "cluster" when a node appears, goes, or changes a field the inventory keeps.
func (inv *Inventory) nodeHandler() toolscache.ResourceEventHandler {
	changed := func(any) { inv.batch.Add(clusterKey) }
	return toolscache.ResourceEventHandlerFuncs{
		AddFunc: changed,
		UpdateFunc: func(o, n any) {
			on, ok1 := o.(*corev1.Node)
			nn, ok2 := n.(*corev1.Node)
			if !ok1 || !ok2 || nodeModel(on, time.Time{}) != nodeModel(nn, time.Time{}) {
				inv.batch.Add(clusterKey)
			}
		},
		DeleteFunc: changed,
	}
}

// NeedLeaderElection makes the inventory run on the leader only.
func (inv *Inventory) NeedLeaderElection() bool { return true }

// Start waits for the caches, runs SyncAll until it succeeds (backing off up to maxRetryBackoff),
// then flushes batches. Every TagTTL it re-resolves template-backed owners; every VersionPoll it
// re-reads the control-plane version; every RetryPoll it flushes the owners of images whose
// quarantine has ended, which hands those images back to the acquirer or the normaliser.
func (inv *Inventory) Start(ctx context.Context) error {
	if inv.cache != nil && !inv.cache.WaitForCacheSync(ctx) {
		if ctx.Err() != nil {
			return nil
		}
		return errors.New("inventory: informer caches did not sync")
	}
	defer inv.retry.stop()
	for delay := inv.o.Debounce; ; delay = min(2*delay, maxRetryBackoff) {
		err := inv.SyncAll(ctx)
		if err == nil {
			break
		}
		logf.FromContext(ctx).WithName("inventory").Error(err, "initial inventory sync failed; retrying", "retryIn", delay)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(delay):
		}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		inv.batch.Run(ctx)
	}()
	defer func() { <-done }()
	tags := time.NewTicker(inv.o.TagTTL)
	defer tags.Stop()
	versions := time.NewTicker(inv.o.VersionPoll)
	defer versions.Stop()
	retries := time.NewTicker(inv.o.RetryPoll)
	defer retries.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-retries.C:
			keys, err := inv.o.Store.OwnersOfExpiredQuarantine(ctx, inv.now())
			if err != nil {
				logf.FromContext(ctx).WithName("inventory").Error(err, "listing owners of images due a retry")
				continue
			}
			inv.batch.Add(keys...)
		case <-tags.C:
			inv.mu.Lock()
			keys := sortedKeys(inv.templateBacked)
			inv.mu.Unlock()
			inv.batch.Add(keys...)
		case <-versions.C:
			inv.refreshVersion(ctx)
			inv.batch.Add(clusterKey)
		}
	}
}

// Synced reports whether a SyncAll has completed. SyncAll sets it (so a direct SyncAll counts);
// Start runs SyncAll before anything else, so after Start it means the first SyncAll completed.
func (inv *Inventory) Synced() bool { return inv.synced.Load() }

// MarkNamespace queues every known owner in ns. With ns "" it queues every known owner plus
// "cluster", which rebuilds the synthetic Cluster and ContainerRuntime owners.
func (inv *Inventory) MarkNamespace(ns string) {
	inv.mu.Lock()
	var keys []string
	if ns == "" {
		keys = append(keys, clusterKey)
	}
	for k := range inv.known {
		if _, kns, _, _ := splitKey(k); ns == "" || kns == ns {
			keys = append(keys, k)
		}
	}
	inv.mu.Unlock()
	inv.batch.Add(keys...)
}

// SyncAll flushes every pod, every workload, "cluster", and every stored workload owner (so owners
// deleted while ffs was down are removed).
func (inv *Inventory) SyncAll(ctx context.Context) error {
	inv.refreshVersion(ctx)
	keys := map[string]bool{clusterKey: true}
	for _, l := range []struct {
		kind string
		list client.ObjectList
	}{
		{"Pod", &corev1.PodList{}}, {"Deployment", &appsv1.DeploymentList{}}, {"StatefulSet", &appsv1.StatefulSetList{}},
		{"DaemonSet", &appsv1.DaemonSetList{}}, {"Job", &batchv1.JobList{}}, {"CronJob", &batchv1.CronJobList{}},
	} {
		if err := inv.o.Client.List(ctx, l.list); err != nil {
			return fmt.Errorf("inventory: list %s: %w", l.kind, err)
		}
		if err := apimeta.EachListItem(l.list, func(obj runtime.Object) error {
			o, err := apimeta.Accessor(obj)
			if err == nil {
				keys[ownerKey(l.kind, o.GetNamespace(), o.GetName())] = true
			}
			return err
		}); err != nil {
			return err
		}
	}
	owners, err := inv.o.Store.ListOwners(ctx)
	if err != nil {
		return err
	}
	for _, o := range owners {
		if !o.Ref.ClusterLevel() {
			keys[o.Ref.Key()] = true
		}
	}
	if err := inv.Flush(ctx, sortedKeys(keys)); err != nil {
		return err
	}
	inv.synced.Store(true)
	return nil
}

// flushState is the per-Flush view of the nodes and what the flush produced.
type flushState struct {
	now      time.Time
	nodes    map[string]model.Node
	nodeList []model.Node // sorted by name
	platform NodePlatform // majority Ready-node platform, for owners with no running pods
	reqs     []sbom.Request
	changed  []string
}

// Flush brings the owners behind keys up to date. Keys are object keys ("Pod/ns/name",
// "Deployment/ns/name", ...) or "cluster". A pod whose intermediate owner is not cached yet is
// retried in the next batch. Any other key that fails (a registry, store or context error) is
// retried with a per-key exponential backoff, logged once per backoff step, until it succeeds.
// Flush returns an error only when the batch as a whole could not be applied or reported; what it
// could not report is reported by a later Flush.
func (inv *Inventory) Flush(ctx context.Context, keys []string) error {
	inv.flushMu.Lock()
	defer inv.flushMu.Unlock()
	f, err := inv.newFlush(ctx)
	if err != nil {
		inv.batch.Add(keys...)
		return err
	}
	log := logf.FromContext(ctx).WithName("inventory")
	done := map[string]bool{}    // every key this flush processed
	failed := map[string]error{} // keys retried with backoff
	pending := map[string]bool{} // keys whose owner is not cached yet, retried in the next batch
	fail := func(key string, err error) {
		if errors.Is(err, errOwnerPending) {
			pending[key] = true
		} else {
			failed[key] = err
		}
	}

	dirty := map[string]bool{}
	cluster := false
	for _, key := range keys {
		done[key] = true
		kind, ns, name, ok := splitKey(key)
		switch {
		case key == reportKey:
			// report below retries the unreported owners.
		case key == clusterKey || model.ClusterLevelKey(key):
			cluster = true
		case !ok:
			log.Info("ignoring malformed inventory key", "key", key)
		case kind == "Pod":
			if err := inv.flushPod(ctx, key, ns, name, dirty); err != nil {
				fail(key, err)
			}
		default:
			owner, err := inv.workloadOwner(ctx, kind, ns, name)
			if err != nil {
				fail(key, err)
				continue
			}
			dirty[owner] = true
		}
	}
	if cluster {
		done[clusterKey] = true
		if err := inv.flushCluster(ctx, f); err != nil {
			fail(clusterKey, err)
		}
	}
	for _, key := range sortedKeys(dirty) {
		done[key] = true
		if err := inv.flushOwner(ctx, f, key); err != nil {
			fail(key, err)
		}
	}
	for _, key := range sortedKeys(done) {
		switch {
		case pending[key]:
		case failed[key] != nil:
			if attempt, delay, ok := inv.retry.fail(key); ok {
				log.Error(failed[key], "inventory update failed; backing off", "key", key, "attempt", attempt, "retryIn", delay)
			}
		case key != reportKey:
			inv.retry.ok(key)
		}
	}
	inv.batch.Add(sortedKeys(pending)...)
	return inv.report(ctx, f)
}

func (inv *Inventory) newFlush(ctx context.Context) (*flushState, error) {
	var list corev1.NodeList
	if err := inv.o.Client.List(ctx, &list); err != nil {
		return nil, fmt.Errorf("inventory: list nodes: %w", err)
	}
	f := &flushState{now: inv.now(), nodes: map[string]model.Node{}}
	for i := range list.Items {
		n := nodeModel(&list.Items[i], f.now)
		f.nodes[n.Name] = n
		f.nodeList = append(f.nodeList, n)
	}
	sort.Slice(f.nodeList, func(i, j int) bool { return f.nodeList[i].Name < f.nodeList[j].Name })
	f.platform = majorityPlatform(f.nodeList)
	return f, nil
}

// report hands collected SBOM requests to the acquirer and reports changed owners, including any
// a previous Flush failed to report. A failed report is retried with backoff through reportKey.
func (inv *Inventory) report(ctx context.Context, f *flushState) error {
	for _, r := range f.reqs {
		inv.o.Acquirer.Enqueue(r)
	}
	changed := map[string]bool{}
	for _, k := range f.changed {
		changed[k] = true
	}
	for k := range inv.unreported {
		changed[k] = true
	}
	if len(changed) == 0 {
		return nil
	}
	keys := sortedKeys(changed)
	if err := inv.o.Hooks.OnOwnersChanged(ctx, keys); err != nil {
		for _, k := range keys {
			inv.unreported[k] = true
		}
		inv.retry.fail(reportKey)
		return fmt.Errorf("inventory: report changed owners: %w", err)
	}
	clear(inv.unreported)
	inv.retry.ok(reportKey)
	return nil
}

// flushPod records which owner a pod belongs to and marks that owner (and any previous one) dirty.
func (inv *Inventory) flushPod(ctx context.Context, key, ns, name string, dirty map[string]bool) error {
	pod := &corev1.Pod{}
	found, err := inv.get(ctx, ns, name, pod)
	if err != nil {
		return err
	}
	old, had := inv.podOwner[key]
	if !found {
		if had {
			dirty[old.Key()] = true
			inv.unlinkPod(key)
		} else {
			dirty[key] = true // a pod not seen since start may be a stored bare-pod owner
		}
		return nil
	}
	ref, err := ownerOf(ctx, inv.o.Client, pod)
	if err != nil {
		return err
	}
	if had && old.Key() != ref.Key() {
		dirty[old.Key()] = true
		inv.unlinkPod(key)
	}
	inv.podOwner[key] = ref
	if inv.ownerPods[ref.Key()] == nil {
		inv.ownerPods[ref.Key()] = map[string]struct{}{}
	}
	inv.ownerPods[ref.Key()][key] = struct{}{}
	dirty[ref.Key()] = true
	return nil
}

func (inv *Inventory) unlinkPod(key string) {
	owner := inv.podOwner[key].Key()
	delete(inv.podOwner, key)
	delete(inv.ownerPods[owner], key)
	if len(inv.ownerPods[owner]) == 0 {
		delete(inv.ownerPods, owner)
	}
}

// flushOwner recomputes one workload owner from its cached pods and workload object, stores it
// when it changed, and records its images.
func (inv *Inventory) flushOwner(ctx context.Context, f *flushState, key string) error {
	kind, ns, name, _ := splitKey(key)
	ref := model.OwnerRef{Kind: kind, Namespace: ns, Name: name}
	var pods []*corev1.Pod
	for _, pk := range sortedKeys(inv.ownerPods[key]) {
		_, pns, pname, _ := splitKey(pk)
		p := &corev1.Pod{}
		found, err := inv.get(ctx, pns, pname, p)
		if err != nil {
			return err
		}
		if found {
			pods = append(pods, p)
			if ref.UID == "" {
				ref.UID = inv.podOwner[pk].UID
			}
		}
	}
	w, err := inv.getWorkload(ctx, kind, ns, name)
	if err != nil {
		return err
	}
	var tmpl *corev1.PodTemplateSpec
	if w != nil {
		ref.UID, tmpl = string(w.meta.GetUID()), w.tmpl
	}
	if len(pods) == 0 && tmpl == nil {
		return inv.deleteOwner(ctx, f, key)
	}
	stored, _, err := inv.o.Store.GetOwner(ctx, key)
	if err != nil {
		return err
	}
	prev := prevUsesOf(stored)

	var (
		uses    []use
		live    []*corev1.Pod // pods with a started container: the ones the uses come from
		pending []error       // containers whose image is still to resolve: stored as placeholders, retried
	)
	archs := map[string]bool{}
	for _, p := range pods {
		if !hasImageID(p) {
			continue
		}
		live = append(live, p)
		platform := f.platform
		if n, ok := f.nodes[p.Spec.NodeName]; ok {
			platform = NodePlatform{OS: n.OS, Arch: n.Arch}
		}
		us, err := inv.containerUses(ctx, p, platform, prev)
		if err != nil {
			if us == nil {
				return fmt.Errorf("pod %s/%s: %w", p.Namespace, p.Name, err)
			}
			pending = append(pending, fmt.Errorf("pod %s/%s: %w", p.Namespace, p.Name, err))
		}
		uses = append(uses, us...)
		archs[platform.Arch] = true
	}
	running := len(archs) > 0
	fromTemplate := !running && tmpl != nil
	if fromTemplate {
		if uses, err = inv.templateUses(ctx, tmpl, ns, f.platform, prev); err != nil {
			if uses == nil {
				return err
			}
			pending = append(pending, err)
		}
		archs[f.platform.Arch] = true
	}
	for _, u := range uses {
		if err := inv.recordImage(ctx, f, u); err != nil {
			return err
		}
	}

	o := model.Owner{
		Ref:            ref,
		NotRunning:     !running && w != nil && w.idle,
		ServiceAccount: ownerServiceAccount(pods, tmpl),
		Containers:     containerList(uses),
		Arch:           sortedKeys(archs),
		PullSecrets:    ownerPullSecrets(pods, tmpl),
		UpdatedAt:      f.now,
	}
	switch {
	case w != nil:
		o.ManagedBy = ManagedByFrom(w.meta.GetLabels(), w.meta.GetAnnotations())
	case len(pods) > 0:
		o.ManagedBy = ManagedByFrom(pods[0].Labels, pods[0].Annotations)
	}
	// Workload.Pods holds only live pods, so it is empty whenever the owner is not running. A bare
	// pod that has not started yet has neither pods nor a template to describe, and no uses either.
	if inv.o.Context != nil && (len(live) > 0 || tmpl != nil) {
		wl := &Workload{Ref: ref, ServiceAccount: o.ServiceAccount, Pods: live, Template: tmpl}
		if o.Context, err = inv.o.Context.Context(ctx, wl); err != nil {
			return fmt.Errorf("workload context: %w", err)
		}
	}
	if err := inv.storeOwner(ctx, f, o); err != nil {
		return err
	}
	inv.mu.Lock()
	inv.known[key] = true
	if fromTemplate {
		inv.templateBacked[key] = true
	} else {
		delete(inv.templateBacked, key)
	}
	inv.mu.Unlock()
	// The owner is stored with every container it could resolve; the key is retried for the rest.
	return errors.Join(pending...)
}

func (inv *Inventory) deleteOwner(ctx context.Context, f *flushState, key string) error {
	inv.mu.Lock()
	delete(inv.known, key)
	delete(inv.templateBacked, key)
	inv.mu.Unlock()
	if _, ok, err := inv.o.Store.GetOwner(ctx, key); err != nil || !ok {
		return err
	}
	if err := inv.o.Store.DeleteOwner(ctx, key); err != nil {
		return err
	}
	f.changed = append(f.changed, key)
	return nil
}

// storeOwner upserts o when it differs from the stored owner, ignoring UpdatedAt.
func (inv *Inventory) storeOwner(ctx context.Context, f *flushState, o model.Owner) error {
	stored, ok, err := inv.o.Store.GetOwner(ctx, o.Ref.Key())
	if err != nil {
		return err
	}
	if ok && sameOwner(stored, o) {
		return nil
	}
	if err := inv.o.Store.UpsertOwner(ctx, o); err != nil {
		return err
	}
	f.changed = append(f.changed, o.Ref.Key())
	return nil
}

func sameOwner(a, b model.Owner) bool {
	a.UpdatedAt, b.UpdatedAt = time.Time{}, time.Time{}
	ja, errA := json.Marshal(a)
	jb, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(ja, jb)
}

// get reads obj from the client; found is false when it does not exist.
func (inv *Inventory) get(ctx context.Context, ns, name string, obj client.Object) (bool, error) {
	err := inv.o.Client.Get(ctx, client.ObjectKey{Namespace: ns, Name: name}, obj)
	if apierrors.IsNotFound(err) {
		return false, nil
	}
	return err == nil, err
}

func ownerKey(kind, ns, name string) string {
	return model.OwnerRef{Kind: kind, Namespace: ns, Name: name}.Key()
}

// splitKey splits "Kind/Namespace/Name"; Namespace may be empty.
func splitKey(key string) (kind, ns, name string, ok bool) {
	parts := strings.SplitN(key, "/", 3)
	if len(parts) != 3 || parts[0] == "" || parts[2] == "" {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}
