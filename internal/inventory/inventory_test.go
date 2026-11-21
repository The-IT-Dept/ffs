package inventory

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/registry"
	"github.com/the-it-dept/ffs/internal/sbom"
	"github.com/the-it-dept/ffs/internal/store"
)

const nginx = "docker.io/library/nginx"

var t0 = time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)

// countingResolver counts tag resolutions on top of the digest tests' fake resolver.
type countingResolver struct {
	*fakeResolver
	resolveTagCalls int
}

func (c *countingResolver) ResolveTag(ctx context.Context, repo, tag string, cs registry.CredSet) (string, error) {
	c.resolveTagCalls++
	return c.fakeResolver.ResolveTag(ctx, repo, tag, cs)
}

type fakeHooks struct {
	mu         sync.Mutex
	owners     [][]string
	catalogued []string
	ownersErr  error // returned by OnOwnersChanged, which then records nothing
}

func (h *fakeHooks) OnOwnersChanged(_ context.Context, keys []string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.ownersErr != nil {
		return h.ownersErr
	}
	h.owners = append(h.owners, append([]string(nil), keys...))
	return nil
}

func (h *fakeHooks) OnImageCatalogued(_ context.Context, digest string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.catalogued = append(h.catalogued, digest)
	return nil
}

// workloadCalls returns the OnOwnersChanged calls with the synthetic owner keys filtered out.
func (h *fakeHooks) workloadCalls() [][]string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out [][]string
	for _, call := range h.owners {
		var keys []string
		for _, k := range call {
			if !strings.HasPrefix(k, "Cluster/") && !strings.HasPrefix(k, "ContainerRuntime/") {
				keys = append(keys, k)
			}
		}
		if len(keys) > 0 {
			out = append(out, keys)
		}
	}
	return out
}

type fakeAcquirer struct {
	mu   sync.Mutex
	reqs []sbom.Request
}

func (a *fakeAcquirer) Enqueue(r sbom.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.reqs = append(a.reqs, r)
}

func (a *fakeAcquirer) digests() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for _, r := range a.reqs {
		out = append(out, r.Digest)
	}
	return out
}

type fakeContext struct{}

func (fakeContext) Context(context.Context, *Workload) (model.WorkloadContext, error) {
	return model.WorkloadContext{}, nil
}

// recordingContext records the last Workload it saw per owner key and fails the owners in err.
type recordingContext struct {
	mu   sync.Mutex
	seen map[string]*Workload
	err  map[string]error
}

func newRecordingContext() *recordingContext {
	return &recordingContext{seen: map[string]*Workload{}, err: map[string]error{}}
}

func (r *recordingContext) Context(_ context.Context, w *Workload) (model.WorkloadContext, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen[w.Ref.Key()] = w
	return model.WorkloadContext{}, r.err[w.Ref.Key()]
}

func (r *recordingContext) setErr(key string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.err[key] = err
}

// backoffOf reports a key's backoff attempt and whether a retry is scheduled.
func backoffOf(r *retrier, key string) (attempt int, scheduled bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if b := r.keys[key]; b != nil {
		return b.attempt, b.timer != nil
	}
	return 0, false
}

type fakeVersion struct{ gitVersion string }

func (v fakeVersion) ServerVersion() (*version.Info, error) {
	return &version.Info{GitVersion: v.gitVersion}, nil
}

type harness struct {
	inv   *Inventory
	st    *store.Store
	c     client.WithWatch
	res   *countingResolver
	hooks *fakeHooks
	acq   *fakeAcquirer
	now   time.Time
}

func newHarness(t *testing.T, objs ...client.Object) *harness {
	t.Helper()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "ffs.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	h := &harness{st: st, now: t0, hooks: &fakeHooks{}, acq: &fakeAcquirer{},
		res: &countingResolver{fakeResolver: &fakeResolver{tags: map[string]string{},
			platforms: map[string]registry.Manifest{}, configs: map[string]string{}}}}
	clock := func() time.Time { return h.now }
	h.c = fake.NewClientBuilder().WithObjects(objs...).Build()
	h.inv = New(Options{Client: h.c, Store: st, Normalizer: NewNormalizer(h.res, st, clock), Resolver: h.res,
		Context: fakeContext{}, Hooks: h.hooks, Acquirer: h.acq, ClusterName: "test", Now: clock})
	return h
}

func registryManifest(digest, index, platform string) registry.Manifest {
	return registry.Manifest{Digest: digest, IndexDigest: index, Platform: platform}
}

func ctrl(apiVersion, kind, name string) []metav1.OwnerReference {
	return []metav1.OwnerReference{{APIVersion: apiVersion, Kind: kind, Name: name, UID: types.UID(name + "-uid"),
		Controller: ptr.To(true)}}
}

func newNode(name, arch string) *corev1.Node {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name}, Status: corev1.NodeStatus{
		NodeInfo: corev1.NodeSystemInfo{OperatingSystem: "linux", Architecture: arch, KubeletVersion: "v1.35.2+k3s1",
			ContainerRuntimeVersion: "containerd://2.1.4-k3s1"},
		Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
	}}
}

func podSpec(image string, secrets ...string) corev1.PodSpec {
	s := corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: image}}}
	for _, n := range secrets {
		s.ImagePullSecrets = append(s.ImagePullSecrets, corev1.LocalObjectReference{Name: n})
	}
	return s
}

func newPod(name, nodeName string, owners []metav1.OwnerReference, image, imageID string, secrets ...string) *corev1.Pod {
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: name, UID: types.UID(name + "-uid"),
		OwnerReferences: owners}, Spec: podSpec(image, secrets...)}
	p.Spec.NodeName = nodeName
	p.Status.Phase = corev1.PodRunning
	p.Status.ContainerStatuses = []corev1.ContainerStatus{{Name: "app", Image: image, ImageID: imageID, Ready: true}}
	return p
}

func newDeployment(name string, replicas int32, image string, secrets ...string) *appsv1.Deployment {
	return &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: name, UID: types.UID(name + "-uid")},
		Spec: appsv1.DeploymentSpec{Replicas: ptr.To(replicas),
			Template: corev1.PodTemplateSpec{Spec: podSpec(image, secrets...)}}}
}

func (h *harness) owner(t *testing.T, key string) model.Owner {
	t.Helper()
	o, ok, err := h.st.GetOwner(ctx, key)
	require.NoError(t, err)
	require.True(t, ok, key)
	return o
}

func TestSyncAll_DeploymentViaReplicaSet(t *testing.T) {
	dep := newDeployment("web", 2, "nginx:1.27", "regcred")
	dep.Spec.Template.Spec.ServiceAccountName = "web"
	dep.Labels = map[string]string{"helm.toolkit.fluxcd.io/name": "web", "helm.toolkit.fluxcd.io/namespace": "flux-system"}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web-5d9",
		OwnerReferences: ctrl("apps/v1", "Deployment", "web")}}
	podX := newPod("web-x", "n1", ctrl("apps/v1", "ReplicaSet", "web-5d9"), "nginx:1.27", nginx+"@"+idx, "regcred")
	podY := newPod("web-y", "n2", ctrl("apps/v1", "ReplicaSet", "web-5d9"), "nginx:1.27", nginx+"@"+idx, "regcred", "extra")
	podX.Spec.ServiceAccountName, podY.Spec.ServiceAccountName = "web", "web"
	// web-y is crash-looping: it still counts as running.
	podY.Status.ContainerStatuses[0].Ready = false
	podY.Status.ContainerStatuses[0].RestartCount = 40
	podY.Status.ContainerStatuses[0].State = corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}}

	h := newHarness(t, newNode("n1", "amd64"), newNode("n2", "arm64"), dep, rs, podX, podY)
	h.res.platforms[idx+"|linux/amd64"] = registryManifest(mA, idx, "linux/amd64")
	h.res.platforms[idx+"|linux/arm64"] = registryManifest(mB, idx, "linux/arm64")

	require.False(t, h.inv.Synced())
	require.NoError(t, h.inv.SyncAll(ctx))
	require.True(t, h.inv.Synced())

	o := h.owner(t, "Deployment/apps/web")
	require.Equal(t, model.OwnerRef{Kind: "Deployment", Namespace: "apps", Name: "web", UID: "web-uid", APIVersion: "apps/v1"}, o.Ref)
	require.Equal(t, []string{"amd64", "arm64"}, o.Arch)
	require.Equal(t, &model.ManagedBy{Tool: "flux-helmrelease", Name: "web", Namespace: "flux-system"}, o.ManagedBy)
	require.False(t, o.NotRunning)
	require.Equal(t, "web", o.ServiceAccount)
	require.Equal(t, []string{"extra", "regcred"}, o.PullSecrets)
	require.Equal(t, []model.ContainerUse{
		{Name: "app", Kind: model.ContainerRegular, ImageRef: "nginx:1.27", Repo: nginx, Digest: mA, Platform: "linux/amd64",
			RootUnlessImageUser: true},
		{Name: "app", Kind: model.ContainerRegular, ImageRef: "nginx:1.27", Repo: nginx, Digest: mB, Platform: "linux/arm64",
			RootUnlessImageUser: true},
	}, o.Containers)

	require.Equal(t, [][]string{{"Deployment/apps/web"}}, h.hooks.workloadCalls())
	require.ElementsMatch(t, []string{mA, mB}, h.acq.digests())
	require.Contains(t, h.acq.reqs, sbom.Request{Repo: nginx, Digest: mA, IndexDigest: idx, Platform: "linux/amd64",
		Creds: registry.CredSet{Namespace: "apps", ServiceAccount: "web", PullSecrets: []string{"regcred"}}})
	img, ok, err := h.st.GetImage(ctx, mA)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, model.ImagePending, img.Status)
	require.ElementsMatch(t, []string{"k8s:1.35.2", "runtime:containerd@2.1.4"}, h.hooks.catalogued)
	h.owner(t, "Cluster//test")
	h.owner(t, "ContainerRuntime//containerd")
	nodes, err := h.st.ListNodes(ctx)
	require.NoError(t, err)
	require.Len(t, nodes, 2)

	// Nothing changed: no hook call, no enqueue, no re-catalogue.
	calls, catalogued := len(h.hooks.owners), len(h.hooks.catalogued)
	h.now = t0.Add(time.Minute)
	require.NoError(t, h.inv.SyncAll(ctx))
	require.Len(t, h.hooks.owners, calls)
	require.Len(t, h.hooks.catalogued, catalogued)
	require.Len(t, h.acq.reqs, 2)

	// The image field is mutable: an in-place update with a new image ID changes the owner.
	idx2, mC := "sha256:"+strings.Repeat("2", 64), "sha256:"+strings.Repeat("e", 64)
	h.res.platforms[idx2+"|linux/amd64"] = registryManifest(mC, idx2, "linux/amd64")
	var p corev1.Pod
	require.NoError(t, h.c.Get(ctx, client.ObjectKey{Namespace: "apps", Name: "web-x"}, &p))
	p.Status.ContainerStatuses[0].ImageID = nginx + "@" + idx2
	require.NoError(t, h.c.Status().Update(ctx, &p))
	require.NoError(t, h.inv.Flush(ctx, []string{"Pod/apps/web-x"}))
	require.Equal(t, []string{mB, mC}, digestsOf(h.owner(t, "Deployment/apps/web").Containers))
	calls2 := h.hooks.workloadCalls()
	require.Equal(t, []string{"Deployment/apps/web"}, calls2[len(calls2)-1])
	require.Equal(t, []string{mA, mB, mC}, h.acq.digests())

	// A Succeeded Job pod still present counts as running.
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "backup", UID: "backup-uid"},
		Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: podSpec("nginx:1.27")}}}
	jp := newPod("backup-abc", "n1", ctrl("batch/v1", "Job", "backup"), "nginx:1.27", nginx+"@"+idx)
	jp.Status.Phase = corev1.PodSucceeded
	jp.Status.ContainerStatuses[0].State = corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{ExitCode: 0}}
	require.NoError(t, h.c.Create(ctx, job))
	require.NoError(t, h.c.Create(ctx, jp))
	require.NoError(t, h.inv.Flush(ctx, []string{"Job/apps/backup", "Pod/apps/backup-abc"}))
	jo := h.owner(t, "Job/apps/backup")
	require.False(t, jo.NotRunning)
	require.Equal(t, []string{mA}, digestsOf(jo.Containers))
}

func TestSyncAll_NotRunningResolvedByTagEvery6h(t *testing.T) {
	cron := &batchv1.CronJob{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "nightly"},
		Spec: batchv1.CronJobSpec{Schedule: "0 3 * * *", JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{Spec: podSpec("nginx:1.27")}}}}}
	paused := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "paused"},
		Spec: batchv1.JobSpec{Suspend: ptr.To(true), Template: corev1.PodTemplateSpec{Spec: podSpec("nginx:1.27")}}}
	backup := &batchv1.CronJob{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "backup", UID: "backup-uid"},
		Spec: batchv1.CronJobSpec{Schedule: "@hourly", JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{Spec: podSpec("nginx:1.27")}}}}}
	backupJob := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "backup-29",
		OwnerReferences: ctrl("batch/v1", "CronJob", "backup")},
		Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: podSpec("nginx:1.27")}}}
	backupPod := newPod("backup-29-abc", "n1", ctrl("batch/v1", "Job", "backup-29"), "nginx:1.27", nginx+"@"+idx)

	h := newHarness(t, newNode("n1", "amd64"), newNode("n2", "amd64"), newNode("n3", "arm64"),
		newDeployment("idle", 0, "nginx:1.27"), cron, paused, backup, backupJob, backupPod)
	h.res.tags[nginx+":1.27"] = idx
	h.res.platforms[idx+"|linux/amd64"] = registryManifest(mA, idx, "linux/amd64")

	require.NoError(t, h.inv.SyncAll(ctx))
	o := h.owner(t, "Deployment/apps/idle")
	require.True(t, o.NotRunning)
	require.Equal(t, []string{"amd64"}, o.Arch)
	require.Equal(t, []model.ContainerUse{{Name: "app", Kind: model.ContainerRegular, ImageRef: "nginx:1.27", Repo: nginx,
		Digest: mA, Platform: "linux/amd64", RootUnlessImageUser: true}}, o.Containers)
	d, _, ok, err := h.st.TagDigest(ctx, nginx, "1.27")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, idx, d)
	require.Equal(t, 1, h.res.resolveTagCalls)

	require.True(t, h.owner(t, "CronJob/apps/nightly").NotRunning)
	require.True(t, h.owner(t, "Job/apps/paused").NotRunning)
	running := h.owner(t, "CronJob/apps/backup")
	require.False(t, running.NotRunning)
	require.Equal(t, []string{mA}, digestsOf(running.Containers))
	_, ok, err = h.st.GetOwner(ctx, "Job/apps/backup-29")
	require.NoError(t, err)
	require.False(t, ok)

	h.now = t0.Add(time.Hour)
	require.NoError(t, h.inv.SyncAll(ctx))
	require.Equal(t, 1, h.res.resolveTagCalls)

	h.now = t0.Add(6*time.Hour + time.Second)
	require.NoError(t, h.inv.SyncAll(ctx))
	require.Equal(t, 2, h.res.resolveTagCalls)
}

func TestSyncAll_UnchangedOwnerNotReported(t *testing.T) {
	proxy := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "kube-proxy"},
		Spec: appsv1.DaemonSetSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{
			{Name: "kube-proxy", Image: "registry.k8s.io/kube-proxy:v1.35.2"}}}}}}
	h := newHarness(t, newNode("n1", "amd64"), newDeployment("web", 1, "nginx:1.27"), proxy,
		newPod("web", "n1", nil, "nginx:1.27", nginx+"@"+idx))
	h.inv.o.Version = fakeVersion{gitVersion: "v1.35.2+k3s1"}
	h.res.tags[nginx+":1.27"] = idx
	h.res.platforms[idx+"|linux/amd64"] = registryManifest(mA, idx, "linux/amd64")
	h.res.tags["registry.k8s.io/kube-proxy:v1.35.2"] = mB
	h.res.platforms[mB+"|linux/amd64"] = registryManifest(mB, "", "linux/amd64")

	require.NoError(t, h.inv.SyncAll(ctx))
	require.NotEmpty(t, h.hooks.owners)
	ci, ok, err := h.st.GetClusterInfo(ctx)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, model.ClusterInfo{Name: "test", GitVersion: "v1.35.2+k3s1", Version: "1.35.2", Distribution: "k3s",
		KubeProxyVersion: "1.35.2", UpdatedAt: t0}, ci)
	pkgs, err := h.st.PackagesForImage(ctx, "k8s:1.35.2")
	require.NoError(t, err)
	require.Equal(t, "control plane; kubelet on 1 node; kube-proxy", pkgs[0].Path)

	calls, catalogued := len(h.hooks.owners), len(h.hooks.catalogued)
	h.now = t0.Add(time.Hour)
	require.NoError(t, h.inv.SyncAll(ctx))
	require.Len(t, h.hooks.owners, calls)
	require.Len(t, h.hooks.catalogued, catalogued)

	// A node joining moves the node counts: the synthetic packages are re-put and re-catalogued,
	// while the synthetic owners themselves are unchanged.
	require.NoError(t, h.c.Create(ctx, newNode("n2", "amd64")))
	require.NoError(t, h.inv.Flush(ctx, []string{"cluster"}))
	pkgs, err = h.st.PackagesForImage(ctx, "k8s:1.35.2")
	require.NoError(t, err)
	require.Equal(t, "control plane; kubelet on 2 nodes; kube-proxy", pkgs[0].Path)
	require.Equal(t, []string{"k8s:1.35.2", "runtime:containerd@2.1.4"}, h.hooks.catalogued[catalogued:])
	require.Len(t, h.hooks.owners, calls)
}

func TestSyncAll_DeletedOwnerRemoved(t *testing.T) {
	h := newHarness(t)
	for _, o := range []model.Owner{
		{Ref: model.OwnerRef{Kind: "Deployment", Namespace: "apps", Name: "old"}},
		{Ref: model.OwnerRef{Kind: "Pod", Namespace: "apps", Name: "gone"}},
		{Ref: model.OwnerRef{Kind: "Cluster", Name: "test"}, Containers: []model.ContainerUse{{Name: "kubernetes", Digest: "k8s:1.35.2"}}},
		{Ref: model.OwnerRef{Kind: "ContainerRuntime", Name: "containerd"}},
	} {
		require.NoError(t, h.st.UpsertOwner(ctx, o))
	}

	require.NoError(t, h.inv.SyncAll(ctx))
	for _, key := range []string{"Deployment/apps/old", "Pod/apps/gone"} {
		_, ok, err := h.st.GetOwner(ctx, key)
		require.NoError(t, err)
		require.False(t, ok, key)
	}
	require.Equal(t, [][]string{{"Deployment/apps/old", "Pod/apps/gone"}}, h.hooks.owners)
	h.owner(t, "Cluster//test")
	h.owner(t, "ContainerRuntime//containerd")
}

func TestSyncAll_UnresolvableNeverEnqueued(t *testing.T) {
	h := newHarness(t, newNode("n1", "amd64"), newPod("side", "n1", nil, "docker.io/library/app:1.0", cfg))

	require.NoError(t, h.inv.SyncAll(ctx))
	img, ok, err := h.st.GetImage(ctx, cfg)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, model.ImageUnresolvable, img.Status)
	require.NotEmpty(t, img.StatusReason)
	require.Empty(t, h.acq.reqs)
	o := h.owner(t, "Pod/apps/side")
	require.Len(t, o.Containers, 1)
	require.Equal(t, cfg, o.Containers[0].Digest)
}

func TestBatcher_FlushesAfterDebounce(t *testing.T) {
	type batch struct {
		keys []string
		at   time.Time
	}
	got := make(chan batch, 4)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	b := newBatcher(50*time.Millisecond, func(_ context.Context, keys []string) {
		got <- batch{keys, time.Now()}
		if calls.Add(1) == 2 {
			close(entered)
			<-release
		}
	})
	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go b.Run(runCtx)
	next := func() batch {
		t.Helper()
		select {
		case bt := <-got:
			return bt
		case <-time.After(5 * time.Second):
			t.Fatal("no flush")
			return batch{}
		}
	}

	start := time.Now()
	b.Add("Pod/a/1")
	time.Sleep(30 * time.Millisecond)
	b.Add("Pod/a/2", "Pod/a/1")
	first := next()
	require.Equal(t, []string{"Pod/a/1", "Pod/a/2"}, first.keys)
	require.GreaterOrEqual(t, first.at.Sub(start), 50*time.Millisecond)
	select {
	case bt := <-got:
		t.Fatalf("unexpected second flush %v", bt.keys)
	case <-time.After(100 * time.Millisecond):
	}

	b.Add("Pod/a/3")
	<-entered
	b.Add("Pod/a/4")
	require.Equal(t, []string{"Pod/a/3"}, next().keys)
	close(release)
	require.Equal(t, []string{"Pod/a/4"}, next().keys)
}

func TestSyncAll_ContextSeesLivePodsOnly(t *testing.T) {
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web-5d9",
		OwnerReferences: ctrl("apps/v1", "Deployment", "web")}}
	running := newPod("web-x", "n1", ctrl("apps/v1", "ReplicaSet", "web-5d9"), "nginx:1.27", nginx+"@"+idx)
	pulling := newPod("web-z", "n1", ctrl("apps/v1", "ReplicaSet", "web-5d9"), "nginx:1.27", "")
	cron := &batchv1.CronJob{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "nightly", UID: "nightly-uid"},
		Spec: batchv1.CronJobSpec{Schedule: "0 3 * * *", JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{Spec: podSpec("nginx:1.27")}}}}}
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "nightly-1",
		OwnerReferences: ctrl("batch/v1", "CronJob", "nightly")},
		Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: podSpec("nginx:1.27")}}}
	cronPod := newPod("nightly-1-abc", "n1", ctrl("batch/v1", "Job", "nightly-1"), "nginx:1.27", "")
	bare := newPod("lonely", "n1", nil, "nginx:1.27", "")

	h := newHarness(t, newNode("n1", "amd64"), newDeployment("web", 2, "nginx:1.27"), rs, running, pulling,
		cron, job, cronPod, bare)
	rc := newRecordingContext()
	h.inv.o.Context = rc
	h.res.tags[nginx+":1.27"] = idx
	h.res.platforms[idx+"|linux/amd64"] = registryManifest(mA, idx, "linux/amd64")
	require.NoError(t, h.inv.SyncAll(ctx))

	// A running owner's Workload holds its live pods only, not the one still pulling.
	web := rc.seen["Deployment/apps/web"]
	require.NotNil(t, web)
	require.Len(t, web.Pods, 1)
	require.Equal(t, "web-x", web.Pods[0].Name)
	require.NotNil(t, web.Template)

	// A not-running owner whose only pod is still pulling: Pods is empty, the template describes it.
	require.True(t, h.owner(t, "CronJob/apps/nightly").NotRunning)
	nightly := rc.seen["CronJob/apps/nightly"]
	require.NotNil(t, nightly)
	require.Empty(t, nightly.Pods)
	require.NotNil(t, nightly.Template)

	// A bare pod that has not started has nothing to describe: no context call and no containers.
	require.NotContains(t, rc.seen, "Pod/apps/lonely")
	require.Empty(t, h.owner(t, "Pod/apps/lonely").Containers)
}

func TestMarkNamespace(t *testing.T) {
	other := newDeployment("tools", 0, "nginx:1.27")
	other.Namespace = "ops"
	h := newHarness(t, newNode("n1", "amd64"), newDeployment("web", 0, "nginx:1.27"), other)
	h.res.tags[nginx+":1.27"] = idx
	h.res.platforms[idx+"|linux/amd64"] = registryManifest(mA, idx, "linux/amd64")
	require.NoError(t, h.inv.SyncAll(ctx))
	h.inv.batch.take()

	h.inv.MarkNamespace("ops")
	require.Equal(t, []string{"Deployment/ops/tools"}, h.inv.batch.take())
	// "" marks every owner, and "cluster" for the synthetic ones.
	h.inv.MarkNamespace("")
	require.Equal(t, []string{"Deployment/apps/web", "Deployment/ops/tools", "cluster"}, h.inv.batch.take())
}

func TestFlush_FailedKeyBacksOff(t *testing.T) {
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web-5d9",
		OwnerReferences: ctrl("apps/v1", "Deployment", "web")}}
	h := newHarness(t, newNode("n1", "amd64"), newDeployment("web", 1, "nginx:1.27"), rs,
		newPod("web-x", "n1", ctrl("apps/v1", "ReplicaSet", "web-5d9"), "nginx:1.27", nginx+"@"+idx),
		newPod("orphan", "n1", ctrl("apps/v1", "ReplicaSet", "gone-1"), "nginx:1.27", nginx+"@"+idx))
	h.res.platforms[idx+"|linux/amd64"] = registryManifest(mA, idx, "linux/amd64")
	rc := newRecordingContext()
	rc.setErr("Deployment/apps/web", errors.New("rbac lookup failed"))
	h.inv.o.Context = rc
	h.inv.retry.min = time.Hour // keep the scheduled retry from firing during the test
	t.Cleanup(h.inv.retry.stop)

	require.NoError(t, h.inv.SyncAll(ctx))
	_, ok, err := h.st.GetOwner(ctx, "Deployment/apps/web")
	require.NoError(t, err)
	require.False(t, ok)
	// Only the pod whose ReplicaSet is not cached yet goes to the next batch; the failed owner backs off.
	require.Equal(t, []string{"Pod/apps/orphan"}, h.inv.batch.take())
	attempt, scheduled := backoffOf(h.inv.retry, "Deployment/apps/web")
	require.Equal(t, 1, attempt)
	require.True(t, scheduled)
	attempt, _ = backoffOf(h.inv.retry, "Pod/apps/orphan")
	require.Zero(t, attempt)

	// An event-driven flush that fails again is absorbed by the scheduled retry.
	require.NoError(t, h.inv.Flush(ctx, []string{"Pod/apps/web-x"}))
	attempt, _ = backoffOf(h.inv.retry, "Deployment/apps/web")
	require.Equal(t, 1, attempt)
	require.Empty(t, h.inv.batch.take())

	// Success clears the backoff.
	rc.setErr("Deployment/apps/web", nil)
	require.NoError(t, h.inv.Flush(ctx, []string{"Deployment/apps/web"}))
	h.owner(t, "Deployment/apps/web")
	attempt, scheduled = backoffOf(h.inv.retry, "Deployment/apps/web")
	require.Zero(t, attempt)
	require.False(t, scheduled)
}

func TestFlush_ReportFailureBacksOff(t *testing.T) {
	h := newHarness(t, newNode("n1", "amd64"), newPod("solo", "n1", nil, "nginx:1.27", nginx+"@"+idx))
	h.res.platforms[idx+"|linux/amd64"] = registryManifest(mA, idx, "linux/amd64")
	h.hooks.ownersErr = errors.New("engine unavailable")
	h.inv.retry.min = time.Hour
	t.Cleanup(h.inv.retry.stop)

	require.Error(t, h.inv.SyncAll(ctx))
	require.False(t, h.inv.Synced())
	require.Empty(t, h.inv.batch.take(), "owners are not re-queued for the next batch")
	attempt, scheduled := backoffOf(h.inv.retry, reportKey)
	require.Equal(t, 1, attempt)
	require.True(t, scheduled)

	// The scheduled retry flushes reportKey, which reports what is still unreported.
	h.hooks.ownersErr = nil
	require.NoError(t, h.inv.Flush(ctx, []string{reportKey}))
	require.Equal(t, [][]string{{"Pod/apps/solo"}}, h.hooks.workloadCalls())
	attempt, _ = backoffOf(h.inv.retry, reportKey)
	require.Zero(t, attempt)
}

func TestRetrier_BacksOffPerKey(t *testing.T) {
	fired := make(chan string, 8)
	r := newRetrier(10*time.Millisecond, 40*time.Millisecond, func(keys ...string) {
		for _, k := range keys {
			fired <- k
		}
	})
	t.Cleanup(r.stop)
	next := func() string {
		t.Helper()
		select {
		case k := <-fired:
			return k
		case <-time.After(5 * time.Second):
			t.Fatal("no retry")
			return ""
		}
	}

	// Each failure doubles the wait, capped at max; a failure while a retry waits is absorbed.
	for i, want := range []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 40 * time.Millisecond,
		40 * time.Millisecond} {
		start := time.Now()
		attempt, delay, scheduled := r.fail("k")
		require.True(t, scheduled)
		require.Equal(t, i+1, attempt)
		require.Equal(t, want, delay)
		_, _, again := r.fail("k")
		require.False(t, again)
		require.Equal(t, "k", next())
		require.GreaterOrEqual(t, time.Since(start), want)
	}

	// Keys back off independently.
	attempt, delay, _ := r.fail("other")
	require.Equal(t, 1, attempt)
	require.Equal(t, 10*time.Millisecond, delay)
	require.Equal(t, "other", next())

	// Success resets the backoff and cancels a waiting retry.
	r.ok("k")
	attempt, delay, _ = r.fail("k")
	require.Equal(t, 1, attempt)
	require.Equal(t, 10*time.Millisecond, delay)
	r.ok("k")
	select {
	case k := <-fired:
		t.Fatalf("cancelled retry fired for %s", k)
	case <-time.After(50 * time.Millisecond):
	}
}
