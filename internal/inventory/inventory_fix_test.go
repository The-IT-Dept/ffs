package inventory

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/cache/informertest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/registry"
)

// restart replaces the inventory with a fresh one over the same store and cluster, as a new
// process would be.
func (h *harness) restart() {
	clock := func() time.Time { return h.now }
	h.inv = New(Options{Client: h.c, Store: h.st, Normalizer: NewNormalizer(h.res, h.st, clock), Resolver: h.res,
		Context: fakeContext{}, Hooks: h.hooks, Acquirer: h.acq, ClusterName: "dev", Now: clock})
}

// TestSyncAll_ExpiredCatalogFailedEnqueued (F9): the 24 h retry of a catalogFailed image comes from
// the store, so a restart does not lose it.
func TestSyncAll_ExpiredCatalogFailedEnqueued(t *testing.T) {
	h := newHarness(t, newNode("n1", "amd64"), newPod("web", "n1", nil, "nginx:1.27", nginx+"@"+mA, "regcred"))
	h.res.platforms[mA+"|linux/amd64"] = registryManifest(mA, "", "linux/amd64")
	require.NoError(t, h.st.UpsertImage(ctx, model.Image{Digest: mA, Repo: nginx, Platform: "linux/amd64",
		Status: model.ImageCatalogFailed, StatusReason: "cataloguer crashed", Attempts: 2, QuarantinedUntil: t0.Add(time.Hour)}))

	// Still quarantined: nothing to do.
	require.NoError(t, h.inv.SyncAll(ctx))
	require.Empty(t, h.acq.reqs)

	// A new process after the quarantine ended hands the image to the acquirer again, with the
	// owner's credentials.
	h.now = t0.Add(time.Hour + time.Second)
	h.restart()
	require.NoError(t, h.inv.SyncAll(ctx))
	require.Len(t, h.acq.reqs, 1)
	require.Equal(t, mA, h.acq.reqs[0].Digest)
	require.Equal(t, registry.CredSet{Namespace: "apps", ServiceAccount: "default", PullSecrets: []string{"regcred"}}, h.acq.reqs[0].Creds)

	// Not again while that request is outstanding.
	require.NoError(t, h.inv.Flush(ctx, []string{"Pod/apps/web"}))
	require.Len(t, h.acq.reqs, 1)
}

// TestStart_FlushesOwnersOfExpiredQuarantine (F9): running owners are not flushed by any event when
// a quarantine ends, so the inventory looks for them every RetryPoll.
func TestStart_FlushesOwnersOfExpiredQuarantine(t *testing.T) {
	h := newHarness(t, newNode("n1", "amd64"), newPod("web", "n1", nil, "nginx:1.27", nginx+"@"+mA))
	h.res.platforms[mA+"|linux/amd64"] = registryManifest(mA, "", "linux/amd64")
	require.NoError(t, h.st.UpsertImage(ctx, model.Image{Digest: mA, Repo: nginx, Platform: "linux/amd64",
		Status: model.ImageCatalogFailed, Attempts: 2, QuarantinedUntil: t0.Add(time.Hour)}))
	h.inv.o.RetryPoll, h.inv.o.Debounce = 20*time.Millisecond, 10*time.Millisecond
	h.inv.batch.window = 10 * time.Millisecond

	sctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- h.inv.Start(sctx) }()
	require.Eventually(t, h.inv.Synced, 5*time.Second, 5*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	require.Empty(t, h.acq.digests())

	// The quarantine ends (written to the store, as the acquirer would, rather than moving the clock
	// under the running inventory).
	require.NoError(t, h.st.UpsertImage(ctx, model.Image{Digest: mA, Repo: nginx, Platform: "linux/amd64",
		Status: model.ImageCatalogFailed, Attempts: 2, QuarantinedUntil: t0.Add(-time.Second)}))
	require.Eventually(t, func() bool { return len(h.acq.digests()) == 1 }, 5*time.Second, 5*time.Millisecond)
	cancel()
	require.NoError(t, <-done)
}

// TestFlush_UnreachableRegistry (F10): a registry ffs cannot reach does not keep the workload out of
// the inventory. The owner is stored at once with its other containers and a placeholder; after
// repeated failures over unreachableAfter the image is recorded unresolvable, with an hourly retry.
func TestFlush_UnreachableRegistry(t *testing.T) {
	const local = "registry.local:5000/app"
	pod := newPod("web", "n1", nil, "nginx:1.27", nginx+"@"+mA)
	pod.Spec.Containers = append(pod.Spec.Containers, corev1.Container{Name: "sidecar", Image: local + ":1"})
	pod.Status.ContainerStatuses = append(pod.Status.ContainerStatuses,
		corev1.ContainerStatus{Name: "sidecar", Image: local + ":1", ImageID: local + "@" + idx})
	h := newHarness(t, newNode("n1", "amd64"), pod)
	h.res.platforms[mA+"|linux/amd64"] = registryManifest(mA, "", "linux/amd64")
	unreachable := &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{Err: "no such host", Name: "registry.local", IsNotFound: true}}
	h.res.fakeResolver = &fakeResolver{tags: h.res.tags, platforms: h.res.platforms, configs: h.res.configs}
	resolver := &failingRepo{fakeResolver: h.res.fakeResolver, repo: local, err: unreachable}
	h.inv.o.Normalizer = NewNormalizer(resolver, h.st, func() time.Time { return h.now })
	h.inv.retry.min = time.Hour
	t.Cleanup(h.inv.retry.stop)

	require.NoError(t, h.inv.SyncAll(ctx))
	o := h.owner(t, "Pod/apps/web")
	require.Equal(t, []string{mA, ""}, digestsOf(o.Containers), "stored with the container it could resolve")
	attempt, _ := backoffOf(h.inv.retry, "Pod/apps/web")
	require.Equal(t, 1, attempt)

	// Retried every 3 minutes: the third failure is past unreachableAfter.
	h.now = t0.Add(3 * time.Minute)
	require.NoError(t, h.inv.Flush(ctx, []string{"Pod/apps/web"}))
	_, ok, err := h.st.GetImage(ctx, idx)
	require.NoError(t, err)
	require.False(t, ok, "two failures in three minutes are still retried")
	h.now = t0.Add(6 * time.Minute)
	require.NoError(t, h.inv.Flush(ctx, []string{"Pod/apps/web"}))
	img, ok, err := h.st.GetImage(ctx, idx)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, model.ImageUnresolvable, img.Status)
	require.Equal(t, fmt.Sprintf(ReasonUnreachable, local, "DNS lookup failed"), img.StatusReason)
	require.True(t, img.QuarantinedUntil.Equal(h.now.Add(UnreachableRetry)))
	require.Equal(t, []string{mA, idx}, digestsOf(h.owner(t, "Pod/apps/web").Containers))
	attempt, _ = backoffOf(h.inv.retry, "Pod/apps/web")
	require.Zero(t, attempt)
}

// failingRepo fails every lookup in one repository.
type failingRepo struct {
	*fakeResolver
	repo string
	err  error
}

func (f *failingRepo) PlatformManifest(ctx context.Context, repo, digest, platform string, cs registry.CredSet) (registry.Manifest, error) {
	if repo == f.repo {
		return registry.Manifest{}, f.err
	}
	return f.fakeResolver.PlatformManifest(ctx, repo, digest, platform, cs)
}

// TestTemplate_TenantCannotAttachPrivateImage (F12): a workload that only names an image (a template,
// never pulled) gets a digest only when the registry confirms its own credentials may pull it, so a
// tenant cannot attach another namespace's private image, its packages and CVEs to its Findings.
func TestTemplate_TenantCannotAttachPrivateImage(t *testing.T) {
	const private = "ghcr.io/team-a/private"
	cron := func(ns, image string, secrets ...string) *batchv1.CronJob {
		return &batchv1.CronJob{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "job"},
			Spec: batchv1.CronJobSpec{Schedule: "@daily", Suspend: ptr.To(true), JobTemplate: batchv1.JobTemplateSpec{
				Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: podSpec(image, secrets...)}}}}}
	}
	h := newHarness(t, newNode("n1", "amd64"),
		cron("team-a", private+":v1", "a-cred"), cron("team-b", private+":v1"), cron("team-c", private+"@"+idx))
	h.res.tags[private+":v1"] = idx
	h.res.platforms[idx+"|linux/amd64"] = registryManifest(mA, idx, "linux/amd64")
	h.res.allow = func(repo string, cs registry.CredSet) bool { return repo != private || cs.Namespace == "team-a" }

	require.NoError(t, h.inv.SyncAll(ctx))
	require.Equal(t, []string{mA}, digestsOf(h.owner(t, "CronJob/team-a/job").Containers))
	for _, key := range []string{"CronJob/team-b/job", "CronJob/team-c/job"} {
		cs := h.owner(t, key).Containers
		require.Len(t, cs, 1, key)
		require.NotEqual(t, mA, cs[0].Digest, key)
		img, ok, err := h.st.GetImage(ctx, cs[0].Digest)
		require.NoError(t, err)
		require.True(t, ok, key)
		require.Equal(t, model.ImageUnresolvable, img.Status, key)
		require.Equal(t, fmt.Sprintf(registry.ReasonUnauthorized, private), img.StatusReason, key)
	}

	// Within TagTTL the confirmed owner reuses the record without asking the registry again.
	before := h.res.resolveTagCalls
	h.now = t0.Add(time.Hour)
	require.NoError(t, h.inv.Flush(ctx, []string{"CronJob/team-a/job"}))
	require.Equal(t, before, h.res.resolveTagCalls)
}

// TestNamespacedClusterKind (F17): a CloudNativePG owner (kind Cluster, in a namespace) is a workload
// owner like any other: MarkNamespace flushes it, and SyncAll removes it once it is gone.
func TestNamespacedClusterKind(t *testing.T) {
	pg := newPod("pg-1", "n1", ctrl("postgresql.cnpg.io/v1", "Cluster", "pg"), "postgres:17", nginx+"@"+mA)
	h := newHarness(t, newNode("n1", "amd64"), pg)
	h.res.platforms[mA+"|linux/amd64"] = registryManifest(mA, "", "linux/amd64")
	require.NoError(t, h.inv.SyncAll(ctx))
	h.owner(t, "Cluster/apps/pg")
	h.owner(t, "Cluster//dev")
	h.inv.batch.take()

	// The pod goes away: MarkNamespace's flush reaches the owner, not the synthetic Cluster.
	require.NoError(t, h.c.Delete(ctx, pg))
	h.inv.MarkNamespace("apps")
	keys := h.inv.batch.take()
	require.Contains(t, keys, "Cluster/apps/pg")
	require.NoError(t, h.inv.Flush(ctx, keys))
	_, ok, err := h.st.GetOwner(ctx, "Cluster/apps/pg")
	require.NoError(t, err)
	require.False(t, ok)
	h.owner(t, "Cluster//dev")

	// Deleted while ffs was down: SyncAll in the next process removes it.
	require.NoError(t, h.st.UpsertOwner(ctx, model.Owner{Ref: model.OwnerRef{Kind: "Cluster", Namespace: "db", Name: "gone"},
		Containers: []model.ContainerUse{{Name: "postgres", Digest: mA}}}))
	h.restart()
	require.NoError(t, h.inv.SyncAll(ctx))
	_, ok, err = h.st.GetOwner(ctx, "Cluster/db/gone")
	require.NoError(t, err)
	require.False(t, ok)
	h.owner(t, "Cluster//dev")
}

// TestRegister_QueuesObjectKeys covers the informer handlers: object events queue their key, and
// node changes and the kube-proxy DaemonSet queue "cluster".
func TestRegister_QueuesObjectKeys(t *testing.T) {
	h := newHarness(t)
	// The ReplicaSet informer is metadata-only, as in the manager's cache.
	s := runtime.NewScheme()
	s.AddKnownTypes(corev1.SchemeGroupVersion, &corev1.Pod{}, &corev1.Node{})
	s.AddKnownTypes(appsv1.SchemeGroupVersion, &appsv1.Deployment{}, &appsv1.StatefulSet{}, &appsv1.DaemonSet{})
	s.AddKnownTypeWithName(appsv1.SchemeGroupVersion.WithKind("ReplicaSet"), &metav1.PartialObjectMetadata{})
	s.AddKnownTypes(batchv1.SchemeGroupVersion, &batchv1.Job{}, &batchv1.CronJob{})
	fi := &informertest.FakeInformers{Scheme: s}
	require.NoError(t, h.inv.register(ctx, fi))
	inf := func(obj client.Object) interface {
		Add(metav1.Object)
		Update(metav1.Object, metav1.Object)
	} {
		i, err := fi.FakeInformerFor(ctx, obj)
		require.NoError(t, err)
		return i
	}

	inf(&corev1.Pod{}).Add(newPod("web-x", "n1", nil, "nginx:1.27", ""))
	inf(&appsv1.Deployment{}).Add(newDeployment("web", 1, "nginx:1.27"))
	proxy := &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "kube-proxy"}}
	inf(&appsv1.DaemonSet{}).Add(proxy)
	require.Equal(t, []string{"DaemonSet/kube-system/kube-proxy", "Deployment/apps/web", "Pod/apps/web-x", "cluster"}, h.inv.batch.take())

	n1 := newNode("n1", "amd64")
	inf(&corev1.Node{}).Add(n1)
	require.Equal(t, []string{"cluster"}, h.inv.batch.take())
	relabelled := n1.DeepCopy()
	relabelled.Labels = map[string]string{"team": "x"}
	inf(&corev1.Node{}).Update(n1, relabelled)
	require.Empty(t, h.inv.batch.take(), "a change the inventory does not keep")
	upgraded := n1.DeepCopy()
	upgraded.Status.NodeInfo.KubeletVersion = "v1.35.3+k3s1"
	inf(&corev1.Node{}).Update(n1, upgraded)
	require.Equal(t, []string{"cluster"}, h.inv.batch.take())
}

// TestStart_SyncsThenStops covers Start: the first SyncAll runs before anything else, and Start
// returns when its context ends.
func TestStart_SyncsThenStops(t *testing.T) {
	h := newHarness(t, newNode("n1", "amd64"), newPod("web", "n1", nil, "nginx:1.27", nginx+"@"+mA))
	h.res.platforms[mA+"|linux/amd64"] = registryManifest(mA, "", "linux/amd64")
	sctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- h.inv.Start(sctx) }()
	require.Eventually(t, h.inv.Synced, 5*time.Second, 5*time.Millisecond)
	h.owner(t, "Pod/apps/web")
	cancel()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after its context ended")
	}
}
