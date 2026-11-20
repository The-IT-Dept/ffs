package inventory

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/registry"
	"github.com/the-it-dept/ffs/internal/sbom"
	"github.com/the-it-dept/ffs/internal/store"
)

func TestFlushCluster_RetiredKeepsStoredRuntimeOwner(t *testing.T) {
	h := newHarness(t, newNode("worker-1", "amd64"))
	require.NoError(t, h.inv.SyncAll(ctx))
	rtKey := "ContainerRuntime//containerd"
	h.owner(t, rtKey) // built while not retired
	require.NoError(t, h.st.PutNodesState(ctx, store.NodesState{AgentEnabled: true, RuntimeRetired: true}))
	h.inv.MarkCluster()
	require.Equal(t, []string{"cluster"}, h.inv.batch.take())
	calls := len(h.hooks.owners)
	require.NoError(t, h.inv.Flush(ctx, []string{"cluster"}))
	h.owner(t, rtKey) // never deleted by the inventory
	img, _, _ := h.st.GetImage(ctx, "k8s:1.35.2")
	require.NotContains(t, img.Coverage.Notes, NoteBundled)
	for _, call := range h.hooks.owners[calls:] {
		require.NotContains(t, call, rtKey)
	}
	require.NoError(t, h.st.DeleteOwner(ctx, rtKey)) // as Rehome drops it
	require.NoError(t, h.inv.Flush(ctx, []string{"cluster"}))
	_, ok, _ := h.st.GetOwner(ctx, rtKey)
	require.False(t, ok) // not rebuilt while retired
	require.NoError(t, h.st.PutNodesState(ctx, store.NodesState{AgentEnabled: true}))
	require.NoError(t, h.inv.Flush(ctx, []string{"cluster"}))
	h.owner(t, rtKey) // back once not retired
}

func TestFlush_AgentImageSupersededAtMostEvery6h(t *testing.T) {
	h := newHarness(t, newNode("worker-1", "amd64"), newPod("web", "worker-1", nil, "nginx:1.27", nginx+"@"+mA, "regcred"))
	require.NoError(t, h.st.UpsertImage(ctx, model.Image{Digest: mA, Repo: nginx, Platform: "linux/amd64",
		Status: model.ImageCatalogued, Source: sbom.SourceAgent, CataloguedAt: t0}))
	require.NoError(t, h.inv.SyncAll(ctx))
	require.Len(t, h.acq.reqs, 1)
	r := h.acq.reqs[0]
	require.True(t, r.Supersede)
	require.Equal(t, mA, r.Digest)
	require.Equal(t, registry.CredSet{Namespace: "apps", ServiceAccount: "default", PullSecrets: []string{"regcred"}}, r.Creds)
	require.NoError(t, h.inv.Flush(ctx, []string{"Pod/apps/web"}))
	require.Len(t, h.acq.reqs, 1) // throttled
	h.now = t0.Add(UnresolvableRetry)
	require.NoError(t, h.inv.Flush(ctx, []string{"Pod/apps/web"}))
	require.Len(t, h.acq.reqs, 2)
	// a registry-catalogued image is never superseded
	require.NoError(t, h.st.UpsertImage(ctx, model.Image{Digest: mA, Repo: nginx, Platform: "linux/amd64",
		Status: model.ImageCatalogued, Source: "registry", CataloguedAt: t0}))
	h.now = h.now.Add(UnresolvableRetry)
	require.NoError(t, h.inv.Flush(ctx, []string{"Pod/apps/web"}))
	require.Len(t, h.acq.reqs, 2)
}

func TestStart_RetryPollFlushesOwnersOfAgentImages(t *testing.T) {
	h := newHarness(t, newNode("worker-1", "amd64"), newPod("web", "worker-1", nil, "nginx:1.27", nginx+"@"+mA))
	require.NoError(t, h.st.UpsertImage(ctx, model.Image{Digest: mA, Repo: nginx, Platform: "linux/amd64",
		Status: model.ImageCatalogued, Source: "registry", CataloguedAt: t0}))
	h.inv.o.RetryPoll, h.inv.o.Debounce = 20*time.Millisecond, 10*time.Millisecond
	h.inv.batch.window = 10 * time.Millisecond

	sctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- h.inv.Start(sctx) }()
	require.Eventually(t, h.inv.Synced, 5*time.Second, 5*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	require.Empty(t, h.acq.digests())

	// The image is now catalogued from a node agent's SBOM (written to the store, as the work queue
	// would, rather than through a pod change).
	require.NoError(t, h.st.UpsertImage(ctx, model.Image{Digest: mA, Repo: nginx, Platform: "linux/amd64",
		Status: model.ImageCatalogued, Source: sbom.SourceAgent, CataloguedAt: t0}))
	require.Eventually(t, func() bool { return len(h.acq.digests()) == 1 }, 5*time.Second, 5*time.Millisecond)
	time.Sleep(50 * time.Millisecond) // later polls are throttled
	cancel()
	require.NoError(t, <-done)
	h.acq.mu.Lock()
	defer h.acq.mu.Unlock()
	require.Len(t, h.acq.reqs, 1)
	require.Equal(t, mA, h.acq.reqs[0].Digest)
	require.True(t, h.acq.reqs[0].Supersede)
}
