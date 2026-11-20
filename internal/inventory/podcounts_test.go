package inventory

import (
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestInventory_PodCountsSnapshot(t *testing.T) {
	dep := newDeployment("web", 2, "nginx:1.27")
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web-5d9",
		OwnerReferences: ctrl("apps/v1", "Deployment", "web")}}
	podX := newPod("web-x", "n1", ctrl("apps/v1", "ReplicaSet", "web-5d9"), "nginx:1.27", nginx+"@"+idx)
	podY := newPod("web-y", "n1", ctrl("apps/v1", "ReplicaSet", "web-5d9"), "nginx:1.27", nginx+"@"+idx)
	h := newHarness(t, newNode("n1", "amd64"), dep, rs, podX, podY)
	h.res.platforms[idx+"|linux/amd64"] = registryManifest(mA, idx, "linux/amd64")

	require.Nil(t, h.inv.PodCounts(), "nothing is known before the first flush")
	require.Nil(t, (*Inventory)(nil).PodCounts())

	require.NoError(t, h.inv.SyncAll(ctx))
	counts := h.inv.PodCounts()
	require.Equal(t, 2, counts["Deployment/apps/web"])
	counts["Deployment/apps/web"] = 99
	counts["Deployment/apps/other"] = 1
	again := h.inv.PodCounts()
	require.Equal(t, 2, again["Deployment/apps/web"], "the returned map is a copy")
	require.NotContains(t, again, "Deployment/apps/other")

	require.NoError(t, h.c.Delete(ctx, podY))
	require.NoError(t, h.inv.Flush(ctx, []string{"Pod/apps/web-y"}))
	require.Equal(t, 1, h.inv.PodCounts()["Deployment/apps/web"])
}
