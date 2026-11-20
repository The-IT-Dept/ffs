package agentapi

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestPodIndex_DigestsOnNode(t *testing.T) {
	a, b, c, d, e := hexDigest("a"), hexDigest("b"), hexDigest("c"), hexDigest("d"), hexDigest("e")
	p1 := agentPod("apps", "web", "uid-1", "worker-1", "docker.io/library/nginx@"+a, "garbage")
	p1.Status.InitContainerStatuses = []corev1.ContainerStatus{{Name: "init", ImageID: b}}
	p1.Status.EphemeralContainerStatuses = []corev1.ContainerStatus{{Name: "debug", ImageID: "docker-pullable://ghcr.io/x/y@" + e}}
	p1.Status.ContainerStatuses[0].VolumeMounts = []corev1.VolumeMountStatus{{Name: "data", MountPath: "/data",
		VolumeStatus: &corev1.VolumeStatus{Image: &corev1.ImageVolumeStatus{ImageRef: "ghcr.io/x/z@" + c}}}}
	p2 := agentPod("apps", "db", "uid-2", "worker-2", d)
	p2.Status.Phase = corev1.PodSucceeded

	cl := fake.NewClientBuilder().WithObjects(p1, p2).WithIndex(&corev1.Pod{}, PodNodeNameIndex, podNodeName).Build()
	idx := NewPodIndex(cl)

	got, err := idx.DigestsOnNode(context.Background(), "worker-1")
	require.NoError(t, err)
	require.Equal(t, map[string]bool{a: true, b: true, c: true, e: true}, got)

	got, err = idx.DigestsOnNode(context.Background(), "worker-2")
	require.NoError(t, err)
	require.Equal(t, map[string]bool{d: true}, got, "pods in any phase count")

	got, err = idx.DigestsOnNode(context.Background(), "worker-3")
	require.NoError(t, err)
	require.Empty(t, got)
}

// recordingIndexer records IndexField calls.
type recordingIndexer struct {
	calls []indexCall
}

type indexCall struct {
	obj     client.Object
	field   string
	extract client.IndexerFunc
}

func (r *recordingIndexer) IndexField(_ context.Context, obj client.Object, field string, extract client.IndexerFunc) error {
	r.calls = append(r.calls, indexCall{obj: obj, field: field, extract: extract})
	return nil
}

func TestIndexPods_RegistersNodeNameIndex(t *testing.T) {
	fi := &recordingIndexer{}
	require.NoError(t, IndexPods(context.Background(), fi))
	require.Len(t, fi.calls, 1)
	require.IsType(t, &corev1.Pod{}, fi.calls[0].obj)
	require.Equal(t, "spec.nodeName", fi.calls[0].field)

	scheduled := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "a"}, Spec: corev1.PodSpec{NodeName: "worker-1"}}
	require.Equal(t, []string{"worker-1"}, fi.calls[0].extract(scheduled))
	require.Nil(t, fi.calls[0].extract(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "b"}}))
}
