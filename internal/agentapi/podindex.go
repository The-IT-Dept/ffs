package agentapi

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/the-it-dept/ffs/internal/inventory"
)

// PodNodeNameIndex is the field index of cached Pods by the node they are scheduled on.
const PodNodeNameIndex = "spec.nodeName"

// IndexPods registers PodNodeNameIndex. It must run before the manager's cache starts.
func IndexPods(ctx context.Context, fi client.FieldIndexer) error {
	return fi.IndexField(ctx, &corev1.Pod{}, PodNodeNameIndex, podNodeName)
}

// podNodeName is the PodNodeNameIndex extractor: the pod's node, or nothing for an unscheduled pod.
func podNodeName(o client.Object) []string {
	p, ok := o.(*corev1.Pod)
	if !ok || p.Spec.NodeName == "" {
		return nil
	}
	return []string{p.Spec.NodeName}
}

// PodIndex reports the image digests the pods on a node run.
type PodIndex interface {
	// DigestsOnNode returns the digests named by the image IDs of every pod on node, in any phase: container,
	// init and ephemeral container statuses, and image volumes.
	DigestsOnNode(ctx context.Context, node string) (map[string]bool, error)
}

type podIndex struct{ r client.Reader }

// NewPodIndex returns a PodIndex over r, a cache-backed reader with PodNodeNameIndex registered.
func NewPodIndex(r client.Reader) PodIndex { return podIndex{r: r} }

func (p podIndex) DigestsOnNode(ctx context.Context, node string) (map[string]bool, error) {
	var pods corev1.PodList
	if err := p.r.List(ctx, &pods, client.MatchingFields{PodNodeNameIndex: node}); err != nil {
		return nil, err
	}
	out := map[string]bool{}
	add := func(imageID string) {
		if _, d, _, err := inventory.ParseImageID(imageID); err == nil {
			out[d] = true
		}
	}
	for i := range pods.Items {
		st := &pods.Items[i].Status
		for _, statuses := range [][]corev1.ContainerStatus{st.ContainerStatuses, st.InitContainerStatuses, st.EphemeralContainerStatuses} {
			for _, cs := range statuses {
				add(cs.ImageID)
				for _, m := range cs.VolumeMounts {
					if m.VolumeStatus != nil && m.VolumeStatus.Image != nil {
						add(m.VolumeStatus.Image.ImageRef)
					}
				}
			}
		}
	}
	return out, nil
}
