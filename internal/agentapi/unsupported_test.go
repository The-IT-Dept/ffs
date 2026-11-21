package agentapi

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/the-it-dept/ffs/internal/config"
)

// TestUnsupportedNodes_Taints (#11): a node with a NoSchedule or NoExecute taint that the agent's
// tolerations do not tolerate is not scheduled by the agent DaemonSet, so it is unsupported rather
// than missing an agent. The chart's default, tolerate everything, leaves no node out; the tolerations
// the DaemonSet controller adds to every daemon pod (cordoned, not-ready, pressured nodes) always apply.
func TestUnsupportedNodes_Taints(t *testing.T) {
	node := func(name string, taints ...corev1.Taint) corev1.Node {
		return corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{"kubernetes.io/os": "linux"}},
			Spec:   corev1.NodeSpec{Taints: taints},
			Status: corev1.NodeStatus{NodeInfo: corev1.NodeSystemInfo{Architecture: "amd64"}}}
	}
	gpu := corev1.Taint{Key: "dedicated", Value: "gpu", Effect: corev1.TaintEffectNoSchedule}
	evict := corev1.Taint{Key: "dedicated", Value: "gpu", Effect: corev1.TaintEffectNoExecute}
	nodes := []corev1.Node{
		node("worker-1"),
		node("worker-2", gpu),
		node("worker-3", gpu, evict),
		node("worker-4", corev1.Taint{Key: corev1.TaintNodeUnschedulable, Effect: corev1.TaintEffectNoSchedule},
			corev1.Taint{Key: corev1.TaintNodeNotReady, Effect: corev1.TaintEffectNoExecute}),
		node("worker-5", corev1.Taint{Key: "spot", Value: "true", Effect: corev1.TaintEffectPreferNoSchedule}),
		node("cp-1", corev1.Taint{Key: "node-role.kubernetes.io/control-plane", Effect: corev1.TaintEffectNoSchedule}),
	}
	na := config.Default().NodeAgent
	require.Equal(t, []config.Toleration{{Operator: "Exists"}}, na.Tolerations, "the chart's default")
	require.Nil(t, unsupportedNodes(na, nodes), "tolerating everything leaves no node out")

	na.Tolerations = nil
	require.Equal(t, map[string]string{
		"worker-2": "taint dedicated=gpu:NoSchedule is not tolerated by nodeAgent.tolerations",
		"worker-3": "taint dedicated=gpu:NoSchedule is not tolerated by nodeAgent.tolerations",
		"cp-1":     "taint node-role.kubernetes.io/control-plane:NoSchedule is not tolerated by nodeAgent.tolerations",
	}, unsupportedNodes(na, nodes))

	na.Tolerations = []config.Toleration{
		{Key: "dedicated", Operator: "Equal", Value: "gpu", Effect: "NoSchedule"},
		{Key: "node-role.kubernetes.io/control-plane", Operator: "Exists"},
	}
	require.Equal(t, map[string]string{"worker-3": "taint dedicated=gpu:NoExecute is not tolerated by nodeAgent.tolerations"},
		unsupportedNodes(na, nodes), "a toleration for NoSchedule does not tolerate NoExecute")

	na.Tolerations = append(na.Tolerations, config.Toleration{Key: "dedicated", Operator: "Exists"})
	require.Nil(t, unsupportedNodes(na, nodes))

	// The node selector still comes first.
	na.NodeSelector = map[string]string{"pool": "general"}
	require.Equal(t, "node labels do not match nodeAgent.nodeSelector", unsupportedNodes(na, nodes)["worker-2"])
}
