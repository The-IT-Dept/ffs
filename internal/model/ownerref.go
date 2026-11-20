package model

import "strings"

// Kinds of the synthetic cluster-level owners.
const (
	OwnerKindCluster          = "Cluster"
	OwnerKindContainerRuntime = "ContainerRuntime"
)

// ClusterLevel reports whether r is one of ffs's synthetic cluster-level owners: kind Cluster or
// ContainerRuntime with no namespace. A workload owner of the same kind, such as a CloudNativePG
// Cluster, is namespaced, so the namespace tells them apart.
func (r OwnerRef) ClusterLevel() bool {
	return r.Namespace == "" && (r.Kind == OwnerKindCluster || r.Kind == OwnerKindContainerRuntime)
}

// ClusterLevelKey reports ClusterLevel for an owner key, "Kind/Namespace/Name".
func ClusterLevelKey(key string) bool {
	kind, rest, _ := strings.Cut(key, "/")
	ns, _, _ := strings.Cut(rest, "/")
	return OwnerRef{Kind: kind, Namespace: ns}.ClusterLevel()
}

// APIVersionForKind returns the apiVersion of a workload owner kind, and false for any kind ffs
// does not reference as a Kubernetes object.
func APIVersionForKind(kind string) (string, bool) {
	switch kind {
	case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet":
		return "apps/v1", true
	case "CronJob", "Job":
		return "batch/v1", true
	case "Pod":
		return "v1", true
	}
	return "", false
}
