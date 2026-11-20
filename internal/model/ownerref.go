package model

import "strings"

// Kinds of the synthetic cluster-level owners.
const (
	OwnerKindCluster          = "Cluster"
	OwnerKindContainerRuntime = "ContainerRuntime"
	OwnerKindNodes            = "Nodes"
)

// ClusterLevel reports whether r is one of ffs's synthetic cluster-level owners: kind Cluster,
// ContainerRuntime or Nodes with no namespace. A workload owner of the same kind, such as a CloudNativePG
// Cluster, is namespaced, so the namespace tells them apart.
func (r OwnerRef) ClusterLevel() bool {
	return r.Namespace == "" && (r.Kind == OwnerKindCluster || r.Kind == OwnerKindContainerRuntime || r.Kind == OwnerKindNodes)
}

// NodesOwner returns the one owner of every host finding in cluster.
func NodesOwner(cluster string) OwnerRef { return OwnerRef{Kind: OwnerKindNodes, Name: cluster} }

// ClusterLevelKey reports ClusterLevel for an owner key, "Kind/Namespace/Name".
func ClusterLevelKey(key string) bool {
	kind, rest, _ := strings.Cut(key, "/")
	ns, _, _ := strings.Cut(rest, "/")
	return OwnerRef{Kind: kind, Namespace: ns}.ClusterLevel()
}

// ObjectAPIVersion returns the apiVersion of the Kubernetes object r names: its recorded APIVersion,
// else the built-in one for its kind (APIVersionForKind). ok is false for the cluster-level subjects
// and for an owner of a custom kind recorded without one.
func (r OwnerRef) ObjectAPIVersion() (string, bool) {
	if r.ClusterLevel() {
		return "", false
	}
	if r.APIVersion != "" {
		return r.APIVersion, true
	}
	return APIVersionForKind(r.Kind)
}

// APIVersionForKind returns the apiVersion of a built-in workload owner kind, and false for any
// other kind.
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
