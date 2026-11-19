package model

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
