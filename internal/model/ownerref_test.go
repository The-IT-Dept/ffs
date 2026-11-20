package model

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAPIVersionForKind(t *testing.T) {
	for kind, want := range map[string]string{
		"Deployment": "apps/v1", "StatefulSet": "apps/v1", "DaemonSet": "apps/v1", "ReplicaSet": "apps/v1",
		"CronJob": "batch/v1", "Job": "batch/v1", "Pod": "v1",
	} {
		got, ok := APIVersionForKind(kind)
		require.True(t, ok, kind)
		require.Equal(t, want, got, kind)
	}
	for _, kind := range []string{"Rollout", "Cluster", "ContainerRuntime", ""} {
		got, ok := APIVersionForKind(kind)
		require.False(t, ok, kind)
		require.Empty(t, got, kind)
	}
}

func TestClusterLevel(t *testing.T) {
	require.True(t, OwnerRef{Kind: "Cluster", Name: "dev"}.ClusterLevel())
	require.True(t, OwnerRef{Kind: "ContainerRuntime", Name: "containerd"}.ClusterLevel())
	// A CloudNativePG Cluster is a namespaced workload owner, not the synthetic one.
	require.False(t, OwnerRef{Kind: "Cluster", Namespace: "db", Name: "pg"}.ClusterLevel())
	require.False(t, OwnerRef{Kind: "Deployment", Namespace: "apps", Name: "web"}.ClusterLevel())
	require.True(t, ClusterLevelKey("Cluster//dev"))
	require.True(t, ClusterLevelKey("ContainerRuntime//containerd"))
	require.False(t, ClusterLevelKey("Cluster/db/pg"))
	require.False(t, ClusterLevelKey("cluster"))
}
