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
	require.True(t, OwnerRef{Kind: "Nodes", Name: "prod"}.ClusterLevel())
	require.False(t, OwnerRef{Kind: "Nodes", Namespace: "ops", Name: "prod"}.ClusterLevel())
	require.True(t, ClusterLevelKey("Nodes//prod"))
}

func TestNodesOwner(t *testing.T) {
	o := NodesOwner("prod")
	require.Equal(t, OwnerRef{Kind: OwnerKindNodes, Name: "prod"}, o)
	require.Equal(t, "Nodes//prod", o.Key())
	// golden: sha256("prod|Nodes||prod|host|CVE-2026-0001"). Task 5 must not change it.
	require.Equal(t, "05e7813802473e285dcc97c21f886ea0da448a12bbbe6c3e74ed3916e6bf34d1",
		FindingFingerprint("prod", o, HostRepo, "CVE-2026-0001"))
	_, ok := APIVersionForKind(OwnerKindNodes)
	require.False(t, ok)
}

func TestObjectAPIVersion(t *testing.T) {
	for _, tc := range []struct {
		ref  OwnerRef
		want string
		ok   bool
	}{
		{OwnerRef{Kind: "Rollout", Namespace: "web", Name: "r", APIVersion: "argoproj.io/v1alpha1"}, "argoproj.io/v1alpha1", true},
		{OwnerRef{Kind: "Cluster", Namespace: "db", Name: "pg", APIVersion: "postgresql.cnpg.io/v1"}, "postgresql.cnpg.io/v1", true},
		{OwnerRef{Kind: "Deployment", Namespace: "web", Name: "api"}, "apps/v1", true}, // recorded before APIVersion was
		{OwnerRef{Kind: "CloneSet", Namespace: "web", Name: "c"}, "", false},
		{OwnerRef{Kind: OwnerKindCluster, Name: "dev"}, "", false},
		{NodesOwner("dev"), "", false},
	} {
		got, ok := tc.ref.ObjectAPIVersion()
		require.Equal(t, tc.ok, ok, tc.ref.Key())
		require.Equal(t, tc.want, got, tc.ref.Key())
	}
	ref := OwnerRef{Kind: "Rollout", Namespace: "web", Name: "r", APIVersion: "argoproj.io/v1alpha1"}
	require.Equal(t, "Rollout/web/r", ref.Key(), "the key leaves the apiVersion out")
	require.Equal(t, FindingFingerprint("prod", OwnerRef{Kind: "Rollout", Namespace: "web", Name: "r"}, "repo", "CVE-1"),
		FindingFingerprint("prod", ref, "repo", "CVE-1"), "so does the fingerprint")
}
