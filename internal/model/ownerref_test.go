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
