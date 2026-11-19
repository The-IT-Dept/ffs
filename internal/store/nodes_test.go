package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

func TestNodesAndClusterInfo(t *testing.T) {
	s := newStore(t)

	nodes, err := s.ListNodes(ctx)
	require.NoError(t, err)
	require.Empty(t, nodes)

	first := []model.Node{
		{Name: "n2", OS: "linux", Arch: "arm64", OSImage: "Ubuntu 24.04", KernelVersion: "6.8.0", KubeletVersion: "v1.35.2+k3s1",
			ContainerRuntimeVersion: "containerd://2.1.4-k3s1", Ready: true, UpdatedAt: t0},
		{Name: "n1", OS: "linux", Arch: "amd64", KubeletVersion: "v1.35.2+k3s1", UpdatedAt: t0},
	}
	require.NoError(t, s.ReplaceNodes(ctx, first))
	nodes, err = s.ListNodes(ctx)
	require.NoError(t, err)
	require.Equal(t, []model.Node{first[1], first[0]}, nodes)

	second := []model.Node{{Name: "n3", OS: "linux", Arch: "amd64", Ready: true, UpdatedAt: t0.Add(time.Minute)}}
	require.NoError(t, s.ReplaceNodes(ctx, second))
	nodes, err = s.ListNodes(ctx)
	require.NoError(t, err)
	require.Equal(t, second, nodes)

	_, ok, err := s.GetClusterInfo(ctx)
	require.NoError(t, err)
	require.False(t, ok)

	ci := model.ClusterInfo{Name: "prod", GitVersion: "v1.30.4-eks-a737599", Version: "1.30.4", Distribution: "eks",
		LowConfidence: true, KubeProxyVersion: "1.30.4", UpdatedAt: t0}
	require.NoError(t, s.PutClusterInfo(ctx, ci))
	got, ok, err := s.GetClusterInfo(ctx)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, ci, got)

	ci.Version, ci.GitVersion, ci.LowConfidence, ci.Distribution = "1.35.2", "v1.35.2", false, ""
	require.NoError(t, s.PutClusterInfo(ctx, ci))
	got, _, err = s.GetClusterInfo(ctx)
	require.NoError(t, err)
	require.Equal(t, ci, got)
}
