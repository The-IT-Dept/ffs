package model

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseScope_RoundTrip(t *testing.T) {
	for in, want := range map[string]Scope{
		"": {Kind: ScopeCluster}, "cluster": {Kind: ScopeCluster}, "controlplane": {Kind: ScopeControlPlane},
		"namespace:shop": {ScopeNamespace, "shop"}, "workload:Deployment/shop/web": {ScopeWorkload, "Deployment/shop/web"},
		"workload:Cluster//test": {ScopeWorkload, "Cluster//test"}, "image:sha256:ab12": {ScopeImage, "sha256:ab12"},
		"image:unknown:ghcr.io/example/private:1.0": {ScopeImage, "unknown:ghcr.io/example/private:1.0"},
		"nodegroup:4f1c": {ScopeNodeGroup, "4f1c"}, "node:worker-1": {ScopeNode, "worker-1"},
	} {
		got, err := ParseScope(in)
		require.NoError(t, err, in)
		require.Equal(t, want, got, in)
		if in != "" {
			require.Equal(t, in, got.String())
		}
	}
	require.Equal(t, "cluster", Scope{Kind: ScopeCluster}.String())
}

func TestParseScope_Rejects(t *testing.T) {
	for _, in := range []string{"namespace:", "workload:Deployment/shop", "workload:/shop/web", "workload:Deployment/shop/",
		"workload:Deployment/shop/web/x", "pod:web", "cluster:test", "controlplane:x", "Namespace:shop", "image"} {
		_, err := ParseScope(in)
		require.ErrorIs(t, err, ErrBadScope, in)
		require.ErrorContains(t, err, in)
	}
}

func TestScope_Owner(t *testing.T) {
	for in, want := range map[string]OwnerRef{
		"workload:Deployment/shop/web": {Kind: "Deployment", Namespace: "shop", Name: "web"},
		"workload:Cluster//test":       {Kind: "Cluster", Name: "test"},
	} {
		sc, err := ParseScope(in)
		require.NoError(t, err, in)
		got, ok := sc.Owner()
		require.True(t, ok, in)
		require.Equal(t, want, got, in)
	}
	sc, err := ParseScope("namespace:shop")
	require.NoError(t, err)
	got, ok := sc.Owner()
	require.False(t, ok)
	require.Equal(t, OwnerRef{}, got)
}
