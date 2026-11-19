package store

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

func TestOwners(t *testing.T) {
	s := newStore(t)
	o := model.Owner{Ref: model.OwnerRef{Kind: "Deployment", Namespace: "netbox", Name: "netbox", UID: "u"},
		ManagedBy:  &model.ManagedBy{Tool: "flux-helmrelease", Name: "netbox", Namespace: "flux-system"},
		Containers: []model.ContainerUse{{Name: "app", Kind: model.ContainerRegular, Digest: "sha256:a"}, {Name: "init", Kind: model.ContainerInit, Digest: "sha256:b"}, {Name: "pending", Digest: ""}},
		Context:    model.WorkloadContext{Exposed: true, ExposurePaths: []string{"HTTPRoute netbox/netbox on Gateway public/edge"}}}
	require.NoError(t, s.UpsertOwner(ctx, o))
	keys, _ := s.OwnersForDigests(ctx, []string{"sha256:a"})
	require.Equal(t, []string{"Deployment/netbox/netbox"}, keys)
	got, ok, _ := s.GetOwner(ctx, "Deployment/netbox/netbox")
	require.True(t, ok)
	require.Equal(t, o.ManagedBy, got.ManagedBy)
	require.Equal(t, o.Context, got.Context)
	o.Containers = o.Containers[1:2] // rollout drops sha256:a
	require.NoError(t, s.UpsertOwner(ctx, o))
	keys, _ = s.OwnersForDigests(ctx, []string{"sha256:a"})
	require.Empty(t, keys)
	inUse, _ := s.DigestsInUse(ctx)
	require.Equal(t, []string{"sha256:b"}, inUse)
	require.NoError(t, s.DeleteOwner(ctx, "Deployment/netbox/netbox"))
	inUse, _ = s.DigestsInUse(ctx)
	require.Empty(t, inUse)
	all, _ := s.ListOwners(ctx)
	require.Empty(t, all)
}
