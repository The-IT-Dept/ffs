package apiserver

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/store"
)

// A hit of a kind the search does not interleave (a kind the store learns before the API does) is
// left out; it never panics the search.
func TestInterleave_UnknownKindIsLeftOut(t *testing.T) {
	hits := []searchHit{
		hitOf(store.JumpHit{Kind: "workload", ID: "Deployment/shop/web", Label: "web"}),
		hitOf(store.JumpHit{Kind: "chart", ID: "nginx", Label: "nginx", Prefix: true}),
		hitOf(store.JumpHit{Kind: "namespace", ID: "shop", Label: "shop", Count: 2, Prefix: true}),
	}
	var got []string
	require.NotPanics(t, func() {
		for _, h := range interleave(hits) {
			got = append(got, h.kind+":"+h.hit.Id)
		}
	})
	require.Equal(t, []string{"namespace:shop", "workload:Deployment/shop/web"}, got)
	require.Equal(t, "2 workloads", *hits[2].hit.Detail, "the API words a namespace's workload count")
}
