package live

import (
	"context"
	"strings"

	"github.com/the-it-dept/ffs/internal/model"
)

// OwnersRecomputed queues a findings and inventory change for the owners whose findings the engine
// wrote: the cluster, each owner's workload and namespace, the control plane for the cluster and
// runtime owners, every node group and node for the Nodes owner, and the images the owners run
// (resolved when the event is flushed). It implements engine.Observer and only queues work.
func (h *Hub) OwnersRecomputed(_ context.Context, keys []string) {
	scopes := []string{model.Scope{Kind: model.ScopeCluster}.String()}
	for _, key := range keys {
		ref, ok := model.Scope{Kind: model.ScopeWorkload, Value: key}.Owner()
		if !ok {
			continue
		}
		scopes = append(scopes, model.Scope{Kind: model.ScopeWorkload, Value: key}.String())
		if ref.Namespace != "" {
			scopes = append(scopes, model.Scope{Kind: model.ScopeNamespace, Value: ref.Namespace}.String())
		}
		if ref.ClusterLevel() {
			switch ref.Kind {
			case model.OwnerKindCluster, model.OwnerKindContainerRuntime:
				scopes = append(scopes, model.Scope{Kind: model.ScopeControlPlane}.String())
			case model.OwnerKindNodes:
				scopes = append(scopes, kindWildcard(model.ScopeNodeGroup), kindWildcard(model.ScopeNode))
			}
		}
	}
	h.add([]Kind{KindFindings, KindInventory}, scopes, keys)
}

// MatchesReplaced queues a findings change for re-matched digests: the cluster and each image, or
// for a node group's host packages every node group and node (the API names a group by its stable
// name, which the digest does not carry, and a node's views read its group). It implements
// engine.Observer.
func (h *Hub) MatchesReplaced(_ context.Context, digests []string) {
	scopes := []string{model.Scope{Kind: model.ScopeCluster}.String()}
	for _, d := range digests {
		if id, ok := strings.CutPrefix(d, model.NodeGroupDigestPrefix); ok && id != "" {
			scopes = append(scopes, kindWildcard(model.ScopeNodeGroup), kindWildcard(model.ScopeNode))
			continue
		}
		scopes = append(scopes, model.Scope{Kind: model.ScopeImage, Value: d}.String())
	}
	h.add([]Kind{KindFindings}, scopes, nil)
}

// kindWildcard is the scope that stands for every scope of a kind: "<kind>:*".
func kindWildcard(k model.ScopeKind) string { return string(k) + ":*" }
