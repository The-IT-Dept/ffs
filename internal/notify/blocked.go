package notify

import (
	"context"
	"net/netip"
	"slices"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// blockedRanges returns the address ranges alert deliveries refuse, unless a target sets
// allowPrivate, besides the built-in private ones: configured (alertTargets.blockedCIDRs) and the
// pod CIDRs of the nodes in c, the manager's cache, read on each call without copying. A node
// list that fails is logged and leaves the configured ranges.
func blockedRanges(c client.Reader, configured []netip.Prefix, log logr.Logger) func(context.Context) []netip.Prefix {
	return func(ctx context.Context) []netip.Prefix {
		out := slices.Clone(configured)
		var nodes corev1.NodeList
		if err := c.List(ctx, &nodes, client.UnsafeDisableDeepCopy); err != nil {
			if ctx.Err() == nil {
				log.Error(err, "reading the nodes' pod CIDRs for the alert target guard failed")
			}
			return out
		}
		for i := range nodes.Items {
			spec := &nodes.Items[i].Spec
			for _, s := range append([]string{spec.PodCIDR}, spec.PodCIDRs...) {
				if p, err := netip.ParsePrefix(s); err == nil && !slices.Contains(out, p.Masked()) {
					out = append(out, p.Masked())
				}
			}
		}
		return out
	}
}
