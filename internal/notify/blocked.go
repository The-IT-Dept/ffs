package notify

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// blockedLogEvery is how often a node list that keeps failing is logged.
const blockedLogEvery = 10 * time.Minute

// blockedRanges returns the address ranges alert deliveries refuse, unless a target sets
// allowPrivate, besides the built-in private ones: configured (alertTargets.blockedCIDRs) and the
// pod CIDRs of the nodes in c, the manager's cache, read on each call without copying, each range
// once. A node list that fails leaves the configured ranges, and is logged at most every
// blockedLogEvery.
func blockedRanges(c client.Reader, configured []netip.Prefix, log logr.Logger) func(context.Context) []netip.Prefix {
	var (
		mu     sync.Mutex
		logged time.Time
	)
	return func(ctx context.Context) []netip.Prefix {
		out := slices.Clone(configured)
		var nodes corev1.NodeList
		if err := c.List(ctx, &nodes, client.UnsafeDisableDeepCopy); err != nil {
			mu.Lock()
			now := time.Now()
			logIt := ctx.Err() == nil && (logged.IsZero() || now.Sub(logged) >= blockedLogEvery)
			if logIt {
				logged = now
			}
			mu.Unlock()
			if logIt {
				log.Error(err, "reading the nodes' pod CIDRs for the alert target guard failed")
			}
			return out
		}
		seen := make(map[netip.Prefix]bool, len(out)+len(nodes.Items))
		for _, p := range out {
			seen[p] = true
		}
		for i := range nodes.Items {
			spec := &nodes.Items[i].Spec
			for _, s := range append([]string{spec.PodCIDR}, spec.PodCIDRs...) {
				if p, err := netip.ParsePrefix(s); err == nil && !seen[p.Masked()] {
					seen[p.Masked()] = true
					out = append(out, p.Masked())
				}
			}
		}
		return out
	}
}
