package config

import (
	"net/netip"
	"strings"
)

// AlertTargetConfig configures alert delivery.
type AlertTargetConfig struct {
	// BlockedCIDRs are address ranges alerts are not delivered to unless the AlertTarget sets
	// allowPrivate. They add to the ranges the guard refuses already (private, carrier-grade NAT and
	// the nodes' pod CIDRs): for example a Service CIDR, or pod ranges, that are globally routable.
	BlockedCIDRs []string `yaml:"blockedCIDRs"`
}

// Prefixes returns BlockedCIDRs parsed, with their host bits cleared. Entries that do not parse,
// which Validate reports, are left out.
func (c AlertTargetConfig) Prefixes() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range c.BlockedCIDRs {
		if p, err := netip.ParsePrefix(strings.TrimSpace(s)); err == nil {
			out = append(out, p.Masked())
		}
	}
	return out
}

func (c AlertTargetConfig) validate(bad func(format string, a ...any)) {
	for i, s := range c.BlockedCIDRs {
		if _, err := netip.ParsePrefix(strings.TrimSpace(s)); err != nil {
			bad("alertTargets.blockedCIDRs[%d]: %q is not a CIDR such as 2001:db8::/64", i, s)
		}
	}
}
