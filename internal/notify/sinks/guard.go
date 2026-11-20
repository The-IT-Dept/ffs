package sinks

import (
	"fmt"
	"net/netip"
	"slices"
)

var (
	cgnat       = netip.MustParsePrefix("100.64.0.0/10")
	ecsMetadata = netip.MustParseAddr("fd00:ec2::254")
	alibabaMeta = netip.MustParseAddr("100.100.100.200")
)

// CheckAddr is the SSRF guard (spec §6.10). Loopback, link-local, unspecified and multicast
// addresses and cloud metadata endpoints are always refused. Private (RFC 1918, ULA) and
// carrier-grade NAT addresses, and addresses in blocked (the nodes' pod CIDRs and
// alertTargets.blockedCIDRs), are refused unless allowPrivate is set.
func CheckAddr(a netip.Addr, allowPrivate bool, blocked ...netip.Prefix) error {
	a = a.Unmap()
	switch {
	case !a.IsValid():
		return fmt.Errorf("address is not valid")
	case a.IsLoopback(), a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast(), a.IsInterfaceLocalMulticast(),
		a.IsUnspecified(), a.IsMulticast(), a == ecsMetadata, a == alibabaMeta:
		return fmt.Errorf("address %s is never a valid alert destination", a)
	case allowPrivate:
		return nil
	case a.IsPrivate() || cgnat.Contains(a):
		return fmt.Errorf("address %s is private; set allowPrivate to deliver to it", a)
	case slices.ContainsFunc(blocked, func(p netip.Prefix) bool { return p.Contains(a) }):
		return fmt.Errorf("address %s is in a node pod CIDR or alertTargets.blockedCIDRs; set allowPrivate to deliver to it", a)
	}
	return nil
}
