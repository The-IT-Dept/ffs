package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAlertTargets_BlockedCIDRs pins F98's config key: alertTargets.blockedCIDRs takes IPv4 and
// IPv6 CIDRs, clears their host bits, and reports every entry that is not a CIDR.
func TestAlertTargets_BlockedCIDRs(t *testing.T) {
	assert.Empty(t, Default().AlertTargets.BlockedCIDRs)

	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("alertTargets:\n  blockedCIDRs: [\"2001:db8:42::/56\", \" 198.51.100.7/24 \"]\n"), 0o600))
	c, err := Load(path)
	require.NoError(t, err)
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("2001:db8:42::/56"), netip.MustParsePrefix("198.51.100.0/24")},
		c.AlertTargets.Prefixes())

	c = Default()
	c.AlertTargets.BlockedCIDRs = []string{"2001:db8::/64", "10.0.0.1", "not-a-cidr"}
	err = c.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), `alertTargets.blockedCIDRs[1]: "10.0.0.1" is not a CIDR`)
	assert.Contains(t, err.Error(), `alertTargets.blockedCIDRs[2]: "not-a-cidr" is not a CIDR`)
	assert.NotContains(t, err.Error(), "blockedCIDRs[0]")
}
