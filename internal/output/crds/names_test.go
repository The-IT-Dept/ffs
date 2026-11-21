package crds

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

func TestFindingName(t *testing.T) {
	api := deployment("web", "api")
	require.Equal(t, "deployment-api-cve-2026-41873", FindingName(api, "CVE-2026-41873"))
	require.Equal(t, "cluster-test-cve-2026-1111", FindingName(model.OwnerRef{Kind: "Cluster", Name: "test"}, "CVE-2026-1111"))
	require.Equal(t, "deployment-api-opensuse-su-2026-1234-1", FindingName(api, "openSUSE-SU-2026:1234-1"))

	valid := regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`)
	long := strings.Repeat("a", 60)
	one, two := deployment("web", long+strings.Repeat("b", 20)), deployment("web", long+strings.Repeat("c", 20))
	require.Len(t, one.Name, 80)
	got := FindingName(one, "CVE-2026-41873")
	require.Len(t, got, 63)
	require.Regexp(t, valid, got)
	require.Regexp(t, `-[0-9a-f]{8}$`, got)
	require.NotEqual(t, got, FindingName(two, "CVE-2026-41873"), "names differing past the cut stay distinct")
	require.Equal(t, got, FindingName(one, "CVE-2026-41873"), "the name is stable")
}

func TestVulnerabilityName(t *testing.T) {
	require.Equal(t, "cve-2026-41873", VulnerabilityName("CVE-2026-41873"))
	require.Equal(t, "ghsa-abcd-1234-wxyz", VulnerabilityName("GHSA-AbCd-1234-wxyz"))
}
