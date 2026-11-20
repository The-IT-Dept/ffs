package apiserver_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/web/apigen"
	"github.com/the-it-dept/ffs/internal/web/webtest"
)

func TestAdvisory_GroupsAffectedWorkloadsByFix(t *testing.T) {
	_, h := newAPI(t)
	got := ok[apigen.AdvisoryDetail](t, get(t, h, "/api/v1/advisories/CVE-2026-0001"))
	require.Equal(t, "CVE-2026-0001", got.Id)
	require.Equal(t, apigen.PriorityCounts{Urgent: 1, High: 1}, got.Counts)
	require.Equal(t, 2, got.Workloads)
	require.Equal(t, 2, got.Findings)
	require.NotNil(t, got.Kev)
	require.Equal(t, "2026-11-02", got.Kev.Added.String())
	require.Equal(t, &apigen.EpssInfo{Score: 0.42, Percentile: 0.97}, got.Epss)

	var keys []string
	for _, r := range got.ByFix {
		keys = append(keys, r.Key)
	}
	require.Equal(t, []string{"upgrade:docker.io/library/nginx:1.30.7", "rebuild:debian:12"}, keys)

	require.Contains(t, got.Severities, apigen.SourceSeverity{Source: "debian", Severity: apigen.SeverityCritical, Used: true})
	require.Contains(t, got.Severities, apigen.SourceSeverity{Source: "cna", Severity: apigen.SeverityCritical, Used: false})

	require.NotNil(t, got.Timeline.Published)
	require.True(t, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC).Equal(*got.Timeline.Published))
	require.NotNil(t, got.Timeline.Observed)
	require.True(t, webtest.Now.Equal(*got.Timeline.Observed))
	require.NotNil(t, got.Timeline.FirstMatched)
	require.True(t, webtest.Now.Add(-3*time.Hour).Equal(*got.Timeline.FirstMatched))

	require.Equal(t, []apigen.AdvisoryPackage{{Name: "openssl", Ecosystem: "deb", Installed: "3.0.15-1~deb12u1",
		Fixed: []string{"3.0.16-1~deb12u1"}, Findings: 2}}, got.Packages)
	require.Equal(t, 4, got.Uncatalogued)
	require.Equal(t, []string{"https://advisories.example.com/CVE-2026-0001"}, got.Links)
}

func TestAdvisory_ByAliasAndNotFound(t *testing.T) {
	_, h := newAPI(t)
	got := ok[apigen.AdvisoryDetail](t, get(t, h, "/api/v1/advisories/GHSA-aaaa-bbbb-cccc"))
	require.Equal(t, "CVE-2026-0002", got.Id)
	require.Equal(t, []string{"GHSA-aaaa-bbbb-cccc"}, got.Aliases)
	require.Equal(t, "<script>alert(1)</script>", got.Title, "returned verbatim; the UI escapes it")

	p := wantProblem(t, get(t, h, "/api/v1/advisories/CVE-1999-0000"), 404, apigen.ProblemCodeNotFound)
	require.NotNil(t, p.Detail)
	require.Contains(t, *p.Detail, "CVE-1999-0000")
}
