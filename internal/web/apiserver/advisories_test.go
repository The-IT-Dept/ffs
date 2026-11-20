package apiserver_test

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
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

// TestAdvisory_FixedVersionsPastTheFirstPage: an advisory with more open findings than one findings
// page still names the fixed versions of its lowest-priority package version.
func TestAdvisory_FixedVersionsPastTheFirstPage(t *testing.T) {
	f := webtest.Open(t)
	const repo, adv = "docker.io/library/nginx", "CVE-2026-0001"
	finding := func(name string, pr model.Priority, pkg model.FindingPackage) model.Finding {
		owner := model.OwnerRef{Kind: "Deployment", Namespace: "shop", Name: name}
		return model.Finding{Fingerprint: model.FindingFingerprint(webtest.ClusterName, owner, repo, adv), Owner: owner,
			ImageRepo: repo, AdvisoryID: adv, Packages: []model.FindingPackage{pkg}, Digests: []string{webtest.DigestWeb},
			Severity: model.SeverityCritical, FixState: model.FixFixed, FixAvailable: true, Priority: pr, State: model.StateOpen,
			Observed: webtest.Now, Matched: webtest.Now, LastSeen: webtest.Now}
	}
	current := model.FindingPackage{Name: "openssl", Ecosystem: "deb", Installed: "3.0.15-1~deb12u1", Fixed: []string{"3.0.16-1~deb12u1"}}
	older := model.FindingPackage{Name: "openssl", Ecosystem: "deb", Installed: "3.0.14-1~deb12u1", Fixed: []string{"3.0.15-1~deb12u1"}}
	var fs []model.Finding
	for i := range 200 {
		fs = append(fs, finding(fmt.Sprintf("fill-%03d", i), model.PriorityUrgent, current))
	}
	low := finding("legacy", model.PriorityLow, older)
	fs = append(fs, low)
	require.NoError(t, f.Store.ApplyFindings(t.Context(), fs, nil))

	first, err := f.Store.FindingsPage(t.Context(), store.FindingQuery{Advisory: adv,
		States: []model.FindingState{model.StateOpen, model.StateExcepted}, Limit: 200})
	require.NoError(t, err)
	require.Equal(t, 203, first.Total)
	require.NotEmpty(t, first.Next)
	require.False(t, slices.ContainsFunc(first.Rows, func(r model.Finding) bool { return r.Fingerprint == low.Fingerprint }),
		"the low-priority finding is past the first page")

	got := ok[apigen.AdvisoryDetail](t, get(t, handlerOf(f), "/api/v1/advisories/"+adv))
	require.Equal(t, []apigen.AdvisoryPackage{
		{Name: "openssl", Ecosystem: "deb", Installed: "3.0.15-1~deb12u1", Fixed: []string{"3.0.16-1~deb12u1"}, Findings: 202},
		{Name: "openssl", Ecosystem: "deb", Installed: "3.0.14-1~deb12u1", Fixed: []string{"3.0.15-1~deb12u1"}, Findings: 1},
	}, got.Packages)
}
