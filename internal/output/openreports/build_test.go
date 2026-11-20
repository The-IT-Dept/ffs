package openreports_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/validation"

	orv1alpha1 "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/output/openreports"
)

var (
	t0     = time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	dref   = model.OwnerRef{Kind: "Deployment", Namespace: "shop", Name: "web", UID: "uid-web"}
	downer = model.Owner{Ref: dref}
)

func finding(id string, p model.Priority, s model.Severity) model.Finding {
	return model.Finding{Owner: dref, ImageRepo: "docker.io/library/nginx", AdvisoryID: id, Priority: p, Severity: s,
		Matched: t0, State: model.StateOpen}
}

func advisories(fs []model.Finding) map[string]model.Advisory {
	m := map[string]model.Advisory{}
	for _, f := range fs {
		m[f.AdvisoryID] = model.Advisory{ID: f.AdvisoryID, Title: "title " + f.AdvisoryID}
	}
	return m
}

func TestBuildReport_ResultsAndCap(t *testing.T) {
	var fs []model.Finding
	for i := 0; i < 2; i++ {
		fs = append(fs, finding(fmt.Sprintf("CVE-2026-%04d", i+1), model.PriorityUrgent, model.SeverityCritical))
	}
	for i := 0; i < 3; i++ {
		fs = append(fs, finding(fmt.Sprintf("CVE-2026-%04d", i+10), model.PriorityHigh, model.SeverityHigh))
	}
	for i := 0; i < 150; i++ {
		fs = append(fs, finding(fmt.Sprintf("CVE-2026-%04d", i+100), model.PriorityMedium, model.SeverityMedium))
	}
	for i := 0; i < 5; i++ {
		fs = append(fs, finding(fmt.Sprintf("CVE-2026-%04d", i+500), model.PriorityLow, model.SeverityLow))
	}
	r, ok := openreports.BuildReport(downer, fs, advisories(fs), 100, "ffs")
	require.True(t, ok)
	assert.Len(t, r.Results, 100)
	assert.Equal(t, orv1alpha1.Result("fail"), r.Results[0].Result)
	assert.Equal(t, "CVE-2026-0001", r.Results[0].Policy)
	assert.Equal(t, orv1alpha1.Result("warn"), r.Results[99].Result)
	assert.Equal(t, orv1alpha1.ReportSummary{Fail: 5, Warn: 150}, r.Summary)
	assert.Equal(t, "ffs", r.Source)
	assert.Equal(t, "apps/v1", r.Scope.APIVersion)
	assert.Equal(t, "Deployment", r.Scope.Kind)
	assert.Equal(t, 100, r.Configuration.Limits.MaxResults)
	assert.Equal(t, "shop", r.Namespace)
	assert.Equal(t, "title CVE-2026-0001", r.Results[0].Description)

	var onlyLow []model.Finding
	onlyLow = append(onlyLow, finding("CVE-2026-0900", model.PriorityLow, model.SeverityLow))
	_, ok = openreports.BuildReport(downer, onlyLow, nil, 100, "ffs")
	assert.False(t, ok)
}

func TestBuildReport_Properties(t *testing.T) {
	f := finding("CVE-2026-0001", model.PriorityUrgent, model.SeverityCritical)
	f.Packages = []model.FindingPackage{
		{Name: "libssl3", Installed: "3.0.11-1~deb12u2", Fixed: []string{"3.0.15-1~deb12u1"}},
		{Name: "openssl", Installed: "3.0.11-1~deb12u2", Fixed: []string{"3.0.15-1~deb12u1"}},
	}
	f.Reasons = []string{"actively exploited (CISA KEV, added 2026-11-02)", "exposed via Service shop/web type LoadBalancer"}
	f.Suggestion = &model.Suggestion{Repo: "docker.io/library/nginx", ToTag: "1.27.4", Tier: model.TierPatch}
	advs := map[string]model.Advisory{"CVE-2026-0001": {ID: "CVE-2026-0001", CNACVSS: 9.8,
		Links: []string{"https://security-tracker.debian.org/tracker/CVE-2026-0001", "https://example.com"}}}
	r, ok := openreports.BuildReport(downer, []model.Finding{f}, advs, 100, "ffs")
	require.True(t, ok)
	p := r.Results[0].Properties
	assert.Equal(t, "libssl3, openssl", p["resource"])
	assert.Equal(t, "3.0.11-1~deb12u2, 3.0.11-1~deb12u2", p["installedVersion"])
	assert.Equal(t, "3.0.15-1~deb12u1, 3.0.15-1~deb12u1", p["fixedVersion"])
	assert.Equal(t, "https://security-tracker.debian.org/tracker/CVE-2026-0001", p["primaryLink"])
	assert.Equal(t, "9.8", p["score"])
	assert.Equal(t, "urgent", p["ffs.priority"])
	assert.Equal(t, "actively exploited (CISA KEV, added 2026-11-02); exposed via Service shop/web type LoadBalancer", p["ffs.reasons"])
	assert.Equal(t, "docker.io/library/nginx:1.27.4", p["ffs.suggestedImage"])
	assert.Equal(t, "CVE-2026-0001", r.Results[0].Policy)
	assert.Equal(t, "docker.io/library/nginx", r.Results[0].Rule)
	assert.Equal(t, "CVE-2026-0001", r.Results[0].Description) // no advisory title
	assert.Equal(t, orv1alpha1.ResultSeverity("critical"), r.Results[0].Severity)

	g := finding("CVE-2026-0002", model.PriorityMedium, model.SeverityNegligible)
	g.Suggestion = &model.Suggestion{Repo: "r", ToTag: "2", Tier: model.TierNone}
	r, _ = openreports.BuildReport(downer, []model.Finding{g}, nil, 100, "ffs")
	assert.Equal(t, orv1alpha1.ResultSeverity("info"), r.Results[0].Severity)
	assert.NotContains(t, r.Results[0].Properties, "ffs.suggestedImage")
	assert.NotContains(t, r.Results[0].Properties, "score")
}

func TestReportName_DNSSafe(t *testing.T) {
	ref := func(n string) model.OwnerRef { return model.OwnerRef{Kind: "Deployment", Namespace: "shop", Name: n} }
	assert.Equal(t, "ffs-deployment-web", openreports.ReportName(dref))
	long := openreports.ReportName(model.OwnerRef{Kind: "StatefulSet", Namespace: "x", Name: strings.Repeat("a", 80)})
	assert.Empty(t, validation.IsDNS1123Label(long))
	assert.Len(t, long, 63)
	a, b := openreports.ReportName(ref("a.b")), openreports.ReportName(ref("a-b"))
	assert.NotEqual(t, a, b)
	assert.Empty(t, validation.IsDNS1123Label(a))
}

// TestBuildReport_CustomKindScope (F93): a custom-kind owner recorded with its apiVersion gets a
// scoped Report; one recorded without it gets none rather than a wrong one.
func TestBuildReport_CustomKindScope(t *testing.T) {
	fs := []model.Finding{finding("CVE-2026-0001", model.PriorityHigh, model.SeverityHigh)}
	rollout := model.OwnerRef{Kind: "Rollout", Namespace: "shop", Name: "web", UID: "uid-r", APIVersion: "argoproj.io/v1alpha1"}
	r, ok := openreports.BuildReport(model.Owner{Ref: rollout}, fs, advisories(fs), 100, "ffs")
	require.True(t, ok)
	require.NotNil(t, r.Scope)
	assert.Equal(t, "argoproj.io/v1alpha1", r.Scope.APIVersion)
	assert.Equal(t, "Rollout", r.Scope.Kind)
	assert.Equal(t, "web", r.Scope.Name)
	assert.EqualValues(t, "uid-r", r.Scope.UID)

	rollout.APIVersion = ""
	r, ok = openreports.BuildReport(model.Owner{Ref: rollout}, fs, advisories(fs), 100, "ffs")
	require.True(t, ok)
	assert.Nil(t, r.Scope)
}
