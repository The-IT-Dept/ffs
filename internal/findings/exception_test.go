package findings

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/the-it-dept/ffs/internal/model"
)

func TestBuild_Exceptions(t *testing.T) {
	exp := now.Add(24 * time.Hour)
	tenant := func(mut func(*ExceptionRule)) ExceptionRule {
		r := ExceptionRule{Namespace: "web", Name: "accept-a", AdvisoryIDs: []string{"CVE-A"}, Expires: exp}
		if mut != nil {
			mut(&r)
		}
		return r
	}
	clusterWide := func(mut func(*ExceptionRule)) ExceptionRule {
		r := ExceptionRule{Namespace: "ffs", Name: "accept", ClusterWide: true, AdvisoryIDs: []string{"CVE-A"}, Expires: exp}
		if mut != nil {
			mut(&r)
		}
		return r
	}
	onlyRepos := func(globs ...string) func(*ExceptionRule) {
		return func(r *ExceptionRule) { r.AdvisoryIDs, r.ImageRepoGlobs = nil, globs }
	}
	onlyOwners := func(owners ...string) func(*ExceptionRule) {
		return func(r *ExceptionRule) { r.AdvisoryIDs, r.Owners = nil, owners }
	}
	advisories := func(ids ...string) func(*ExceptionRule) {
		return func(r *ExceptionRule) { r.AdvisoryIDs = ids }
	}
	const urgentReason = "exception web/accept-a not applied: urgent findings can only be excepted from the ffs namespace"

	cases := []struct {
		name     string
		urgent   bool // the finding is on a KEV advisory
		rules    []ExceptionRule
		wantBy   string // "" = stays open
		wantPrio model.Priority
		reason   string // a reason the finding must carry
	}{
		{"tenant rule", false, []ExceptionRule{tenant(nil)}, "web/accept-a", model.PriorityHigh, ""},
		{"other namespace", false, []ExceptionRule{tenant(func(r *ExceptionRule) { r.Namespace = "shop" })}, "", model.PriorityHigh, ""},
		{"cluster-wide rule", false, []ExceptionRule{clusterWide(nil)}, "ffs/accept", model.PriorityHigh, ""},
		{"expired", false, []ExceptionRule{tenant(func(r *ExceptionRule) { r.Expires = now.Add(-time.Second) })}, "", model.PriorityHigh, ""},
		{"repo glob", false, []ExceptionRule{tenant(onlyRepos("docker.io/library/*"))}, "web/accept-a", model.PriorityHigh, ""},
		{"other repo glob", false, []ExceptionRule{tenant(onlyRepos("ghcr.io/*"))}, "", model.PriorityHigh, ""},
		{"owner kind/name", false, []ExceptionRule{tenant(onlyOwners("Deployment/api"))}, "web/accept-a", model.PriorityHigh, ""},
		{"other owner", false, []ExceptionRule{tenant(onlyOwners("worker"))}, "", model.PriorityHigh, ""},
		{"no criteria", false, []ExceptionRule{tenant(advisories())}, "", model.PriorityHigh, ""},
		{"alias", false, []ExceptionRule{tenant(advisories("GHSA-aaaa-bbbb-cccc"))}, "web/accept-a", model.PriorityHigh, ""},
		{"cluster-wide before tenant", false, []ExceptionRule{tenant(nil), clusterWide(nil)}, "ffs/accept", model.PriorityHigh, ""},
		{"tenant rule on urgent", true, []ExceptionRule{tenant(nil)}, "", model.PriorityUrgent, urgentReason},
		{"cluster-wide rule on urgent", true, []ExceptionRule{clusterWide(nil)}, "ffs/accept", model.PriorityUrgent, ""},
		{"VEX not affected", false, []ExceptionRule{clusterWide(func(r *ExceptionRule) { r.VEXStatus = "not_affected" })},
			"ffs/accept", model.PriorityLow, "not affected (VEX)"},
		{"VEX under investigation", false, []ExceptionRule{clusterWide(func(r *ExceptionRule) { r.VEXStatus = "under_investigation" })},
			"ffs/accept", model.PriorityHigh, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := advisory("CVE-A", cna(model.SeverityCritical))
			a.Aliases = []string{"GHSA-aaaa-bbbb-cccc"}
			if c.urgent {
				kev(&a)
			}
			in := input([]model.Match{match(model.SourceGrype, libssl3Amd, "CVE-A", fixedIn("3.0.15-1"))}, a)
			in.Exceptions = c.rules
			f := one(t, Build(in))
			if c.wantBy == "" {
				assert.Equal(t, model.StateOpen, f.State)
			} else {
				assert.Equal(t, model.StateExcepted, f.State)
			}
			assert.Equal(t, c.wantBy, f.ExceptedBy)
			assert.Equal(t, c.wantPrio, f.Priority)
			if c.reason != "" {
				assert.Contains(t, f.Reasons, c.reason)
			}
		})
	}
}

func TestExceptionRule_Matches(t *testing.T) {
	f := model.Finding{
		Owner:      model.OwnerRef{Kind: "Deployment", Namespace: "web", Name: "api"},
		ImageRepo:  phpRepo,
		AdvisoryID: "CVE-2026-0001",
		Packages:   []model.FindingPackage{{Name: "libssl3"}, {Name: "openssl"}},
	}
	clusterFinding := model.Finding{Owner: model.OwnerRef{Kind: "Cluster", Name: "prod"}, ImageRepo: "kubernetes",
		AdvisoryID: "CVE-2026-0001", Packages: []model.FindingPackage{{Name: "kubernetes"}}}
	rule := func(mut func(*ExceptionRule)) ExceptionRule {
		r := ExceptionRule{Namespace: "web", Name: "accept", Expires: now.Add(time.Hour)}
		mut(&r)
		return r
	}
	aliases := []string{"GHSA-aaaa-bbbb-cccc"}
	cases := []struct {
		name string
		f    model.Finding
		r    ExceptionRule
		want bool
	}{
		{"advisory, any case", f, rule(func(r *ExceptionRule) { r.AdvisoryIDs = []string{"cve-2026-0001"} }), true},
		{"alias, any case", f, rule(func(r *ExceptionRule) { r.AdvisoryIDs = []string{"ghsa-AAAA-bbbb-cccc"} }), true},
		{"other advisory", f, rule(func(r *ExceptionRule) { r.AdvisoryIDs = []string{"CVE-2026-0002"} }), false},
		{"any package in the list", f, rule(func(r *ExceptionRule) { r.Packages = []string{"curl", "openssl"} }), true},
		{"other package", f, rule(func(r *ExceptionRule) { r.Packages = []string{"curl"} }), false},
		{"lists are ANDed", f, rule(func(r *ExceptionRule) {
			r.AdvisoryIDs, r.Packages = []string{"CVE-2026-0001"}, []string{"curl"}
		}), false},
		{"every list hits", f, rule(func(r *ExceptionRule) {
			r.AdvisoryIDs, r.Packages, r.ImageRepoGlobs, r.Owners =
				[]string{"CVE-2026-0001"}, []string{"libssl3"}, []string{"docker.io/*/php"}, []string{"api"}
		}), true},
		{"owner name, any case", f, rule(func(r *ExceptionRule) { r.Owners = []string{"API"} }), true},
		{"owner kind/name, any case", f, rule(func(r *ExceptionRule) { r.Owners = []string{"deployment/Api"} }), true},
		{"owner of another kind", f, rule(func(r *ExceptionRule) { r.Owners = []string{"StatefulSet/api"} }), false},
		{"bad glob", f, rule(func(r *ExceptionRule) { r.ImageRepoGlobs = []string{"docker.io/["} }), false},
		{"expires now", f, rule(func(r *ExceptionRule) { r.AdvisoryIDs, r.Expires = []string{"CVE-2026-0001"}, now }), false},
		{"no expiry", f, rule(func(r *ExceptionRule) { r.AdvisoryIDs, r.Expires = []string{"CVE-2026-0001"}, time.Time{} }), false},
		{"cluster-level owner, tenant rule", clusterFinding, rule(func(r *ExceptionRule) { r.Packages = []string{"kubernetes"} }), false},
		{"cluster-level owner, cluster-wide rule", clusterFinding, rule(func(r *ExceptionRule) {
			r.Namespace, r.ClusterWide, r.Packages = "ffs", true, []string{"kubernetes"}
		}), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, c.r.Matches(c.f, aliases, now))
		})
	}
	assert.Equal(t, "web/accept", rule(func(*ExceptionRule) {}).Key())
}
