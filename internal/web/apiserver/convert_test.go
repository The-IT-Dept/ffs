package apiserver

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/eol"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
	"github.com/the-it-dept/ffs/internal/web/apigen"
)

func TestFixActionOf_ShapesEachKind(t *testing.T) {
	str := func(s string) *string { return &s }
	debian12 := &model.Distro{ID: "debian", VersionID: "12", Codename: "bookworm"}
	rebuild := &model.FixAction{Kind: model.FixKindRebuild, Key: "rebuild:debian:12", Label: "debian 12 rebuild", Distro: debian12}

	upgrade := model.Finding{Fix: rebuild, Suggestion: &model.Suggestion{Repo: "docker.io/library/nginx", FromTag: "1.30.6", ToTag: "1.30.7",
		Tier: model.TierPatch, Introduces: map[model.Priority]int{model.PriorityHigh: 1}}}
	require.Equal(t, apigen.FixAction{Kind: apigen.FixKindUpgrade, Key: "upgrade:docker.io/library/nginx:1.30.7", Label: "nginx:1.30.7",
		Repo: str("docker.io/library/nginx"), FromTag: str("1.30.6"), ToTag: str("1.30.7"), Tier: str("patch"),
		Introduces: &apigen.PriorityCounts{Urgent: 0, High: 1, Medium: 0, Low: 0}}, fixActionOf(upgrade))

	require.Equal(t, apigen.FixAction{Kind: apigen.FixKindRebuild, Key: "rebuild:debian:12", Label: "debian 12 rebuild",
		Title: str("Rebuild to pick up distro fixes")}, fixActionOf(model.Finding{Fix: rebuild}))

	pkg := model.Finding{FixAvailable: true, Fix: &model.FixAction{Kind: model.FixKindPackage, Key: "package:binary:php-cli:8.3.14:8.3.15",
		Label: "php-cli 8.3.14 → 8.3.15", Package: "php-cli", Ecosystem: "binary", From: "8.3.14", To: "8.3.15"}}
	require.Equal(t, apigen.FixAction{Kind: apigen.FixKindPackage, Key: "package:binary:php-cli:8.3.14:8.3.15", Label: "php-cli 8.3.14 → 8.3.15",
		Package: str("php-cli"), Ecosystem: str("binary"), From: str("8.3.14"), To: str("8.3.15")}, fixActionOf(pkg))

	require.Equal(t, apigen.FixAction{Kind: apigen.FixKindWontfix, Key: "wontfix", Label: "Won't fix"},
		fixActionOf(model.Finding{FixState: model.FixWontFix}))
	require.Equal(t, apigen.FixAction{Kind: apigen.FixKindNone, Key: "none", Label: "No fix yet"},
		fixActionOf(model.Finding{FixState: model.FixNotFixed}))

	require.Equal(t, apigen.PriorityNone, priorityOf(model.PriorityNone))
	require.Equal(t, apigen.PriorityUrgent, priorityOf(model.PriorityUrgent))
	require.Equal(t, model.PriorityUrgent, modelPriority(apigen.PriorityUrgent))
	require.Equal(t, model.PriorityNone, modelPriority(apigen.PriorityNone))
}

func TestConvert_SharedShapes(t *testing.T) {
	str := func(s string) *string { return &s }
	require.Equal(t, apigen.PriorityCounts{Urgent: 1, High: 2, Medium: 3, Low: 4},
		priorityCounts(store.PriorityCounts{Urgent: 1, High: 2, Medium: 3, Low: 4}))
	require.Equal(t, apigen.PriorityCounts{High: 2, Low: 1},
		countsOfMap(map[model.Priority]int{model.PriorityHigh: 2, model.PriorityLow: 1, model.PriorityNone: 7}))
	require.Equal(t, apigen.CoverageFigure{InUse: 10, SeenInto: 6, Full: 4}, coverageFigure(store.CoverageFigure{InUse: 10, SeenInto: 6, Full: 4}))

	require.Equal(t, apigen.WorkloadRef{Scope: "workload:Deployment/shop/web", Kind: "Deployment", Namespace: "shop", Name: "web"},
		workloadRef(model.OwnerRef{Kind: "Deployment", Namespace: "shop", Name: "web", UID: "u1"}))
	require.Equal(t, apigen.WorkloadRef{Scope: "workload:Cluster//test", Kind: "Cluster", Namespace: "", Name: "test"},
		workloadRef(model.OwnerRef{Kind: "Cluster", Name: "test"}))
	require.Equal(t, apigen.ScopeRef{Scope: "namespace:shop", Kind: apigen.ScopeKindNamespace, Label: "shop"},
		scopeRef(model.Scope{Kind: model.ScopeNamespace, Value: "shop"}, "shop"))
	require.Equal(t, apigen.ScopeRef{Scope: "cluster", Kind: apigen.ScopeKindCluster, Label: "test"},
		scopeRef(model.Scope{Kind: model.ScopeCluster}, "test"))

	require.Nil(t, managedBy(nil))
	require.Equal(t, &apigen.ManagedBy{Tool: "helm", Name: "web", Namespace: str("shop")},
		managedBy(&model.ManagedBy{Tool: "helm", Name: "web", Namespace: "shop"}))
	require.Equal(t, &apigen.ManagedBy{Tool: "argocd", Name: "web"}, managedBy(&model.ManagedBy{Tool: "argocd", Name: "web"}))

	at := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	sg := suggestionOf(model.Suggestion{Repo: "ghcr.io/example/worker", FromTag: "2.1.0", Tier: model.TierNone, ComputedAt: at,
		Alternatives: []model.Suggestion{{Repo: "ghcr.io/example/worker", FromTag: "2.1.0", ToTag: "3.0.0", Tier: model.TierMajor,
			Fixes: map[model.Priority]int{model.PriorityMedium: 1}, FixedIDs: []string{"CVE-2026-0004"}}}})
	require.Equal(t, "none", sg.Tier)
	require.Equal(t, []string{}, sg.FixedIds)
	require.Equal(t, []string{}, sg.Notes)
	require.Nil(t, sg.ToDigest)
	require.Equal(t, &at, sg.ComputedAt)
	require.Len(t, sg.Alternatives, 1)
	require.Equal(t, apigen.PriorityCounts{Medium: 1}, sg.Alternatives[0].Fixes)
	require.Equal(t, []string{"CVE-2026-0004"}, sg.Alternatives[0].FixedIds)
	require.Equal(t, []apigen.Suggestion{}, sg.Alternatives[0].Alternatives)
	require.Nil(t, sg.Alternatives[0].ComputedAt)

	require.Equal(t, []apigen.Signal{}, signalsOf(model.Finding{}))
	require.Equal(t, []apigen.Signal{apigen.SignalExposed, apigen.SignalExploited, apigen.SignalProvisional, apigen.SignalEpss},
		signalsOf(model.Finding{Provisional: true, Signals: model.FindingSignals{Exposed: true, KEV: true, EPSSElevated: true}}))

	require.Equal(t, []apigen.FindingPackage{
		{Name: "openssl", Ecosystem: "deb", Installed: "3.0.15-1~deb12u1", Fixed: []string{"3.0.16-1~deb12u1"}},
		{Name: "traefik", Ecosystem: "binary", Installed: "3.2.0", Path: str("/usr/local/bin/traefik"), Fixed: []string{}},
	}, findingPackages([]model.FindingPackage{
		{Name: "openssl", Ecosystem: "deb", Installed: "3.0.15-1~deb12u1", Fixed: []string{"3.0.16-1~deb12u1"}},
		{Name: "traefik", Ecosystem: "binary", Installed: "3.2.0", Path: "/usr/local/bin/traefik"},
	}))
	require.Equal(t, []apigen.FindingPackage{}, findingPackages(nil))

	eolDate := time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)
	require.Equal(t, apigen.EOL{Product: "kubernetes", Cycle: "1.34", EolDate: "2026-10-27", IsEol: true, Latest: "1.34.13",
		Text: "kubernetes 1.34 reached end of life 2026-10-27"},
		eolOf(eol.Status{Product: "kubernetes", Cycle: "1.34", EOLDate: &eolDate, IsEOL: true, Latest: "1.34.13"}, at))
	// F105: a status with no date still has text, its labelled note or "supported".
	require.Equal(t, apigen.EOL{Product: "alpine", Cycle: "rolling", Note: "rolling release", Text: "Alpine Linux: rolling release"},
		eolOf(eol.Status{Product: "alpine", Label: "Alpine Linux", Cycle: "rolling", Note: "rolling release"}, at))
	require.Equal(t, apigen.EOL{Product: "debian", Cycle: "13", Text: "Debian 13 supported"},
		eolOf(eol.Status{Product: "debian", Label: "Debian", Cycle: "13"}, at))
}

func TestImagePackageRow_InstalledForm(t *testing.T) {
	rpm := model.Package{Ecosystem: "rpm", Name: "openssl-libs", Epoch: "1", Version: "3.0.7-27.el9"}
	got := imagePackageRow(store.ImagePackageRow{Package: rpm, Findings: 2, Worst: model.PriorityHigh})
	require.Equal(t, "1:3.0.7-27.el9", got.Version, "the epoch-prefixed form findings record")
	require.Equal(t, rpm.Installed(), got.Version)
	require.Equal(t, 2, got.Findings)
	require.Equal(t, apigen.PriorityHigh, got.Worst)
}

func TestFreshness_StaleFeedsAndOldestSuccess(t *testing.T) {
	ctx := t.Context()
	st, err := store.Open(ctx, t.TempDir()+"/ffs.db")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	now := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	require.NoError(t, st.PutFeedState(ctx, store.FeedState{Name: "osv", LastSuccess: now.Add(-10 * time.Minute)}))
	require.NoError(t, st.PutFeedState(ctx, store.FeedState{Name: "kev", LastSuccess: now.Add(-30 * time.Hour)}))
	s := New(Options{Store: st, Now: func() time.Time { return now },
		Feeds: []FeedInfo{{Name: "eol", StaleAfter: 72 * time.Hour}, {Name: "kev", StaleAfter: 24 * time.Hour}, {Name: "osv", StaleAfter: 2 * time.Hour}}})

	got, err := s.freshness(ctx)
	require.NoError(t, err)
	oldest := now.Add(-30 * time.Hour)
	require.Equal(t, apigen.FeedFreshness{Fresh: false, Stale: []string{"eol", "kev"}, OldestSuccess: &oldest}, got,
		"eol never succeeded, kev is past its threshold")

	s = New(Options{Store: st, Now: func() time.Time { return now }, Feeds: []FeedInfo{{Name: "osv", StaleAfter: 2 * time.Hour}}})
	got, err = s.freshness(ctx)
	require.NoError(t, err)
	require.True(t, got.Fresh)
	require.Equal(t, []string{}, got.Stale)

	cluster, at := New(Options{Config: config.Config{ClusterName: "test"}, Now: func() time.Time { return now.In(time.FixedZone("x", 3600)) }}).stamp()
	require.Equal(t, "test", cluster)
	require.Equal(t, time.UTC, at.Location())
	require.True(t, now.Equal(at))
}
