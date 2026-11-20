package store

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/findings"
	"github.com/the-it-dept/ffs/internal/model"
)

func TestNamespaceStats_WorkloadNamespaces(t *testing.T) {
	s := newStore(t)
	seedExplorer(t, s)
	stats, err := s.NamespaceStats(ctx)
	require.NoError(t, err)
	var names []string
	byName := map[string]NamespaceStat{}
	for _, n := range stats {
		names = append(names, n.Namespace)
		byName[n.Namespace] = n
	}
	require.Equal(t, []string{"kube-system", "ops", "payments", "shop"}, names)

	web, worker := statsOf(t, s, exWeb.Key()), statsOf(t, s, exWorker.Key())
	shopStats := web
	shopStats.Counts.Urgent += worker.Counts.Urgent
	shopStats.Counts.High += worker.Counts.High
	shopStats.Open += worker.Open
	shopStats.Fixable += worker.Fixable
	require.Equal(t, NamespaceStat{Namespace: "shop", Workloads: 2, Exposed: 1, Stats: shopStats,
		Coverage: CoverageFigure{InUse: 2, SeenInto: 2, Full: 2}}, byName["shop"])
	require.Equal(t, NamespaceStat{Namespace: "ops", Workloads: 3, Exposed: 1,
		Stats:    OwnerStats{Counts: PriorityCounts{Low: 1}, Open: 1},
		Coverage: CoverageFigure{InUse: 3, SeenInto: 1, Full: 1}}, byName["ops"])
	require.Equal(t, CoverageFigure{InUse: 1, SeenInto: 1}, byName["payments"].Coverage)
	require.Equal(t, CoverageFigure{InUse: 1}, byName["kube-system"].Coverage)
	require.Equal(t, OwnerStats{}, byName["kube-system"].Stats)
}

func TestOwnerEntities_ScopesAndLookup(t *testing.T) {
	s := newStore(t)
	seedExplorer(t, s)
	keys := func(es []OwnerEntity) []string {
		out := make([]string, len(es))
		for i, e := range es {
			out[i] = e.Key
		}
		return out
	}
	all, err := s.OwnerEntities(ctx, model.Scope{Kind: model.ScopeCluster})
	require.NoError(t, err)
	require.Equal(t, keysOf(exCoreDNS, exBackup, exExporter, exReport, exAPI, exWeb, exWorker), keys(all))
	ops, err := s.OwnerEntities(ctx, model.Scope{Kind: model.ScopeNamespace, Value: "ops"})
	require.NoError(t, err)
	require.Equal(t, keysOf(exBackup, exExporter, exReport), keys(ops))
	_, err = s.OwnerEntities(ctx, model.Scope{Kind: model.ScopeImage, Value: "sha256:web"})
	require.ErrorIs(t, err, ErrScope)

	cluster, ok, err := s.OwnerEntityOf(ctx, "Cluster//test")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, OwnerEntity{Key: "Cluster//test", Kind: "Cluster", Name: testCluster}, cluster)
	web, ok, err := s.OwnerEntityOf(ctx, exWeb.Key())
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, &model.ManagedBy{Tool: "flux-helmrelease", Name: "web", Namespace: "shop"}, web.Managed)
	_, ok, err = s.OwnerEntityOf(ctx, "Deployment/shop/missing")
	require.NoError(t, err)
	require.False(t, ok)
}

func TestExposureEdges_FromStoredContext(t *testing.T) {
	s := newStore(t)
	seedExplorer(t, s)
	internal := model.ExposureEdge{Entry: model.EntryIngress, EntryName: "internal-nginx", Hostname: "web.internal.example.com",
		Route: "Ingress shop/web-lan", Service: "shop/web:80", Internal: true}
	require.NoError(t, s.UpsertOwner(ctx, uiOwner(exWeb, func(o *model.Owner) {
		o.Context = model.WorkloadContext{Exposed: true, ExposurePaths: []string{exWebEdge.Path}, Exposure: []model.ExposureEdge{exWebEdge, internal}}
	})))
	edges := func(sc model.Scope) []ExposureEdgeRow {
		t.Helper()
		rows, err := s.ExposureEdges(ctx, sc)
		require.NoError(t, err)
		return rows
	}
	public := exWebEdge
	public.Path = ""
	webRows := []ExposureEdgeRow{{OwnerKey: exWeb.Key(), Namespace: "shop", Edge: public}, {OwnerKey: exWeb.Key(), Namespace: "shop", Edge: internal}}
	require.Equal(t, webRows, edges(model.Scope{Kind: model.ScopeWorkload, Value: exWeb.Key()}))
	require.True(t, webRows[1].Edge.Internal)
	require.Empty(t, edges(model.Scope{Kind: model.ScopeNamespace, Value: "payments"}))
	all := edges(model.Scope{Kind: model.ScopeCluster})
	require.Equal(t, append([]ExposureEdgeRow{{OwnerKey: exExporter.Key(), Namespace: "ops", Edge: model.ExposureEdge{Entry: model.EntryHostNetwork}}},
		webRows...), all)
	_, err := s.ExposureEdges(ctx, model.Scope{Kind: model.ScopeImage, Value: "sha256:web"})
	require.ErrorIs(t, err, ErrScope)
}

func TestBestFixes_MostUrgentThenHigh(t *testing.T) {
	s := newStore(t)
	seedExplorer(t, s)
	n := 100
	adv := func() string { n++; return fmt.Sprintf("CVE-2026-%04d", n) }
	pkgFix := func(name string) func(*model.Finding) {
		return func(f *model.Finding) {
			f.FixAvailable = true
			f.Fix = &model.FixAction{Kind: model.FixKindPackage, Key: "package:npm:" + name + ":1.0.0:1.0.1", Label: name + " 1.0.0 → 1.0.1",
				Package: name, Ecosystem: "npm", From: "1.0.0", To: "1.0.1"}
		}
	}
	rebuild := func(f *model.Finding) {
		f.FixAvailable = true
		f.Fix = &model.FixAction{Kind: model.FixKindRebuild, Key: "rebuild:debian:12", Label: "debian 12 rebuild",
			Distro: &model.Distro{ID: "debian", VersionID: "12"}}
	}
	noFix := func(f *model.Finding) { f.FixState = model.FixNotFixed }
	const webRepo = "ghcr.io/example/web"
	up1, up2 := uiFinding(exWeb, webRepo, adv(), model.PriorityUrgent), uiFinding(exWeb, webRepo, adv(), model.PriorityUrgent)
	fs := []model.Finding{up1, up2, uiFinding(exWeb, webRepo, adv(), model.PriorityUrgent, rebuild)}
	for range 5 {
		fs = append(fs, uiFinding(exWeb, webRepo, adv(), model.PriorityHigh, rebuild))
	}
	for range 3 {
		fs = append(fs, uiFinding(exWeb, webRepo, adv(), model.PriorityUrgent, noFix))
	}
	fs = append(fs,
		uiFinding(exAPI, "ghcr.io/example/api", adv(), model.PriorityHigh, pkgFix("a")),
		uiFinding(exAPI, "ghcr.io/example/api", adv(), model.PriorityLow, pkgFix("a")),
		uiFinding(exAPI, "ghcr.io/example/api", adv(), model.PriorityLow, pkgFix("a")),
		uiFinding(exAPI, "ghcr.io/example/api", adv(), model.PriorityHigh, pkgFix("b")),
		uiFinding(exBackup, "ghcr.io/example/backup", adv(), model.PriorityHigh, pkgFix("y")),
		uiFinding(exBackup, "ghcr.io/example/backup", adv(), model.PriorityHigh, pkgFix("x")),
	)
	apply(t, s, fs...)
	require.NoError(t, s.PutSuggestion(ctx, exWeb.Key(), model.Suggestion{Repo: webRepo, FromTag: "1.0.0", ToTag: "1.0.1", Tier: model.TierPatch,
		FixedIDs: []string{up1.AdvisoryID, up2.AdvisoryID}}, nil))

	got, err := s.BestFixes(ctx, keysOf(exWeb, exAPI, exWorker, exBackup))
	require.NoError(t, err)
	require.Len(t, got, 3)
	require.NotContains(t, got, exWorker.Key())

	web := got[exWeb.Key()]
	require.Equal(t, "upgrade:"+webRepo+":1.0.1", web.Key)
	require.Equal(t, model.FixKindUpgrade, web.Kind)
	require.Equal(t, PriorityCounts{Urgent: 2}, web.Clears)
	require.Equal(t, 2, web.Findings)
	require.Equal(t, model.PriorityUrgent, web.Sample.Priority)
	require.Contains(t, []string{up1.Fingerprint, up2.Fingerprint}, web.Sample.Fingerprint)
	require.NotNil(t, web.Sample.Suggestion)

	api := got[exAPI.Key()]
	require.Equal(t, "package:npm:a:1.0.0:1.0.1", api.Key)
	require.Equal(t, model.FixKindPackage, api.Kind)
	require.Equal(t, PriorityCounts{High: 1, Low: 2}, api.Clears)
	require.Equal(t, 3, api.Findings)
	require.Equal(t, model.PriorityHigh, api.Sample.Priority, "the sample is the group's highest-priority finding")

	backup := got[exBackup.Key()]
	require.Equal(t, "package:npm:x:1.0.0:1.0.1", backup.Key, "equal on every count: the smaller key")
	require.Equal(t, "package:npm:x:1.0.0:1.0.1", backup.Sample.Fix.Key)

	none, err := s.BestFixes(ctx, nil)
	require.NoError(t, err)
	require.Empty(t, none)

	// the aggregate reads only findings_fix: no row read and no JSON decoded per finding
	requireIndexOnly(t, s, "findings_fix", stmt{query: bestFixesQuery, args: []any{idList(keysOf(exWeb, exAPI, exWorker, exBackup))}},
		"best fixes")
}

func TestCoverage_ScopesAndImages(t *testing.T) {
	s := newStore(t)
	seedExplorer(t, s)
	cov := func(sc model.Scope) CoverageFigure {
		t.Helper()
		c, err := s.CoverageOf(ctx, sc)
		require.NoError(t, err)
		return c
	}
	// web, worker and backup are full and api is partial; node-exporter (pending), report
	// (unresolvable) and coredns (no row) are not seen into; nodegroup:g1 and the synthetic digests
	// are not container images
	require.Equal(t, CoverageFigure{InUse: 7, SeenInto: 4, Full: 3}, cov(model.Scope{Kind: model.ScopeCluster}))
	require.Equal(t, CoverageFigure{InUse: 2, SeenInto: 2, Full: 2}, cov(model.Scope{Kind: model.ScopeNamespace, Value: "shop"}))
	require.Equal(t, CoverageFigure{InUse: 3, SeenInto: 1, Full: 1}, cov(model.Scope{Kind: model.ScopeNamespace, Value: "ops"}))
	require.Equal(t, CoverageFigure{InUse: 1, SeenInto: 1}, cov(model.Scope{Kind: model.ScopeWorkload, Value: exAPI.Key()}))
	require.Equal(t, CoverageFigure{InUse: 1, SeenInto: 1, Full: 1}, cov(model.Scope{Kind: model.ScopeImage, Value: "sha256:web"}))
	require.Equal(t, CoverageFigure{InUse: 1, SeenInto: 1}, cov(model.Scope{Kind: model.ScopeImage, Value: "sha256:api"}))
	require.Equal(t, CoverageFigure{InUse: 1}, cov(model.Scope{Kind: model.ScopeImage, Value: "sha256:norow"}))
	require.Equal(t, CoverageFigure{}, cov(model.Scope{Kind: model.ScopeImage, Value: "sha256:unused"}),
		"a catalogued image no owner runs is neither seen into nor in full: never more than in use")
	_, err := s.CoverageOf(ctx, model.Scope{Kind: model.ScopeControlPlane})
	require.ErrorIs(t, err, ErrScope)

	owners, err := s.OwnerCoverage(ctx, []string{exWeb.Key(), exReport.Key(), "Deployment/shop/missing"})
	require.NoError(t, err)
	require.Equal(t, map[string]CoverageFigure{exWeb.Key(): {InUse: 1, SeenInto: 1, Full: 1}, exReport.Key(): {InUse: 1}}, owners)

	require.NoError(t, s.UpsertOwner(ctx, uiOwner(ref("Deployment", "ops", "api-mirror"), func(o *model.Owner) { o.Containers[0].Digest = "sha256:api" })))
	imgs, err := s.CoverageImages(ctx, model.Scope{Kind: model.ScopeCluster})
	require.NoError(t, err)
	var digests []string
	for _, c := range imgs {
		digests = append(digests, c.Image.Digest)
		require.NotEqual(t, model.CoverageFull, CoverageClassOf(c.Image), c.Image.Digest)
	}
	require.Equal(t, []string{"sha256:api", "sha256:norow", "sha256:node-exporter", placeholderDigest}, digests)
	require.Equal(t, []string{"Deployment/ops/api-mirror", exAPI.Key()}, imgs[0].Owners)
	require.True(t, imgs[0].HasRow)
	require.Equal(t, "attestation", imgs[0].Image.Source)
	require.Equal(t, CoverageImage{Image: model.Image{Digest: "sha256:norow", Repo: "ghcr.io/example/coredns", Platform: explorerPlatform,
		Status: model.ImagePending}, Owners: []string{exCoreDNS.Key()}}, imgs[1])
	require.Equal(t, model.ImagePending, imgs[2].Image.Status)
	require.True(t, imgs[2].HasRow)
	require.Equal(t, model.ImageUnresolvable, imgs[3].Image.Status)
	require.Equal(t, []string{exReport.Key()}, imgs[3].Owners)

	ops, err := s.CoverageImages(ctx, model.Scope{Kind: model.ScopeNamespace, Value: "ops"})
	require.NoError(t, err)
	require.Len(t, ops, 3)
	require.Equal(t, []string{"Deployment/ops/api-mirror"}, ops[0].Owners, "owners in scope only")
	_, err = s.CoverageImages(ctx, model.Scope{Kind: model.ScopeImage, Value: "sha256:web"})
	require.ErrorIs(t, err, ErrScope)
}

func TestImageAndAdvisoryReads(t *testing.T) {
	s := newStore(t)
	seedExplorer(t, s)
	digests, err := s.DigestsOfOwners(ctx, keysOf(exWeb, exCluster))
	require.NoError(t, err)
	require.Equal(t, map[string][]string{exWeb.Key(): {"sha256:web"}, exCluster.Key(): {"k8s:1.35.1"}}, digests)

	require.NoError(t, s.PutTagDigest(ctx, "ghcr.io/example/web", "latest", "sha256:web", t0))
	require.NoError(t, s.PutTagDigest(ctx, "ghcr.io/example/web", "1.2", "sha256:web", t0))
	require.NoError(t, s.PutTagDigest(ctx, "ghcr.io/example/web", "1.1", "sha256:old", t0))
	tags, err := s.TagsOf(ctx, "sha256:web")
	require.NoError(t, err)
	require.Equal(t, []string{"ghcr.io/example/web:1.2", "ghcr.io/example/web:latest"}, tags)

	const id, alias = "CVE-2026-0001", "GHSA-aaaa-bbbb-cccc"
	require.NoError(t, s.UpsertAdvisory(ctx, model.Advisory{ID: id, Aliases: []string{alias}, Title: "t"}))
	vendor := func(m model.Match, sev model.Severity, src string, observed time.Time) model.Match {
		m.VendorSeverity, m.VendorSeveritySource, m.ObservedAt = sev, src, observed
		return m
	}
	seed(t, s,
		vendor(mt("sha256:web", "pkg-a", id, model.SourceGrype), model.SeverityHigh, "debian", t0.Add(-2*time.Hour)),
		vendor(mt("sha256:web", "pkg-b", id, model.SourceGrype), model.SeverityMedium, "debian", t0.Add(-3*time.Hour)),
		vendor(mt("sha256:worker", "pkg-c", id, model.SourceGrype), model.SeverityLow, "ubuntu", t0.Add(-1*time.Hour)),
		mt("sha256:worker", "pkg-d", id, model.SourceOSV),
		vendor(mt("sha256:api", "pkg-e", "CVE-2026-0099", model.SourceGrype), model.SeverityCritical, "debian", t0.Add(-9*time.Hour)),
	)
	for _, q := range []string{id, alias} {
		sev, err := s.AdvisorySeverities(ctx, q)
		require.NoError(t, err)
		require.Equal(t, []SourceSeverity{{"debian", model.SeverityHigh}, {"ubuntu", model.SeverityLow}}, sev, q)
		first, err := s.AdvisoryFirstMatched(ctx, q)
		require.NoError(t, err)
		require.Equal(t, t0.Add(-3*time.Hour), first, q)
	}
	first, err := s.AdvisoryFirstMatched(ctx, "CVE-2026-0404")
	require.NoError(t, err)
	require.True(t, first.IsZero())

	const used = "CVE-2026-0005"
	source := func(src string) func(*model.Finding) { return func(f *model.Finding) { f.SeveritySource = src } }
	resolvedAt := t0.Add(-time.Hour)
	apply(t, s,
		uiFinding(exWeb, "ghcr.io/example/web", used, model.PriorityHigh, source("debian")),
		uiFinding(exWorker, "ghcr.io/example/worker", used, model.PriorityHigh, source("debian")),
		uiFinding(exAPI, "ghcr.io/example/api", used, model.PriorityHigh, source("cna")),
		uiFinding(exBackup, "ghcr.io/example/backup", used, model.PriorityHigh, source("cna"), func(f *model.Finding) {
			f.State, f.ResolvedAt = model.StateResolved, &resolvedAt
		}),
	)
	src, err := s.AdvisorySeverityUsed(ctx, used)
	require.NoError(t, err)
	require.Equal(t, "debian", src, "a resolved finding does not count")
	src, err = s.AdvisorySeverityUsed(ctx, "CVE-2026-0404")
	require.NoError(t, err)
	require.Empty(t, src)
}

func TestJump_PrefixFirstPerKind(t *testing.T) {
	s := newStore(t)
	seedExplorer(t, s)
	require.NoError(t, s.UpsertOwner(ctx, uiOwner(ref("Deployment", "webshop", "legacy-web"))))
	put(t, s, "sha256:web", model.Package{Ecosystem: "deb", Name: "webkit", Version: "1.0"}, model.Package{Ecosystem: "deb", Name: "webkit", Version: "2.0"})
	require.NoError(t, s.ReplaceNodes(ctx, []model.Node{{Name: "worker-1", Ready: true}, {Name: "cp-1", Ready: true}}))

	hits, more, err := s.Jump(ctx, "web", 0)
	require.NoError(t, err)
	require.False(t, more)
	require.Equal(t, []JumpHit{
		{Kind: "workload", ID: exWeb.Key(), Label: "web", Detail: "Deployment · shop", Worst: model.PriorityUrgent, Prefix: true},
		{Kind: "workload", ID: "Deployment/webshop/legacy-web", Label: "legacy-web", Detail: "Deployment · webshop"},
		{Kind: "namespace", ID: "webshop", Label: "webshop", Count: 1, Prefix: true},
		{Kind: "image", ID: "sha256:web", Label: "ghcr.io/example/web", Detail: "sha256:web", Worst: model.PriorityUrgent},
		{Kind: "package", ID: "deb/webkit", Label: "webkit", Detail: "deb", Prefix: true},
	}, hits)

	one, more, err := s.Jump(ctx, "web", 1)
	require.NoError(t, err)
	require.True(t, more, "a second web workload is left out")
	var kinds []string
	for _, h := range one {
		kinds = append(kinds, h.Kind+":"+h.ID)
	}
	require.Equal(t, []string{"workload:" + exWeb.Key(), "namespace:webshop", "image:sha256:web", "package:deb/webkit"}, kinds)

	hits, _, err = s.Jump(ctx, "WORK", 0)
	require.NoError(t, err)
	require.Contains(t, hits, JumpHit{Kind: "node", ID: "worker-1", Label: "worker-1", Prefix: true})
	require.Equal(t, JumpHit{Kind: "workload", ID: exWorker.Key(), Label: "worker", Detail: "Deployment · shop", Prefix: true}, hits[0])
	require.Equal(t, model.PriorityNone, hits[len(hits)-1].Worst)

	require.NoError(t, s.UpsertAdvisory(ctx, model.Advisory{ID: "CVE-2026-0001", Title: "web server overflow"}))
	require.NoError(t, s.UpsertAdvisory(ctx, model.Advisory{ID: "CVE-2026-0003", Title: "api bug"}))
	hits, _, err = s.Jump(ctx, "CVE-2026-000", 0)
	require.NoError(t, err)
	require.Equal(t, []JumpHit{
		{Kind: "advisory", ID: "CVE-2026-0001", Label: "CVE-2026-0001", Detail: "web server overflow", Worst: model.PriorityUrgent, Prefix: true},
		{Kind: "advisory", ID: "CVE-2026-0003", Label: "CVE-2026-0003", Detail: "api bug", Worst: model.PriorityMedium, Prefix: true},
	}, hits)
}

// A prefix hit is never lost to an alphabetical cut: with many labels containing the query, those
// starting with it still come back, before the rest.
func TestJump_PrefixHitsSurviveTheCut(t *testing.T) {
	s := newStore(t)
	for _, name := range []string{"a-kube-1", "a-kube-2", "b-kube-3", "c-kube-4", "d-kube-5", "e-kube-6", "kube-proxy", "kubelet-csr"} {
		require.NoError(t, s.UpsertOwner(ctx, uiOwner(ref("Deployment", "ops", name))))
	}
	hits, more, err := s.Jump(ctx, "kube", 3)
	require.NoError(t, err)
	require.True(t, more)
	var labels []string
	for _, h := range hits {
		if h.Kind == "workload" {
			labels = append(labels, h.Label)
		}
	}
	require.Equal(t, []string{"kube-proxy", "kubelet-csr", "a-kube-1"}, labels)
}

func TestChangeMarks_StableSensitiveAndReadOnly(t *testing.T) {
	s := newStore(t)
	seedExplorer(t, s)
	require.NoError(t, s.ReplaceNodes(ctx, []model.Node{{Name: "worker-1", Ready: true, UpdatedAt: t0}}))
	marks := func() ChangeMarks {
		t.Helper()
		m, err := s.ChangeMarks(ctx)
		require.NoError(t, err)
		return m
	}
	dataVersion := func() int64 {
		t.Helper()
		var v int64
		require.NoError(t, s.wdb.QueryRowContext(ctx, `PRAGMA data_version`).Scan(&v))
		return v
	}
	v := dataVersion()
	before := marks()
	require.Equal(t, before, marks())
	require.Equal(t, v, dataVersion(), "ChangeMarks writes nothing")
	for _, m := range []string{before.Images, before.Feeds, before.Exceptions, before.Suggestions, before.Nodes} {
		require.NotEmpty(t, m)
	}

	fields := map[string]func(ChangeMarks) string{
		"images": func(m ChangeMarks) string { return m.Images }, "feeds": func(m ChangeMarks) string { return m.Feeds },
		"exceptions": func(m ChangeMarks) string { return m.Exceptions }, "suggestions": func(m ChangeMarks) string { return m.Suggestions },
		"nodes": func(m ChangeMarks) string { return m.Nodes },
	}
	step := func(name string, write func()) {
		t.Helper()
		prev := marks()
		write()
		next := marks()
		for field, mark := range fields {
			if field == name {
				require.NotEqual(t, mark(prev), mark(next), name)
			} else {
				require.Equal(t, mark(prev), mark(next), "%s changed the %s mark", name, field)
			}
		}
	}
	step("images", func() {
		require.NoError(t, s.UpsertImage(ctx, model.Image{Digest: "sha256:new", Repo: "ghcr.io/example/new", Status: model.ImagePending}))
	})
	step("feeds", func() {
		require.NoError(t, s.PutFeedState(ctx, FeedState{Name: "osv", LastAttempt: t0, LastError: "timeout"}))
	})
	step("exceptions", func() {
		_, err := s.PutExceptionRule(ctx, findings.ExceptionRule{Namespace: "shop", Name: "accepted", AdvisoryIDs: []string{"CVE-2026-0001"},
			Expires: t0.Add(24 * time.Hour)})
		require.NoError(t, err)
	})
	step("suggestions", func() {
		require.NoError(t, s.PutSuggestion(ctx, exWeb.Key(), model.Suggestion{Repo: "ghcr.io/example/web", FromTag: "1.0.0", ToTag: "1.0.1",
			Tier: model.TierPatch, ComputedAt: t0}, nil))
	})
	step("nodes", func() {
		require.NoError(t, s.ReplaceNodes(ctx, []model.Node{{Name: "worker-1", Ready: false, UpdatedAt: t0}}))
	})

	prev := marks()
	require.NoError(t, s.ReplaceNodes(ctx, []model.Node{{Name: "worker-1", Ready: false, UpdatedAt: t0.Add(time.Minute)}}))
	require.Equal(t, prev, marks(), "a heartbeat that changes only UpdatedAt changes no mark")
}

func TestSBOMDescriptor_StreamsToDescriptor(t *testing.T) {
	s := newStore(t)
	doc := `{"artifacts":[{"name":"a","metadata":{"s":"}{"}}],"source":{},"distro":{},` +
		`"descriptor":{"name":"syft","version":"1.38.0","configuration":{"x":[1,2]}},"schema":{}}`
	require.NoError(t, s.PutSBOM(ctx, "sha256:web", []byte(doc), nil))
	name, version, ok, err := s.SBOMDescriptor(ctx, "sha256:web")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "syft", name)
	require.Equal(t, "1.38.0", version)

	for _, digest := range []string{"k8s:1.35.1", "runtime:containerd@2.2.1", "nodegroup:g1", "sha256:none"} {
		name, version, ok, err := s.SBOMDescriptor(ctx, digest)
		require.NoError(t, err, digest)
		require.False(t, ok, digest)
		require.Empty(t, name+version, digest)
	}

	require.NoError(t, s.PutSBOM(ctx, "sha256:bare", []byte(`{"artifacts":[],"schema":{"version":"16"}}`), nil))
	_, _, ok, err = s.SBOMDescriptor(ctx, "sha256:bare")
	require.NoError(t, err)
	require.False(t, ok, "no descriptor")
	require.NoError(t, s.PutSBOM(ctx, "sha256:broken", []byte(`{"artifacts":[`), nil))
	_, _, _, err = s.SBOMDescriptor(ctx, "sha256:broken")
	require.Error(t, err)
}

// An image whose SBOM is stored but whose first match has not run is not seen into yet: it counts
// as in use only, reads as pending in the images explorer and is a coverage gap, until the match.
func TestCoverage_UnmatchedImagesAreNotSeenInto(t *testing.T) {
	s := newStore(t)
	seedExplorer(t, s)
	cluster := model.Scope{Kind: model.ScopeCluster}
	before, err := s.CoverageOf(ctx, cluster)
	require.NoError(t, err)
	require.NoError(t, s.MarkUnmatched(ctx, "sha256:web", t0))

	after, err := s.CoverageOf(ctx, cluster)
	require.NoError(t, err)
	require.Equal(t, CoverageFigure{InUse: before.InUse, SeenInto: before.SeenInto - 1, Full: before.Full - 1}, after)
	img, err := s.CoverageOf(ctx, model.Scope{Kind: model.ScopeImage, Value: "sha256:web"})
	require.NoError(t, err)
	require.Equal(t, CoverageFigure{InUse: 1}, img)
	owners, err := s.OwnerCoverage(ctx, []string{exWeb.Key()})
	require.NoError(t, err)
	require.Equal(t, CoverageFigure{InUse: 1}, owners[exWeb.Key()])
	nss, err := s.NamespaceStats(ctx)
	require.NoError(t, err)
	for _, n := range nss {
		if n.Namespace == "shop" {
			require.Equal(t, CoverageFigure{InUse: 2, SeenInto: 1, Full: 1}, n.Coverage)
		}
	}
	byOwner, err := s.OwnerImageCoverage(ctx, []string{exWeb.Key()})
	require.NoError(t, err)
	require.Equal(t, []DigestCoverage{{Digest: "sha256:web"}}, byOwner[exWeb.Key()])

	page, err := s.ImagesPage(ctx, ImageQuery{Q: "example/web", Limit: 10})
	require.NoError(t, err)
	require.Len(t, page.Rows, 1)
	require.Equal(t, model.ImagePending, page.Rows[0].Image.Status)
	require.Equal(t, model.CoverageNone, page.Rows[0].Class)
	gaps, err := s.CoverageImages(ctx, cluster)
	require.NoError(t, err)
	require.True(t, slices.ContainsFunc(gaps, func(c CoverageImage) bool {
		return c.Image.Digest == "sha256:web" && c.Image.Status == model.ImagePending
	}), "the unmatched image is a pending gap")

	require.NoError(t, s.MarkMatched(ctx, "sha256:web"))
	matched, err := s.CoverageOf(ctx, cluster)
	require.NoError(t, err)
	require.Equal(t, before, matched)
}

// An image's own coverage figure counts it in use only when an owner runs it.
func TestCoverageOf_ImageInUseOnlyWhenRun(t *testing.T) {
	s := newStore(t)
	seedExplorer(t, s)
	unused, err := s.CoverageOf(ctx, model.Scope{Kind: model.ScopeImage, Value: "sha256:unused"})
	require.NoError(t, err)
	require.Equal(t, CoverageFigure{SeenInto: 1, Full: 1}, unused, "catalogued, but no owner runs it")
	none, err := s.CoverageOf(ctx, model.Scope{Kind: model.ScopeImage, Value: "sha256:nowhere"})
	require.NoError(t, err)
	require.Equal(t, CoverageFigure{}, none)
}

// A fully covered image holding classifier-found packages is listed, so the API can name the
// packages matched against CPE data only; one without them is not.
func TestCoverageImages_ListsFullImagesWithClassifierPackages(t *testing.T) {
	s := newStore(t)
	seedExplorer(t, s)
	put(t, s, "sha256:worker", model.Package{Ecosystem: "binary", Name: "redis-server", Version: "7.4.1", Classifier: "redis-binary",
		Path: "/usr/local/bin/redis-server"})
	put(t, s, "sha256:web", deb("openssl", ""))
	imgs, err := s.CoverageImages(ctx, model.Scope{Kind: model.ScopeNamespace, Value: "shop"})
	require.NoError(t, err)
	require.Len(t, imgs, 1)
	require.Equal(t, "sha256:worker", imgs[0].Image.Digest)
	require.Equal(t, model.CoverageFull, CoverageClassOf(imgs[0].Image))
}

// Each owner's distinct container images, with how far ffs sees into each; synthetic digests are
// left out.
func TestOwnerImageCoverage_DistinctContainerImages(t *testing.T) {
	s := newStore(t)
	seedExplorer(t, s)
	require.NoError(t, s.UpsertOwner(ctx, uiOwner(ref("Deployment", "shop", "web-canary"), func(o *model.Owner) {
		o.Containers = append(o.Containers, model.ContainerUse{Name: "proxy", Digest: "sha256:web"})
	})))
	got, err := s.OwnerImageCoverage(ctx, []string{exWeb.Key(), "Deployment/shop/web-canary", exAPI.Key(), exReport.Key(), exNodes.Key()})
	require.NoError(t, err)
	require.Equal(t, map[string][]DigestCoverage{
		exWeb.Key():                  {{Digest: "sha256:web", SeenInto: true, Full: true}},
		"Deployment/shop/web-canary": {{Digest: "sha256:web", SeenInto: true, Full: true}, {Digest: "sha256:web-canary"}},
		exAPI.Key():                  {{Digest: "sha256:api", SeenInto: true}},
		exReport.Key():               {{Digest: placeholderDigest}},
	}, got)
}
