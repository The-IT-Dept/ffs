package store

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/findings"
	"github.com/the-it-dept/ffs/internal/model"
)

func TestRollups_MatchFindingsAfterEveryWritePath(t *testing.T) {
	s := newStore(t)
	web, worker := ref("Deployment", "shop", "web"), ref("Deployment", "shop", "worker")
	const webRepo, workerRepo = "ghcr.io/example/web", "ghcr.io/example/worker"
	step := func(name string, write func()) {
		t.Helper()
		write()
		require.Empty(t, rollupDrift(t, s), name)
	}
	resolvedAt := t0.Add(-10 * 24 * time.Hour)
	urgent := uiFinding(web, webRepo, "CVE-2026-0001", model.PriorityUrgent, func(f *model.Finding) {
		f.Signals.KEV = true
		f.Digests = []string{"sha256:web-amd", "sha256:web-arm"}
		f.Packages = []model.FindingPackage{{Name: "libssl3", Ecosystem: "deb", Installed: "3.0.15-1"},
			{Name: "openssl", Ecosystem: "deb", Installed: "3.0.15-1"}}
	})
	high := uiFinding(web, webRepo, "CVE-2026-0002", model.PriorityHigh, func(f *model.Finding) { f.FixAvailable = true })
	medium := uiFinding(web, webRepo, "CVE-2026-0003", model.PriorityMedium, func(f *model.Finding) { f.Provisional = true })
	low := uiFinding(worker, workerRepo, "CVE-2026-0004", model.PriorityLow)
	excepted := uiFinding(worker, workerRepo, "CVE-2026-0005", model.PriorityMedium, func(f *model.Finding) {
		f.State, f.ExceptedBy = model.StateExcepted, "shop/accepted"
	})
	resolved := uiFinding(worker, workerRepo, "CVE-2026-0006", model.PriorityHigh, func(f *model.Finding) {
		f.State, f.ResolvedAt = model.StateResolved, &resolvedAt
	})

	bare := uiFinding(ref("CronJob", "ops", "backup"), "ghcr.io/example/backup", "CVE-2026-0007", model.PriorityLow,
		func(f *model.Finding) { f.Digests, f.Packages = nil, nil })

	step("ApplyFindings inserts", func() { apply(t, s, urgent, high, medium, low, excepted, resolved, bare) })
	var bareRows int
	require.NoError(t, s.wdb.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM finding_digests WHERE fingerprint = ?)
		+ (SELECT count(*) FROM finding_packages WHERE fingerprint = ?)`, bare.Fingerprint, bare.Fingerprint).Scan(&bareRows))
	require.Zero(t, bareRows, "a finding with no digests or packages has no digest or package rows")
	require.Equal(t, OwnerStats{Counts: PriorityCounts{Low: 1}, Open: 1}, statsOf(t, s, bare.Owner.Key()))
	require.Equal(t, OwnerStats{Counts: PriorityCounts{Urgent: 1, High: 1, Medium: 1}, Open: 3, Fixable: 1, Exploited: 1, Provisional: 1},
		statsOf(t, s, web.Key()))
	require.Equal(t, OwnerStats{Counts: PriorityCounts{Low: 1}, Open: 1, Excepted: 1}, statsOf(t, s, worker.Key()))

	step("INSERT OR REPLACE changes state, priority, digests and packages", func() {
		u := urgent
		u.State, u.ExceptedBy = model.StateExcepted, "shop/accepted"
		u.Digests, u.Packages = []string{"sha256:web-amd"}, u.Packages[:1]
		w := low
		w.Priority = model.PriorityHigh
		apply(t, s, u, w)
	})
	require.Equal(t, OwnerStats{Counts: PriorityCounts{High: 1, Medium: 1}, Open: 2, Fixable: 1, Provisional: 1, Excepted: 1},
		statsOf(t, s, web.Key()))
	require.Equal(t, OwnerStats{Counts: PriorityCounts{High: 1}, Open: 1, Excepted: 1}, statsOf(t, s, worker.Key()))

	step("PutSuggestion sets Suggestion through json_set", func() {
		require.NoError(t, s.PutSuggestion(ctx, web.Key(), model.Suggestion{Repo: webRepo, FromTag: "1.0.0", ToTag: "1.0.1",
			Tier: model.TierPatch, FixedIDs: []string{high.AdvisoryID}}, nil))
	})
	require.Equal(t, 1, statsOf(t, s, web.Key()).Upgradable)

	step("DeleteSuggestions clears it", func() { require.NoError(t, s.DeleteSuggestions(ctx, web.Key(), nil)) })
	require.Zero(t, statsOf(t, s, web.Key()).Upgradable)

	step("RekeyFindings to a free fingerprint (UPDATE)", func() {
		require.NoError(t, s.RekeyFindings(ctx, []FindingRekey{{OldFingerprint: medium.Fingerprint,
			NewFingerprint: model.FindingFingerprint(testCluster, web, webRepo, "GHSA-2026-0003"), AdvisoryID: "GHSA-2026-0003"}}))
	})
	require.Equal(t, 1, statsOf(t, s, web.Key()).Counts.Medium)

	step("RekeyFindings onto a taken fingerprint (DELETE)", func() {
		require.NoError(t, s.RekeyFindings(ctx, []FindingRekey{{OldFingerprint: low.Fingerprint,
			NewFingerprint: excepted.Fingerprint, AdvisoryID: excepted.AdvisoryID}}))
	})
	require.Equal(t, OwnerStats{Excepted: 1}, statsOf(t, s, worker.Key()))

	step("re-home UPDATE moves fingerprint, owner_key, namespace and data", func() {
		// stands in for the node agent's Store.Rehome
		nodes := ref("Nodes", "", testCluster)
		owner, err := json.Marshal(nodes)
		require.NoError(t, err)
		fp := model.FindingFingerprint(testCluster, nodes, "host", high.AdvisoryID)
		_, err = s.wdb.ExecContext(ctx, `UPDATE findings SET fingerprint = ?, owner_key = 'Nodes//test', namespace = '',
			data = json_set(data, '$.Fingerprint', ?, '$.Owner', json(?), '$.ImageRepo', 'host') WHERE fingerprint = ?`,
			fp, fp, string(owner), high.Fingerprint)
		require.NoError(t, err)
	})
	var kind, ns string
	require.NoError(t, s.wdb.QueryRowContext(ctx, `SELECT owner_kind, namespace FROM owner_stats WHERE owner_key = 'Nodes//test'`).
		Scan(&kind, &ns))
	require.Equal(t, "Nodes", kind)
	require.Empty(t, ns)
	require.Equal(t, OwnerStats{Counts: PriorityCounts{High: 1}, Open: 1, Fixable: 1}, statsOf(t, s, "Nodes//test"))
	require.Equal(t, OwnerStats{Counts: PriorityCounts{Medium: 1}, Open: 1, Provisional: 1, Excepted: 1}, statsOf(t, s, web.Key()))

	step("PruneResolved deletes", func() {
		n, err := s.PruneResolved(ctx, t0)
		require.NoError(t, err)
		require.Equal(t, 1, n)
	})

	step("deleting an owner's last open or excepted finding removes its row", func() {
		_, err := s.wdb.ExecContext(ctx, `DELETE FROM findings WHERE fingerprint = ?`, excepted.Fingerprint)
		require.NoError(t, err)
	})
	got, err := s.OwnerStatsOf(ctx, []string{worker.Key()})
	require.NoError(t, err)
	require.Empty(t, got)
	var rows int
	require.NoError(t, s.wdb.QueryRowContext(ctx, `SELECT count(*) FROM owner_stats WHERE owner_key = ?`, worker.Key()).Scan(&rows))
	require.Zero(t, rows)

	var on int
	require.NoError(t, s.wdb.QueryRowContext(ctx, `PRAGMA recursive_triggers`).Scan(&on))
	require.Equal(t, 1, on)
}

// TestRollups_RehomeKeepsRollups runs the node agent's real Store.Rehome, which moves findings with
// an UPDATE of owner_key and a DELETE, through both arms of its "taken" rule and a free move, and
// checks the trigger-maintained rollups after each call (Review Focus 5).
func TestRollups_RehomeKeepsRollups(t *testing.T) {
	s := newStore(t)
	web, nodes := ref("Deployment", "shop", "web"), model.NodesOwner(testCluster)
	const webRepo = "ghcr.io/example/web"
	group := model.NodeGroupDigestPrefix + "g1"
	resolvedAt := t0.Add(-10 * 24 * time.Hour)
	hostFP := func(adv string) string { return model.FindingFingerprint(testCluster, nodes, model.HostRepo, adv) }
	onHost := func(adv string, st model.FindingState, p model.Priority) model.Finding {
		return uiFinding(nodes, model.HostRepo, adv, p, func(f *model.Finding) {
			f.State, f.Digests = st, []string{group}
			if st == model.StateResolved {
				f.ResolvedAt = &resolvedAt
			}
		})
	}
	free := uiFinding(web, webRepo, "CVE-2026-0001", model.PriorityUrgent, func(f *model.Finding) {
		f.Signals.KEV, f.FixAvailable = true, true
	})
	overResolved := uiFinding(web, webRepo, "CVE-2026-0002", model.PriorityHigh, func(f *model.Finding) {
		f.FixAvailable = true
		f.Digests = []string{"sha256:web-amd", "sha256:web-arm"}
		f.Packages = []model.FindingPackage{{Name: "libssl3", Ecosystem: "deb", Installed: "3.0.15-1"},
			{Name: "openssl", Ecosystem: "deb", Installed: "3.0.15-1"}}
	})
	resolvedTarget := onHost("CVE-2026-0002", model.StateResolved, model.PriorityMedium)
	overOpen := uiFinding(web, webRepo, "CVE-2026-0003", model.PriorityMedium, func(f *model.Finding) { f.Provisional = true })
	openTarget := onHost("CVE-2026-0003", model.StateOpen, model.PriorityLow)
	apply(t, s, free, overResolved, resolvedTarget, overOpen, openTarget)
	require.Empty(t, rollupDrift(t, s), "before the re-home")
	require.Equal(t, OwnerStats{Counts: PriorityCounts{Low: 1}, Open: 1}, statsOf(t, s, nodes.Key()))

	nodesOwner := model.Owner{Ref: nodes, Containers: []model.ContainerUse{{Name: "g1", Kind: model.ContainerRegular,
		ImageRef: "g1", Repo: model.HostRepo, Digest: group}}}
	move := func(f model.Finding) FindingMove {
		return FindingMove{OldFingerprint: f.Fingerprint, NewFingerprint: hostFP(f.AdvisoryID), Owner: nodes, ImageRepo: model.HostRepo}
	}
	rowsOf := func(fp string) (digests, packages int) {
		t.Helper()
		require.NoError(t, s.wdb.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM finding_digests WHERE fingerprint = ?),
			(SELECT count(*) FROM finding_packages WHERE fingerprint = ?)`, fp, fp).Scan(&digests, &packages))
		return digests, packages
	}

	// The target holds a resolved row: Rehome deletes it and the moved row takes its fingerprint.
	require.NoError(t, s.Rehome(ctx, &nodesOwner, []FindingMove{move(overResolved)}, nil))
	require.Empty(t, rollupDrift(t, s), "a resolved target is replaced")
	require.Equal(t, OwnerStats{Counts: PriorityCounts{High: 1, Low: 1}, Open: 2, Fixable: 1}, statsOf(t, s, nodes.Key()))
	require.Equal(t, OwnerStats{Counts: PriorityCounts{Urgent: 1, Medium: 1}, Open: 2, Fixable: 1, Exploited: 1, Provisional: 1},
		statsOf(t, s, web.Key()))
	d, p := rowsOf(hostFP(overResolved.AdvisoryID))
	require.Equal(t, 2, d, "the moved row's two digests replace the resolved row's one")
	require.Equal(t, 2, p)
	d, p = rowsOf(overResolved.Fingerprint)
	require.Zero(t, d+p, "nothing is left under the old fingerprint")

	// The target holds an open row: Rehome keeps it and deletes the moved row.
	require.NoError(t, s.Rehome(ctx, &nodesOwner, []FindingMove{move(overOpen)}, nil))
	require.Empty(t, rollupDrift(t, s), "a taken target keeps its row")
	require.Equal(t, OwnerStats{Counts: PriorityCounts{High: 1, Low: 1}, Open: 2, Fixable: 1}, statsOf(t, s, nodes.Key()))
	require.Equal(t, OwnerStats{Counts: PriorityCounts{Urgent: 1}, Open: 1, Fixable: 1, Exploited: 1}, statsOf(t, s, web.Key()))
	d, p = rowsOf(overOpen.Fingerprint)
	require.Zero(t, d+p)
	d, _ = rowsOf(hostFP(overOpen.AdvisoryID))
	require.Equal(t, 1, d, "the kept target still has its own digest row")

	// A free fingerprint, with the old owner dropped: its owner_stats row goes with its last finding.
	require.NoError(t, s.Rehome(ctx, &nodesOwner, []FindingMove{move(free)}, []string{web.Key()}))
	require.Empty(t, rollupDrift(t, s), "a move to a free fingerprint")
	require.Equal(t, OwnerStats{Counts: PriorityCounts{Urgent: 1, High: 1, Low: 1}, Open: 3, Fixable: 2, Exploited: 1},
		statsOf(t, s, nodes.Key()))
	got, err := s.OwnerStatsOf(ctx, []string{web.Key()})
	require.NoError(t, err)
	require.Empty(t, got)
	var kind, ns string
	require.NoError(t, s.wdb.QueryRowContext(ctx, `SELECT owner_kind, namespace FROM owner_stats WHERE owner_key = ?`, nodes.Key()).
		Scan(&kind, &ns))
	require.Equal(t, model.OwnerKindNodes, kind)
	require.Empty(t, ns)
}

func TestReadModelColumns_MatchModel(t *testing.T) {
	s := newStore(t)
	web, cluster := ref("Deployment", "shop", "web"), ref("Cluster", "", testCluster)
	const repo = "ghcr.io/example/web"
	aest := time.FixedZone("AEST", 10*60*60)
	rebuild := &model.FixAction{Kind: model.FixKindRebuild, Key: "rebuild:debian:12", Label: "debian 12 rebuild",
		Distro: &model.Distro{ID: "debian", VersionID: "12"}}
	pkgFix := &model.FixAction{Kind: model.FixKindPackage, Key: "package:npm:lodash:4.17.20:4.17.21", Label: "lodash 4.17.20 → 4.17.21",
		Package: "lodash", Ecosystem: "npm", From: "4.17.20", To: "4.17.21"}
	fs := []model.Finding{
		uiFinding(web, repo, "CVE-2026-0001", model.PriorityUrgent, func(f *model.Finding) { // Suggestion wins over Fix
			f.Fix, f.FixAvailable, f.Severity = rebuild, true, model.SeverityCritical
			f.Signals = model.FindingSignals{Exposed: true, KEV: true, EPSSElevated: true, EPSS: 0.42}
		}),
		uiFinding(web, repo, "CVE-2026-0002", model.PriorityHigh, func(f *model.Finding) {
			f.Fix, f.FixAvailable, f.Severity = rebuild, true, model.SeverityHigh
			f.Signals = model.FindingSignals{Privileged: true, PowerfulSA: true, NotRunning: true}
			f.Published = time.Date(2026, 11, 17, 10, 30, 0, 0, aest)
		}),
		uiFinding(web, repo, "CVE-2026-0003", model.PriorityMedium, func(f *model.Finding) {
			f.Fix, f.FixAvailable, f.Severity, f.Provisional = pkgFix, true, model.SeverityMedium, true
			f.Packages = []model.FindingPackage{{Name: "lodash", Ecosystem: "npm", Installed: "4.17.20", Fixed: []string{"4.17.21"}}}
			f.Signals = model.FindingSignals{Malicious: true, EPSS: 0.05}
			f.Published = time.Date(2026, 11, 16, 1, 2, 3, 123456000, time.UTC)
		}),
		uiFinding(web, repo, "CVE-2026-0004", model.PriorityLow, func(f *model.Finding) { // stored before Build set Fix
			f.FixAvailable, f.FixState, f.Severity = true, model.FixFixed, model.SeverityLow
		}),
		uiFinding(web, repo, "CVE-2026-0005", model.PriorityLow, func(f *model.Finding) {
			f.FixState, f.Severity, f.Packages = model.FixWontFix, model.SeverityNegligible, nil
			f.Published = time.Time{}
		}),
		uiFinding(web, repo, "CVE-2026-0006", model.PriorityLow, func(f *model.Finding) {
			f.FixState, f.Severity = model.FixNotFixed, model.SeverityUnknown
			f.Fix = &model.FixAction{Kind: model.FixKindNone, Key: "none", Label: model.FixLabelNone}
		}),
		uiFinding(cluster, "registry.k8s.io/kubernetes", "CVE-2026-0007", model.PriorityHigh, func(f *model.Finding) {
			f.Digests = []string{"k8s:1.35.1"}
			f.Packages = []model.FindingPackage{{Name: "kubernetes", Ecosystem: "kubernetes", Installed: "1.35.1"}}
		}),
	}
	apply(t, s, fs...)
	require.NoError(t, s.PutSuggestion(ctx, web.Key(), model.Suggestion{Repo: repo, FromTag: "1.0.0", ToTag: "1.0.1",
		Tier: model.TierPatch, FixedIDs: []string{"CVE-2026-0001"}}, nil))

	stored, err := s.ListFindings(ctx, FindingFilter{})
	require.NoError(t, err)
	require.Len(t, stored, len(fs))
	classes := map[model.FixClass]bool{}
	for _, f := range stored {
		var (
			ownerKind, imageRepo, ecosystem, fixClass, fixKey, published string
			severity, fixAvailable, signals                              int64
			epss                                                         float64
		)
		require.NoError(t, s.rdb.QueryRowContext(ctx, `SELECT owner_kind, image_repo, ecosystem, severity, fix_available, fix_class, fix_key,
			signals, epss, published FROM findings WHERE fingerprint = ?`, f.Fingerprint).
			Scan(&ownerKind, &imageRepo, &ecosystem, &severity, &fixAvailable, &fixClass, &fixKey, &signals, &epss, &published))
		id := f.AdvisoryID
		require.Equal(t, f.Owner.Kind, ownerKind, id)
		require.Equal(t, f.ImageRepo, imageRepo, id)
		wantEco := ""
		if len(f.Packages) > 0 {
			wantEco = f.Packages[0].Ecosystem
		}
		require.Equal(t, wantEco, ecosystem, id)
		require.Equal(t, int64(f.Severity), severity, id)
		require.Equal(t, f.FixAvailable, fixAvailable == 1, id)
		wantClass := model.FixClassNone
		switch {
		case f.Suggestion != nil:
			wantClass = model.FixClassUpgrade
		case f.FixAvailable:
			wantClass = model.FixClassFixed
		case f.FixState == model.FixWontFix:
			wantClass = model.FixClassWontFix
		}
		classes[wantClass] = true
		require.Equal(t, string(wantClass), fixClass, id)
		require.Equal(t, f.EffectiveFix().Key, fixKey, id)
		require.Equal(t, f.SignalBits(), signals, id)
		require.InDelta(t, f.Signals.EPSS, epss, 0, id)
		require.Equal(t, f.Published.UTC().Format("2006-01-02T15:04:05.000Z"), published, id)
	}
	require.Len(t, classes, 4, "every fix class is covered")
	upgrade := byAdvisoryID(t, stored, "CVE-2026-0001")
	require.NotNil(t, upgrade.Suggestion)
	require.Equal(t, "upgrade:"+repo+":1.0.1", upgrade.EffectiveFix().Key)
	require.Equal(t, int64(1|8|128), upgrade.SignalBits())
	require.Equal(t, "2026-11-17T00:30:00.000Z", byAdvisoryID(t, stored, "CVE-2026-0002").Published.UTC().Format("2006-01-02T15:04:05.000Z"))

	// images: kind and coverage class
	for _, img := range []model.Image{
		{Digest: "k8s:1.35.1", Repo: "kubernetes", Status: model.ImageCatalogued},
		{Digest: "runtime:containerd@2.2.1", Repo: "containerd", Status: model.ImageCatalogued},
		{Digest: "nodegroup:g1", Repo: "host", Status: model.ImageCatalogued, Source: "agent"},
		{Digest: "sha256:x", Repo: "ghcr.io/example/x", Status: model.ImageCatalogued, Source: "registry"},
		{Digest: "sha256:attested", Repo: "ghcr.io/example/a", Status: model.ImageCatalogued, Source: "attestation"},
		{Digest: "sha256:elf", Repo: "ghcr.io/example/e", Status: model.ImageCatalogued, Source: "registry",
			Coverage: model.Coverage{UnattributedELF: 3}},
		{Digest: "sha256:rust", Repo: "ghcr.io/example/r", Status: model.ImageCatalogued, Source: "registry",
			Coverage: model.Coverage{RustWithoutAuditable: 1}},
		{Digest: "sha256:pending", Repo: "ghcr.io/example/p", Status: model.ImagePending},
		{Digest: "sha256:unresolvable", Repo: "ghcr.io/example/u", Status: model.ImageUnresolvable, StatusReason: "unauthorized"},
		{Digest: "sha256:failed", Repo: "ghcr.io/example/f", Status: model.ImageCatalogFailed},
	} {
		require.NoError(t, s.UpsertImage(ctx, img))
	}
	wantImages := map[string][2]string{
		"k8s:1.35.1": {"synthetic", "full"}, "runtime:containerd@2.2.1": {"synthetic", "full"}, "nodegroup:g1": {"host", "full"},
		"sha256:x": {"container", "full"}, "sha256:attested": {"container", "partial"}, "sha256:elf": {"container", "partial"},
		"sha256:rust": {"container", "partial"}, "sha256:pending": {"container", "none"},
		"sha256:unresolvable": {"container", "none"}, "sha256:failed": {"container", "none"},
	}
	rows, err := s.rdb.QueryContext(ctx, `SELECT digest, image_kind, cov_class FROM images`)
	require.NoError(t, err)
	gotImages := map[string][2]string{}
	for rows.Next() {
		var digest, kind, class string
		require.NoError(t, rows.Scan(&digest, &kind, &class))
		gotImages[digest] = [2]string{kind, class}
	}
	require.NoError(t, rows.Err())
	require.NoError(t, rows.Close())
	require.Equal(t, wantImages, gotImages)
	for digest, want := range wantImages {
		img, ok, err := s.GetImage(ctx, digest)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, model.CoverageClass(want[1]), CoverageClassOf(img), digest)
	}

	// transitions: owner key and namespace
	require.NoError(t, s.ApplyFindings(ctx, nil, []model.Transition{
		{Fingerprint: fs[0].Fingerprint, Owner: web, AdvisoryID: "CVE-2026-0001", ToState: model.StateOpen, Trigger: model.TriggerNewAdvisory, At: t0},
		{Fingerprint: fs[6].Fingerprint, Owner: cluster, AdvisoryID: "CVE-2026-0007", ToState: model.StateOpen, Trigger: model.TriggerNewAdvisory, At: t0},
	}))
	trs, err := queryAll(ctx, s.rdb, func(r scanner) ([2]string, error) {
		var v [2]string
		return v, r.Scan(&v[0], &v[1])
	}, `SELECT owner_key, namespace FROM transitions ORDER BY id`)
	require.NoError(t, err)
	require.Equal(t, [][2]string{{"Deployment/shop/web", "shop"}, {"Cluster//test", ""}}, trs)

	// owners: generated columns and the exposure_edges view
	edges := []model.ExposureEdge{
		{Entry: model.EntryGateway, EntryName: "gateway/public", Listener: "https", Hostname: "shop.example.com",
			Route: "HTTPRoute shop/web", Service: "shop/web:8080", Path: "HTTPRoute shop/web on Gateway gateway/public"},
		{Entry: model.EntryLoadBalancer, EntryName: "shop/web-lb", Service: "shop/web-lb", Internal: true},
	}
	require.NoError(t, s.UpsertOwner(ctx, uiOwner(web, func(o *model.Owner) {
		o.ManagedBy = &model.ManagedBy{Tool: "helm", Name: "shop", Namespace: "shop"}
		o.NotRunning = true
		o.Context = model.WorkloadContext{Exposed: true, ExposurePaths: []string{edges[0].Path}, Privileged: true,
			PrivilegeReasons: []string{"privileged"}, PowerfulSA: true, SAReasons: []string{"secrets: get"}, Exposure: edges}
	})))
	worker := ref("Deployment", "shop", "worker")
	require.NoError(t, s.UpsertOwner(ctx, uiOwner(worker)))
	type ownerCols struct {
		kind, name, managedBy                    string
		exposed, privileged, saPower, notRunning bool
	}
	readOwner := func(key string) ownerCols {
		var c ownerCols
		require.NoError(t, s.rdb.QueryRowContext(ctx, `SELECT kind, name, exposed, ctx_privileged, sa_power, not_running, managed_by
			FROM owners WHERE key = ?`, key).Scan(&c.kind, &c.name, &c.exposed, &c.privileged, &c.saPower, &c.notRunning, &c.managedBy))
		return c
	}
	require.Equal(t, ownerCols{kind: "Deployment", name: "web", managedBy: "helm", exposed: true, privileged: true, saPower: true, notRunning: true},
		readOwner(web.Key()))
	require.Equal(t, ownerCols{kind: "Deployment", name: "worker"}, readOwner(worker.Key()))
	gotEdges, err := queryAll(ctx, s.rdb, func(r scanner) (model.ExposureEdge, error) {
		var (
			e     model.ExposureEdge
			entry string
		)
		err := r.Scan(&entry, &e.EntryName, &e.Listener, &e.Hostname, &e.Route, &e.Service, &e.Internal)
		e.Entry = model.EntryKind(entry)
		return e, err
	}, `SELECT entry, entry_name, listener, hostname, route, service, internal FROM exposure_edges WHERE owner_key = ? ORDER BY entry`, web.Key())
	require.NoError(t, err)
	wantEdges := []model.ExposureEdge{edges[0], edges[1]}
	wantEdges[0].Path = "" // the view does not carry Path
	require.Equal(t, wantEdges, gotEdges)
	var workerEdges int
	require.NoError(t, s.rdb.QueryRowContext(ctx, `SELECT count(*) FROM exposure_edges WHERE owner_key = ?`, worker.Key()).Scan(&workerEdges))
	require.Zero(t, workerEdges)
}

func byAdvisoryID(t *testing.T, fs []model.Finding, id string) model.Finding {
	t.Helper()
	for _, f := range fs {
		if f.AdvisoryID == id {
			return f
		}
	}
	t.Fatalf("no finding on %s", id)
	return model.Finding{}
}

func TestOwnerEntities_PrivilegedMatchesBuildContext(t *testing.T) {
	type image struct {
		status model.ImageStatus
		user   string
	}
	catalogued := func(user string) *image { return &image{model.ImageCatalogued, user} }
	cases := []struct {
		name       string
		ctxPriv    bool
		rootUnless bool
		img        *image // nil: no images row
		want       bool
	}{
		{"context privileged, image user 65532", true, false, catalogued("65532"), true},
		{`catalogued ""`, false, true, catalogued(""), true},
		{`catalogued "0"`, false, true, catalogued("0"), true},
		{`catalogued "root"`, false, true, catalogued("root"), true},
		{`catalogued "root:root"`, false, true, catalogued("root:root"), true},
		{`catalogued "0:0"`, false, true, catalogued("0:0"), true},
		{`catalogued "65532"`, false, true, catalogued("65532"), false},
		{`catalogued "nginx"`, false, true, catalogued("nginx"), false},
		{`catalogued "1000:1000"`, false, true, catalogued("1000:1000"), false},
		{`pending ""`, false, true, &image{model.ImagePending, ""}, false},
		{"no images row", false, true, nil, false},
		{`RootUnlessImageUser false, catalogued ""`, false, false, catalogued(""), false},
	}
	s := newStore(t)
	const advisoryID = "CVE-2026-0001"
	for i, tc := range cases {
		r := ref("Deployment", "shop", "app-"+string(rune('a'+i)))
		digest := "sha256:" + r.Name
		o := uiOwner(r, func(o *model.Owner) {
			o.Containers[0].RootUnlessImageUser = tc.rootUnless
			o.Context.Privileged = tc.ctxPriv
		})
		require.NoError(t, s.UpsertOwner(ctx, o), tc.name)
		if tc.img != nil {
			require.NoError(t, s.UpsertImage(ctx, model.Image{Digest: digest, Repo: o.Containers[0].Repo, Status: tc.img.status,
				ConfigUser: tc.img.user}), tc.name)
		}
		// ImageUsers as engine/recompute.go builds it: catalogued rows only.
		users := map[string]string{}
		if img, ok, err := s.GetImage(ctx, digest); err != nil {
			t.Fatal(err)
		} else if ok && img.Status == model.ImageCatalogued {
			users[digest] = img.ConfigUser
		}
		p := model.Package{ID: "pkg-" + r.Name, ImageDigest: digest, Ecosystem: "deb", Name: "openssl", Version: "3.0.13-1"}
		built := findings.Build(findings.BuildInput{
			Cluster:        testCluster,
			Owner:          o,
			Matches:        []model.Match{{ImageDigest: digest, PackageID: p.ID, AdvisoryID: advisoryID, Source: model.SourceGrype, FixState: model.FixNotFixed}},
			Packages:       map[string]model.Package{p.ID: p},
			Advisories:     map[string]model.Advisory{advisoryID: {ID: advisoryID}},
			ImageUsers:     users,
			Now:            t0,
			PriorityConfig: config.Default().Priority,
		})
		require.Len(t, built, 1, tc.name)
		want := built[0].Signals.Privileged
		require.Equal(t, tc.want, want, tc.name)
		var got bool
		require.NoError(t, s.rdb.QueryRowContext(ctx, `SELECT privileged FROM owner_entities WHERE key = ?`, r.Key()).Scan(&got), tc.name)
		require.Equal(t, want, got, tc.name)
	}
}

func TestMigrations_FillRollupsFromExistingFindings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ffs.db")
	old, err := openThrough(ctx, path, "030_findings_rollup.sql")
	require.NoError(t, err)
	var triggers int
	require.NoError(t, old.rdb.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type = 'trigger'`).Scan(&triggers))
	require.Zero(t, triggers)
	web, worker := ref("Deployment", "shop", "web"), ref("Deployment", "shop", "worker")
	const webRepo, workerRepo = "ghcr.io/example/web", "ghcr.io/example/worker"
	resolvedAt := t0.Add(-24 * time.Hour)
	high := uiFinding(web, webRepo, "CVE-2026-0002", model.PriorityHigh, func(f *model.Finding) { f.FixAvailable = true })
	resolved := uiFinding(worker, workerRepo, "CVE-2026-0004", model.PriorityHigh, func(f *model.Finding) {
		f.State, f.ResolvedAt, f.Digests = model.StateResolved, &resolvedAt, []string{"sha256:worker-old"}
	})
	require.NoError(t, old.ApplyFindings(ctx, []model.Finding{
		uiFinding(web, webRepo, "CVE-2026-0001", model.PriorityUrgent, func(f *model.Finding) { f.Signals.KEV = true }),
		high,
		uiFinding(worker, workerRepo, "CVE-2026-0003", model.PriorityMedium, func(f *model.Finding) {
			f.State, f.ExceptedBy = model.StateExcepted, "shop/accepted"
		}),
		resolved,
	}, nil))
	require.NoError(t, old.PutSuggestion(ctx, web.Key(), model.Suggestion{Repo: webRepo, FromTag: "1.0.0", ToTag: "1.0.1",
		Tier: model.TierPatch, FixedIDs: []string{high.AdvisoryID}}, nil))
	require.NoError(t, old.Close())

	s, err := Open(ctx, path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	require.Empty(t, rollupDrift(t, s))
	require.Equal(t, OwnerStats{Counts: PriorityCounts{Urgent: 1, High: 1}, Open: 2, Fixable: 1, Upgradable: 1, Exploited: 1},
		statsOf(t, s, web.Key()))
	require.Equal(t, OwnerStats{Excepted: 1}, statsOf(t, s, worker.Key()))
	var held bool
	require.NoError(t, s.rdb.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM finding_digests WHERE digest = 'sha256:worker-old'
		AND fingerprint = ? AND state = 'resolved')`, resolved.Fingerprint).Scan(&held))
	require.True(t, held, "finding_digests holds the resolved finding too")

	applied, err := queryAll(ctx, s.rdb, scanString, `SELECT name FROM schema_migrations`)
	require.NoError(t, err)
	names, err := migrations.ReadDir("migrations")
	require.NoError(t, err)
	for _, n := range names {
		require.Contains(t, applied, n.Name())
	}
	for _, n := range []string{"050_findings_read_model.sql", "051_finding_rollups.sql", "052_owner_entities.sql",
		"053_image_coverage.sql", "054_transitions_scope.sql"} {
		require.Contains(t, applied, n)
	}

	apply(t, s, uiFinding(worker, workerRepo, "CVE-2026-0005", model.PriorityLow))
	require.Empty(t, rollupDrift(t, s))
	require.Equal(t, OwnerStats{Counts: PriorityCounts{Low: 1}, Open: 1, Excepted: 1}, statsOf(t, s, worker.Key()))
}

func TestScopeStats_EveryScopeKind(t *testing.T) {
	s := newStore(t)
	web, api := ref("Deployment", "shop", "web"), ref("Deployment", "payments", "api")
	cluster, runtime, nodes := ref("Cluster", "", testCluster), ref("ContainerRuntime", "", "containerd"), ref("Nodes", "", testCluster)
	apply(t, s,
		uiFinding(web, "ghcr.io/example/web", "CVE-2026-0001", model.PriorityUrgent),
		uiFinding(web, "ghcr.io/example/web", "CVE-2026-0002", model.PriorityHigh, func(f *model.Finding) { f.FixAvailable = true }),
		uiFinding(web, "ghcr.io/example/web", "CVE-2026-0003", model.PriorityMedium, func(f *model.Finding) {
			f.State, f.ExceptedBy = model.StateExcepted, "shop/accepted"
		}),
		uiFinding(api, "ghcr.io/example/api", "CVE-2026-0004", model.PriorityMedium),
		uiFinding(cluster, "kubernetes", "CVE-2026-0005", model.PriorityHigh, func(f *model.Finding) { f.Digests = []string{"k8s:1.35.1"} }),
		uiFinding(runtime, "containerd", "CVE-2026-0006", model.PriorityLow, func(f *model.Finding) {
			f.Digests = []string{"runtime:containerd@2.2.1"}
		}),
		uiFinding(nodes, "host", "CVE-2026-0007", model.PriorityUrgent, func(f *model.Finding) {
			f.Digests, f.Signals.KEV = []string{"nodegroup:g1"}, true
		}),
	)
	require.NoError(t, s.PutSuggestion(ctx, api.Key(), model.Suggestion{Repo: "ghcr.io/example/api", FromTag: "2.0.0", ToTag: "2.1.0",
		Tier: model.TierMinor, FixedIDs: []string{"CVE-2026-0004"}}, nil))

	stats := func(scope string) OwnerStats {
		t.Helper()
		sc, err := model.ParseScope(scope)
		require.NoError(t, err)
		st, err := s.ScopeStats(ctx, sc)
		require.NoError(t, err, scope)
		return st
	}
	require.Equal(t, OwnerStats{Counts: PriorityCounts{Urgent: 2, High: 2, Medium: 1, Low: 1}, Open: 6, Fixable: 1, Upgradable: 1,
		Exploited: 1, Excepted: 1}, stats("cluster"))
	shop := OwnerStats{Counts: PriorityCounts{Urgent: 1, High: 1}, Open: 2, Fixable: 1, Excepted: 1}
	require.Equal(t, shop, stats("namespace:shop"))
	require.Equal(t, shop, stats("workload:Deployment/shop/web"))
	require.Equal(t, OwnerStats{Counts: PriorityCounts{Medium: 1}, Open: 1, Upgradable: 1}, stats("namespace:payments"))
	require.Equal(t, OwnerStats{Counts: PriorityCounts{High: 1, Low: 1}, Open: 2}, stats("controlplane"))
	require.Equal(t, shop, stats("image:sha256:web"))
	require.Equal(t, OwnerStats{Counts: PriorityCounts{Urgent: 1}, Open: 1, Exploited: 1}, stats("nodegroup:g1"))
	require.Equal(t, OwnerStats{}, stats("namespace:missing"))
	require.Equal(t, OwnerStats{}, stats("image:sha256:missing"))

	_, err := s.ScopeStats(ctx, model.Scope{Kind: model.ScopeNode, Value: "worker-1"})
	require.ErrorIs(t, err, ErrScope)
	_, err = findingScopeWhere(model.Scope{Kind: model.ScopeNode, Value: "worker-1"})
	require.ErrorIs(t, err, ErrScope)
	require.ErrorContains(t, err, "node")

	got, err := s.OwnerStatsOf(ctx, []string{web.Key(), api.Key(), "Deployment/shop/missing"})
	require.NoError(t, err)
	require.Len(t, got, 2)
	require.Equal(t, shop, got[web.Key()])
	require.Equal(t, OwnerStats{}, got["Deployment/shop/missing"])

	require.Equal(t, model.PriorityHigh, PriorityCounts{High: 1}.Worst())
	require.Equal(t, model.PriorityUrgent, PriorityCounts{Urgent: 1, Low: 3}.Worst())
	require.Equal(t, model.PriorityLow, PriorityCounts{Low: 3}.Worst())
	require.Equal(t, model.PriorityNone, PriorityCounts{}.Worst())
	require.Equal(t, 10, PriorityCounts{Urgent: 1, High: 2, Medium: 3, Low: 4}.Total())
}

func TestFindingScopeWhere_Predicates(t *testing.T) {
	s := newStore(t)
	web, cluster := ref("Deployment", "shop", "web"), ref("Cluster", "", testCluster)
	nodes := ref("Nodes", "", testCluster)
	apply(t, s,
		uiFinding(web, "ghcr.io/example/web", "CVE-2026-0001", model.PriorityHigh),
		uiFinding(cluster, "kubernetes", "CVE-2026-0002", model.PriorityHigh, func(f *model.Finding) { f.Digests = []string{"k8s:1.35.1"} }),
		uiFinding(nodes, "host", "CVE-2026-0003", model.PriorityHigh, func(f *model.Finding) { f.Digests = []string{"nodegroup:g1"} }),
	)
	for scope, want := range map[string][]string{
		"cluster":                      {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"},
		"namespace:shop":               {"CVE-2026-0001"},
		"workload:Deployment/shop/web": {"CVE-2026-0001"},
		"image:sha256:web":             {"CVE-2026-0001"},
		"nodegroup:g1":                 {"CVE-2026-0003"},
		"controlplane":                 {"CVE-2026-0002"},
	} {
		sc, err := model.ParseScope(scope)
		require.NoError(t, err)
		w, err := findingScopeWhere(sc)
		require.NoError(t, err, scope)
		got, err := queryAll(ctx, s.rdb, scanString, `SELECT advisory_id FROM findings`+w.String()+` ORDER BY advisory_id`, w.args...)
		require.NoError(t, err, scope)
		require.Equal(t, want, got, scope)
	}
}
