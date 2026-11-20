package store

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

// The explorer fixture: every image is catalogued from a registry with full coverage unless stated.
const (
	placeholderDigest = "unknown:ghcr.io/example/private:1.0"
	explorerPlatform  = "linux/amd64"
)

var (
	exWeb      = ref("Deployment", "shop", "web")
	exWorker   = ref("Deployment", "shop", "worker")
	exAPI      = ref("Deployment", "payments", "api")
	exExporter = ref("DaemonSet", "ops", "node-exporter")
	exBackup   = ref("CronJob", "ops", "backup")
	exReport   = ref("CronJob", "ops", "report")
	exCoreDNS  = ref("Deployment", "kube-system", "coredns")
	exCluster  = ref("Cluster", "", testCluster)
	exRuntime  = ref("ContainerRuntime", "", "containerd")
	exNodes    = ref("Nodes", "", testCluster)
	exWebEdge  = model.ExposureEdge{Entry: model.EntryGateway, EntryName: "gateway/public", Listener: "https", Hostname: "shop.example.com",
		Route: "HTTPRoute shop/web", Service: "shop/web:8080", Path: "HTTPRoute shop/web on Gateway gateway/public"}
)

// seedExplorer stores the explorer fixture:
//   - shop/web on sha256:web: exposed through a Gateway, managed by Flux; open urgent and high
//     findings, the high one fixable;
//   - shop/worker on sha256:worker: no findings;
//   - payments/api on sha256:api: attestation-sourced (partial) with config user "", a container
//     running as the image's user (privileged), and an open medium finding;
//   - ops/node-exporter on sha256:node-exporter: pending, hostNetwork (exposed);
//   - ops/backup on sha256:backup: not running, with an open low finding;
//   - ops/report on the unresolvable placeholder image;
//   - kube-system/coredns on sha256:norow: no images row;
//   - the Cluster, ContainerRuntime and Nodes owners on k8s:1.35.1, runtime:containerd@2.2.1 and
//     nodegroup:g1;
//   - sha256:unused: catalogued, run by no owner.
func seedExplorer(t *testing.T, s *Store) {
	t.Helper()
	on := func(digest, repo string) func(*model.Owner) {
		return func(o *model.Owner) { o.Containers[0].Digest, o.Containers[0].Repo = digest, repo }
	}
	platform := func(o *model.Owner) { o.Containers[0].Platform = explorerPlatform }
	owners := []model.Owner{
		uiOwner(exWeb, platform, func(o *model.Owner) {
			o.Context = model.WorkloadContext{Exposed: true, ExposurePaths: []string{exWebEdge.Path}, Exposure: []model.ExposureEdge{exWebEdge}}
			o.ManagedBy = &model.ManagedBy{Tool: "flux-helmrelease", Name: "web", Namespace: "shop"}
		}),
		uiOwner(exWorker, platform),
		uiOwner(exAPI, platform, func(o *model.Owner) { o.Containers[0].RootUnlessImageUser = true }),
		uiOwner(exExporter, platform, func(o *model.Owner) {
			o.Context = model.WorkloadContext{Exposed: true, ExposurePaths: []string{"hostNetwork"},
				Exposure: []model.ExposureEdge{{Entry: model.EntryHostNetwork, Path: "hostNetwork"}}}
		}),
		uiOwner(exBackup, platform, func(o *model.Owner) { o.NotRunning = true }),
		uiOwner(exReport, platform, on(placeholderDigest, "ghcr.io/example/private")),
		uiOwner(exCoreDNS, platform, func(o *model.Owner) { o.Containers[0].Digest = "sha256:norow" }),
		uiOwner(exCluster, on("k8s:1.35.1", "kubernetes")),
		uiOwner(exRuntime, on("runtime:containerd@2.2.1", "containerd")),
		uiOwner(exNodes, on("nodegroup:g1", "host")),
	}
	for _, o := range owners {
		require.NoError(t, s.UpsertOwner(ctx, o))
	}
	registry := func(name string) model.Image {
		return model.Image{Digest: "sha256:" + name, Repo: "ghcr.io/example/" + name, Platform: explorerPlatform,
			Status: model.ImageCatalogued, Source: "registry", CataloguedAt: t0}
	}
	api := registry("api")
	api.Source = "attestation"
	for _, img := range []model.Image{
		registry("web"), registry("worker"), api, registry("backup"), registry("unused"),
		{Digest: "sha256:node-exporter", Repo: "ghcr.io/example/node-exporter", Platform: explorerPlatform, Status: model.ImagePending},
		{Digest: placeholderDigest, Repo: "ghcr.io/example/private", Status: model.ImageUnresolvable, StatusReason: "unauthorized"},
		{Digest: "k8s:1.35.1", Repo: "kubernetes", Status: model.ImageCatalogued},
		{Digest: "runtime:containerd@2.2.1", Repo: "containerd", Status: model.ImageCatalogued},
		{Digest: "nodegroup:g1", Repo: "host", Status: model.ImageCatalogued, Source: "agent"},
	} {
		require.NoError(t, s.UpsertImage(ctx, img))
	}
	apply(t, s,
		uiFinding(exWeb, "ghcr.io/example/web", "CVE-2026-0001", model.PriorityUrgent),
		uiFinding(exWeb, "ghcr.io/example/web", "CVE-2026-0002", model.PriorityHigh, func(f *model.Finding) { f.FixAvailable = true }),
		uiFinding(exAPI, "ghcr.io/example/api", "CVE-2026-0003", model.PriorityMedium),
		uiFinding(exBackup, "ghcr.io/example/backup", "CVE-2026-0004", model.PriorityLow),
	)
}

func workloadKeys(rows []WorkloadRow) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.Owner.Key
	}
	return out
}

func keysOf(rs ...model.OwnerRef) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.Key()
	}
	return out
}

func TestWorkloadsPage_ListsEntitiesIncludingClean(t *testing.T) {
	s := newStore(t)
	seedExplorer(t, s)
	page, err := s.WorkloadsPage(ctx, WorkloadQuery{Limit: 200})
	require.NoError(t, err)
	require.Equal(t, 7, page.Total)
	require.Len(t, page.Rows, 7)
	rows := map[string]WorkloadRow{}
	for _, r := range page.Rows {
		rows[r.Owner.Key] = r
	}
	for _, k := range keysOf(exCluster, exRuntime, exNodes) {
		require.NotContains(t, rows, k)
	}
	worker := rows[exWorker.Key()]
	require.Equal(t, OwnerStats{}, worker.Stats)
	require.Equal(t, model.PriorityNone, worker.Stats.Counts.Worst())

	web := rows[exWeb.Key()]
	require.Equal(t, OwnerEntity{Key: exWeb.Key(), Kind: "Deployment", Namespace: "shop", Name: "web", ManagedBy: "flux-helmrelease",
		Managed: &model.ManagedBy{Tool: "flux-helmrelease", Name: "web", Namespace: "shop"}, Exposed: true}, web.Owner)
	require.Equal(t, PriorityCounts{Urgent: 1, High: 1}, web.Stats.Counts)
	require.Equal(t, OwnerStats{Counts: PriorityCounts{Urgent: 1, High: 1}, Open: 2, Fixable: 1}, web.Stats)
	require.Equal(t, CoverageFigure{InUse: 1, SeenInto: 1, Full: 1}, web.Coverage)
	require.Equal(t, model.CoverageFull, web.Class)

	api := rows[exAPI.Key()]
	require.True(t, api.Owner.Privileged)
	require.Equal(t, model.CoveragePartial, api.Class)
	require.Equal(t, CoverageFigure{InUse: 1, SeenInto: 1}, api.Coverage)
	for _, k := range keysOf(exReport, exCoreDNS, exExporter) {
		require.Equal(t, model.CoverageNone, rows[k].Class, k)
		require.Equal(t, CoverageFigure{InUse: 1}, rows[k].Coverage, k)
	}
	for k, r := range rows {
		if k != exWeb.Key() {
			require.Nil(t, r.Owner.Managed, k)
			require.Empty(t, r.Owner.ManagedBy, k)
		}
	}
	require.True(t, rows[exBackup.Key()].Owner.NotRunning)
	require.True(t, rows[exExporter.Key()].Owner.Exposed)
}

func TestWorkloadsPage_FiltersSortsAndPages(t *testing.T) {
	s := newStore(t)
	seedExplorer(t, s)
	keys := func(q WorkloadQuery) []string {
		t.Helper()
		q.Limit = 200
		p, err := s.WorkloadsPage(ctx, q)
		require.NoError(t, err)
		require.Equal(t, len(p.Rows), p.Total)
		return workloadKeys(p.Rows)
	}
	sorted := func(q WorkloadQuery) []string { t.Helper(); q.Sort = WorkloadName; return keys(q) }
	require.ElementsMatch(t, keysOf(exExporter, exBackup, exReport), keys(WorkloadQuery{Scope: model.Scope{Kind: model.ScopeNamespace, Value: "ops"}}))
	require.ElementsMatch(t, keysOf(exBackup, exReport), keys(WorkloadQuery{Kinds: []string{"CronJob"}}))
	require.ElementsMatch(t, keysOf(exWeb, exExporter), keys(WorkloadQuery{Signals: []model.Signal{model.SignalExposed}}))
	require.Empty(t, keys(WorkloadQuery{Signals: []model.Signal{model.SignalPrivileged, model.SignalNotRunning}}))
	require.ElementsMatch(t, keysOf(exAPI), keys(WorkloadQuery{Signals: []model.Signal{model.SignalPrivileged, model.SignalExploited}}),
		"signals outside the workload columns are ignored")
	require.ElementsMatch(t, keysOf(exWorker, exExporter, exReport, exCoreDNS), keys(WorkloadQuery{Worst: []model.Priority{model.PriorityNone}}))
	require.ElementsMatch(t, keysOf(exWeb, exAPI), keys(WorkloadQuery{Worst: []model.Priority{model.PriorityUrgent, model.PriorityMedium}}))
	require.ElementsMatch(t, keysOf(exExporter, exReport, exCoreDNS), keys(WorkloadQuery{Coverage: []model.CoverageClass{model.CoverageNone}}))
	require.Equal(t, keysOf(exWeb), keys(WorkloadQuery{Q: "WEB"}))
	require.Equal(t, keysOf(exCoreDNS), sorted(WorkloadQuery{Q: "kube"}), "Q matches the namespace")
	require.Equal(t, keysOf(exBackup, exReport), sorted(WorkloadQuery{Namespaces: []string{"ops"}, Kinds: []string{"CronJob"}}))

	// orders
	rest := keysOf(exBackup, exReport, exExporter, exCoreDNS, exAPI, exWorker) // by key
	require.Equal(t, append(keysOf(exWeb), rest...), keys(WorkloadQuery{}))
	require.Equal(t, append(keysOf(exWeb), rest...), keys(WorkloadQuery{Sort: WorkloadRisk}))
	require.Equal(t, keysOf(exAPI, exBackup, exCoreDNS, exExporter, exReport, exWeb, exWorker), keys(WorkloadQuery{Sort: WorkloadName}))
	require.Equal(t, keysOf(exCoreDNS, exBackup, exExporter, exReport, exAPI, exWeb, exWorker), keys(WorkloadQuery{Sort: WorkloadNamespace}))
	require.Equal(t, keysOf(exWeb, exBackup, exAPI, exReport, exExporter, exCoreDNS, exWorker), keys(WorkloadQuery{Sort: WorkloadFindings}))

	// keyset pages
	for _, sort := range []WorkloadSort{WorkloadRisk, WorkloadName, WorkloadNamespace, WorkloadFindings} {
		var seen []string
		after := ""
		for range 10 {
			p, err := s.WorkloadsPage(ctx, WorkloadQuery{Sort: sort, Limit: 2, After: after})
			require.NoError(t, err)
			require.Equal(t, 7, p.Total)
			seen = append(seen, workloadKeys(p.Rows)...)
			if after = p.Next; after == "" {
				break
			}
		}
		require.Equal(t, keys(WorkloadQuery{Sort: sort}), seen, sort)
	}

	_, err := s.WorkloadsPage(ctx, WorkloadQuery{Scope: model.Scope{Kind: model.ScopeImage, Value: "sha256:web"}})
	require.ErrorIs(t, err, ErrScope)
	first, err := s.WorkloadsPage(ctx, WorkloadQuery{Limit: 2})
	require.NoError(t, err)
	_, err = s.WorkloadsPage(ctx, WorkloadQuery{Sort: WorkloadName, After: first.Next})
	require.ErrorIs(t, err, ErrBadCursor)
}

func TestWorkloadFacets_CountEntities(t *testing.T) {
	s := newStore(t)
	seedExplorer(t, s)
	type fv = FacetValue
	got, err := s.WorkloadFacets(ctx, WorkloadQuery{Signals: []model.Signal{model.SignalExposed}},
		[]string{"kind", "signal", "priority", "coverage"})
	require.NoError(t, err)
	require.Equal(t, []fv{{"DaemonSet", 1}, {"Deployment", 1}}, got["kind"])
	require.Equal(t, []fv{{"exposed", 2}, {"not_running", 1}, {"privileged", 1}, {"sa_power", 0}}, got["signal"])
	require.Equal(t, []fv{{"none", 1}, {"urgent", 1}, {"high", 0}, {"low", 0}, {"medium", 0}}, got["priority"])
	require.Contains(t, got["priority"], fv{Value: "none", Count: 1})
	require.Equal(t, []fv{{"full", 1}, {"none", 1}, {"partial", 0}}, got["coverage"])

	got, err = s.WorkloadFacets(ctx, WorkloadQuery{}, []string{"namespace"})
	require.NoError(t, err)
	require.Equal(t, []fv{{"ops", 3}, {"shop", 2}, {"kube-system", 1}, {"payments", 1}}, got["namespace"])

	got, err = s.WorkloadFacets(ctx, WorkloadQuery{Namespaces: []string{"payments"}, Kinds: []string{"CronJob"}}, []string{"namespace", "kind"})
	require.NoError(t, err)
	require.Equal(t, []fv{{"ops", 2}}, got["namespace"][:1])
	require.Contains(t, got["namespace"], fv{Value: "payments", Count: 0}, "a selected value is listed")
	require.Equal(t, []fv{{"Deployment", 1}, {"CronJob", 0}}, got["kind"])

	_, err = s.WorkloadFacets(ctx, WorkloadQuery{}, []string{"colour"})
	require.ErrorContains(t, err, "colour")
}

func imageDigests(rows []ImageRow) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.Image.Digest
	}
	return out
}

func TestImagesPage_InUseContainerImagesOnly(t *testing.T) {
	s := newStore(t)
	seedExplorer(t, s)
	page, err := s.ImagesPage(ctx, ImageQuery{Limit: 200})
	require.NoError(t, err)
	require.Equal(t, 7, page.Total)
	require.ElementsMatch(t, []string{"sha256:web", "sha256:worker", "sha256:api", "sha256:node-exporter", "sha256:backup",
		placeholderDigest, "sha256:norow"}, imageDigests(page.Rows))
	rows := map[string]ImageRow{}
	for _, r := range page.Rows {
		rows[r.Image.Digest] = r
	}
	norow := rows["sha256:norow"]
	require.Equal(t, model.ImagePending, norow.Image.Status)
	require.Equal(t, "ghcr.io/example/coredns", norow.Image.Repo)
	require.Equal(t, explorerPlatform, norow.Image.Platform)
	require.Equal(t, model.CoverageNone, norow.Class)
	require.Equal(t, 1, norow.Workloads)

	ph := rows[placeholderDigest]
	require.Equal(t, model.ImageUnresolvable, ph.Image.Status)
	require.Equal(t, "unauthorized", ph.Image.StatusReason)
	require.Equal(t, model.CoverageNone, ph.Class)

	web := rows["sha256:web"]
	require.Equal(t, 1, web.Workloads)
	require.Equal(t, PriorityCounts{Urgent: 1, High: 1}, web.Counts)
	require.Equal(t, 1, web.Fixable)
	require.Equal(t, model.CoverageFull, web.Class)
	require.Equal(t, model.ImageCatalogued, web.Image.Status)
	require.Equal(t, t0, web.Image.CataloguedAt)
	require.Equal(t, model.CoveragePartial, rows["sha256:api"].Class)
	require.Equal(t, "attestation", rows["sha256:api"].Image.Source)
}

func TestImagesPage_ScopeFiltersAndSorts(t *testing.T) {
	s := newStore(t)
	seedExplorer(t, s)
	digests := func(q ImageQuery) []string {
		t.Helper()
		q.Limit = 200
		p, err := s.ImagesPage(ctx, q)
		require.NoError(t, err)
		require.Equal(t, len(p.Rows), p.Total)
		return imageDigests(p.Rows)
	}
	require.ElementsMatch(t, []string{"sha256:web", "sha256:worker"}, digests(ImageQuery{Scope: model.Scope{Kind: model.ScopeNamespace, Value: "shop"}}))
	require.Equal(t, []string{"sha256:api"}, digests(ImageQuery{Scope: model.Scope{Kind: model.ScopeWorkload, Value: exAPI.Key()}}))
	require.ElementsMatch(t, []string{"sha256:node-exporter", "sha256:norow"}, digests(ImageQuery{Statuses: []model.ImageStatus{model.ImagePending}}))
	require.Equal(t, []string{"sha256:api"}, digests(ImageQuery{Sources: []string{"attestation"}}))
	require.Equal(t, []string{"sha256:api"}, digests(ImageQuery{Coverage: []model.CoverageClass{model.CoveragePartial}}))
	require.ElementsMatch(t, []string{"sha256:worker", "sha256:node-exporter", placeholderDigest, "sha256:norow"},
		digests(ImageQuery{Worst: []model.Priority{model.PriorityNone}}))
	require.Equal(t, []string{"sha256:web"}, digests(ImageQuery{Q: "example/web"}))
	require.Equal(t, []string{"sha256:web"}, digests(ImageQuery{Q: "sha256:we"}))
	require.ElementsMatch(t, []string{"sha256:node-exporter", "sha256:backup", placeholderDigest}, digests(ImageQuery{Namespaces: []string{"ops"}}))
	_, err := s.ImagesPage(ctx, ImageQuery{Scope: model.Scope{Kind: model.ScopeNodeGroup, Value: "g1"}})
	require.ErrorIs(t, err, ErrScope)

	// a namespace scope counts only that namespace's owners and their findings
	require.NoError(t, s.UpsertOwner(ctx, uiOwner(ref("Deployment", "ops", "web-mirror"), func(o *model.Owner) { o.Containers[0].Digest = "sha256:web" })))
	ops, err := s.ImagesPage(ctx, ImageQuery{Scope: model.Scope{Kind: model.ScopeNamespace, Value: "ops"}, Q: "sha256:web"})
	require.NoError(t, err)
	require.Len(t, ops.Rows, 1)
	require.Equal(t, 1, ops.Rows[0].Workloads)
	require.Equal(t, PriorityCounts{}, ops.Rows[0].Counts, "web's findings belong to shop/web")
	all, err := s.ImagesPage(ctx, ImageQuery{Q: "sha256:web"})
	require.NoError(t, err)
	require.Equal(t, 2, all.Rows[0].Workloads)
	require.Equal(t, PriorityCounts{Urgent: 1, High: 1}, all.Rows[0].Counts)

	// orders
	require.Equal(t, []string{"sha256:web", "sha256:api", "sha256:backup", "sha256:node-exporter", "sha256:norow", "sha256:worker", placeholderDigest},
		digests(ImageQuery{}))
	require.Equal(t, []string{"sha256:api", "sha256:backup", "sha256:norow", "sha256:node-exporter", placeholderDigest, "sha256:web", "sha256:worker"},
		digests(ImageQuery{Sort: ImageRepoSort}))
	require.Equal(t, []string{"sha256:web", "sha256:api", "sha256:backup", "sha256:node-exporter", "sha256:norow", "sha256:worker", placeholderDigest},
		digests(ImageQuery{Sort: ImageWorkloads}))

	for _, sort := range []ImageSort{ImageRisk, ImageRepoSort, ImageWorkloads} {
		var seen []string
		after := ""
		for range 10 {
			p, err := s.ImagesPage(ctx, ImageQuery{Sort: sort, Limit: 1, After: after})
			require.NoError(t, err)
			require.Equal(t, 7, p.Total)
			seen = append(seen, imageDigests(p.Rows)...)
			if after = p.Next; after == "" {
				break
			}
		}
		require.Equal(t, digests(ImageQuery{Sort: sort}), seen, sort)
	}
}

func TestImageFacets_CountImages(t *testing.T) {
	s := newStore(t)
	seedExplorer(t, s)
	require.NoError(t, s.UpsertOwner(ctx, uiOwner(ref("Deployment", "ops", "web-mirror"), func(o *model.Owner) { o.Containers[0].Digest = "sha256:web" })))
	type fv = FacetValue
	got, err := s.ImageFacets(ctx, ImageQuery{}, []string{"status", "source", "coverage", "namespace", "priority"})
	require.NoError(t, err)
	require.Equal(t, []fv{{"catalogued", 4}, {"pending", 2}, {"unresolvable", 1}, {"catalogFailed", 0}}, got["status"])
	require.Equal(t, []fv{{"registry", 3}, {"attestation", 1}}, got["source"])
	require.Equal(t, []fv{{"full", 3}, {"none", 3}, {"partial", 1}}, got["coverage"])
	require.Equal(t, []fv{{"ops", 4}, {"shop", 2}, {"kube-system", 1}, {"payments", 1}}, got["namespace"])
	require.Equal(t, []fv{{"none", 4}, {"low", 1}, {"medium", 1}, {"urgent", 1}, {"high", 0}}, got["priority"])

	// each facet ignores its own selection
	got, err = s.ImageFacets(ctx, ImageQuery{Statuses: []model.ImageStatus{model.ImagePending}, Namespaces: []string{"ops"}},
		[]string{"status", "namespace"})
	require.NoError(t, err)
	require.Equal(t, []fv{{"catalogued", 2}, {"pending", 1}, {"unresolvable", 1}, {"catalogFailed", 0}}, got["status"])
	require.Equal(t, []fv{{"kube-system", 1}, {"ops", 1}}, got["namespace"])

	_, err = s.ImageFacets(ctx, ImageQuery{}, []string{"colour"})
	require.ErrorContains(t, err, "colour")
}

func packageNames(rows []PackageRow) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.Name
	}
	return out
}

func TestPackagesPage_InstalledVersionJoinsFindings(t *testing.T) {
	s := newStore(t)
	seedExplorer(t, s)
	libc6 := model.Package{Ecosystem: "deb", Name: "libc6", Epoch: "1", Version: "2.36-9", Path: "/var/lib/dpkg/status"}
	tzdata := model.Package{Ecosystem: "deb", Name: "tzdata", Version: "2025a", Path: "/var/lib/dpkg/status"}
	bash := model.Package{Ecosystem: "rpm", Name: "bash", Epoch: "1", Version: "1:5.2-1", Path: "/var/lib/rpm"}
	php := model.Package{Ecosystem: "binary", Name: "php", Version: "8.3.14", Classifier: "php-cli-binary", Path: "/usr/local/bin/php"}
	put(t, s, "sha256:web", libc6, tzdata, bash, php)
	put(t, s, "sha256:worker", libc6)
	apply(t, s, uiFinding(exWeb, "ghcr.io/example/web", "CVE-2026-0010", model.PriorityUrgent, func(f *model.Finding) {
		f.Packages = []model.FindingPackage{{Name: "libc6", Ecosystem: "deb", Installed: "1:2.36-9"}}
	}))

	page, err := s.PackagesPage(ctx, PackageEntityQuery{Limit: 200})
	require.NoError(t, err)
	rows := map[string]PackageRow{}
	for _, r := range page.Rows {
		rows[r.Name] = r
	}
	require.Equal(t, 4, page.Total)
	require.Equal(t, PackageRow{Ecosystem: "deb", Name: "libc6", Version: "1:2.36-9", Images: 2, Workloads: 2,
		Counts: PriorityCounts{Urgent: 1}, Worst: model.PriorityUrgent}, rows["libc6"])
	require.Equal(t, "2025a", rows["tzdata"].Version)
	require.Equal(t, model.PriorityNone, rows["tzdata"].Worst)
	require.Equal(t, 1, rows["tzdata"].Images)
	require.Equal(t, "1:5.2-1", rows["bash"].Version)
	require.Equal(t, "php-cli-binary", rows["php"].Classifier)
	require.Equal(t, "libc6", page.Rows[0].Name, "-risk puts the urgent package first")
	for _, p := range []model.Package{libc6, tzdata, bash, php} {
		require.Equal(t, p.Installed(), rows[p.Name].Version, "installedExpr and model.Package.Installed agree on %s", p.Name)
	}
}

func TestPackagesPage_ScopesSortsAndFacets(t *testing.T) {
	s := newStore(t)
	seedExplorer(t, s)
	libc6 := model.Package{Ecosystem: "deb", Name: "libc6", Version: "2.36-9"}
	tzdata := model.Package{Ecosystem: "deb", Name: "tzdata", Version: "2025a"}
	put(t, s, "sha256:web", libc6, tzdata)
	put(t, s, "sha256:worker", libc6, tzdata)
	put(t, s, "sha256:api", model.Package{Ecosystem: "deb", Name: "bash", Version: "5.2-1"})
	put(t, s, "sha256:backup", model.Package{Ecosystem: "binary", Name: "php", Version: "8.3.14", Classifier: "php-cli-binary"})
	apply(t, s, uiFinding(exWeb, "ghcr.io/example/web", "CVE-2026-0010", model.PriorityUrgent, func(f *model.Finding) {
		f.Packages = []model.FindingPackage{{Name: "libc6", Ecosystem: "deb", Installed: "2.36-9"}}
	}))
	pkgs := func(q PackageEntityQuery) []PackageRow {
		t.Helper()
		q.Limit = 200
		p, err := s.PackagesPage(ctx, q)
		require.NoError(t, err)
		require.Equal(t, len(p.Rows), p.Total)
		return p.Rows
	}
	names := func(q PackageEntityQuery) []string { t.Helper(); q.Sort = "name"; return packageNames(pkgs(q)) }
	require.Equal(t, []string{"bash"}, names(PackageEntityQuery{Scope: model.Scope{Kind: model.ScopeImage, Value: "sha256:api"}}))
	worker := pkgs(PackageEntityQuery{Scope: model.Scope{Kind: model.ScopeWorkload, Value: exWorker.Key()}, Sort: "name"})
	require.Equal(t, []string{"libc6", "tzdata"}, packageNames(worker))
	require.Equal(t, PriorityCounts{}, worker[0].Counts, "the worker has no findings on libc6")
	shop := pkgs(PackageEntityQuery{Scope: model.Scope{Kind: model.ScopeNamespace, Value: "shop"}})
	require.Equal(t, "libc6", shop[0].Name)
	require.Equal(t, 2, shop[0].Images)
	require.Equal(t, 2, shop[0].Workloads)
	require.Equal(t, 1, shop[0].Counts.Urgent)
	require.Equal(t, []string{"php"}, names(PackageEntityQuery{Ecosystems: []string{"binary"}}))
	require.Equal(t, []string{"bash", "php", "tzdata"}, names(PackageEntityQuery{Worst: []model.Priority{model.PriorityNone}}))
	require.Equal(t, []string{"libc6"}, names(PackageEntityQuery{Q: "lib"}))
	_, err := s.PackagesPage(ctx, PackageEntityQuery{Scope: model.Scope{Kind: model.ScopeControlPlane}})
	require.ErrorIs(t, err, ErrScope)

	require.Equal(t, []string{"bash", "libc6", "php", "tzdata"}, names(PackageEntityQuery{}))
	require.Equal(t, []string{"libc6", "tzdata", "php", "bash"}, packageNames(pkgs(PackageEntityQuery{Sort: "-images"})))
	require.Equal(t, []string{"libc6", "tzdata", "php", "bash"}, packageNames(pkgs(PackageEntityQuery{})), "-risk: worst, then images")
	for _, sort := range []string{"-risk", "name", "-images"} {
		var seen []string
		after := ""
		for range 10 {
			p, err := s.PackagesPage(ctx, PackageEntityQuery{Sort: sort, Limit: 1, After: after})
			require.NoError(t, err)
			require.Equal(t, 4, p.Total)
			seen = append(seen, packageNames(p.Rows)...)
			if after = p.Next; after == "" {
				break
			}
		}
		require.Equal(t, packageNames(pkgs(PackageEntityQuery{Sort: sort})), seen, sort)
	}
	_, err = s.PackagesPage(ctx, PackageEntityQuery{Sort: "name", After: encodeCursor("packages:-risk", []any{int64(0)})})
	require.ErrorIs(t, err, ErrBadCursor)

	type fv = FacetValue
	got, err := s.PackageFacets(ctx, PackageEntityQuery{}, []string{"ecosystem", "priority"})
	require.NoError(t, err)
	require.Equal(t, []fv{{"deb", 3}, {"binary", 1}}, got["ecosystem"])
	require.Equal(t, []fv{{"none", 3}, {"urgent", 1}, {"high", 0}, {"low", 0}, {"medium", 0}}, got["priority"])
	got, err = s.PackageFacets(ctx, PackageEntityQuery{Ecosystems: []string{"binary"}}, []string{"ecosystem", "priority"})
	require.NoError(t, err)
	require.Equal(t, []fv{{"deb", 3}, {"binary", 1}}, got["ecosystem"], "the ecosystem facet ignores its own selection")
	require.Equal(t, []fv{{"none", 1}, {"high", 0}, {"low", 0}, {"medium", 0}, {"urgent", 0}}, got["priority"])
	_, err = s.PackageFacets(ctx, PackageEntityQuery{}, []string{"colour"})
	require.ErrorContains(t, err, "colour")
}

func TestImagePackages_SearchFindingsAndHostDigests(t *testing.T) {
	s := newStore(t)
	seedExplorer(t, s) // web's urgent and high findings are on deb openssl 3.0.15-1
	put(t, s, "sha256:web",
		model.Package{Ecosystem: "deb", Name: "openssl", Version: "3.0.15-1"},
		model.Package{Ecosystem: "deb", Name: "libssl3", Version: "3.0.15-1"},
		model.Package{Ecosystem: "npm", Name: "lodash", Version: "4.17.20", Path: "/app/node_modules/lodash"})
	apply(t, s, uiFinding(exWeb, "ghcr.io/example/web", "CVE-2026-0011", model.PriorityMedium, func(f *model.Finding) {
		f.Packages = []model.FindingPackage{{Name: "libssl3", Ecosystem: "deb", Installed: "3.0.15-1"}}
	}))
	names := func(p ImagePackagePage) []string {
		out := make([]string, len(p.Rows))
		for i, r := range p.Rows {
			out[i] = r.Package.Name
		}
		return out
	}

	p, err := s.ImagePackages(ctx, "sha256:web", "ssl", nil, "", 50)
	require.NoError(t, err)
	require.Equal(t, []string{"libssl3", "openssl"}, names(p))
	require.Equal(t, 2, p.Total)
	require.Equal(t, 1, p.Rows[0].Findings)
	require.Equal(t, model.PriorityMedium, p.Rows[0].Worst)
	require.Equal(t, 2, p.Rows[1].Findings)
	require.Equal(t, model.PriorityUrgent, p.Rows[1].Worst)
	require.Equal(t, "sha256:web", p.Rows[1].Package.ImageDigest)

	p, err = s.ImagePackages(ctx, "sha256:web", "", []string{"npm"}, "", 50)
	require.NoError(t, err)
	require.Equal(t, []string{"lodash"}, names(p))
	require.Zero(t, p.Rows[0].Findings)
	require.Equal(t, model.PriorityNone, p.Rows[0].Worst)

	var seen []string
	after := ""
	for range 10 {
		p, err := s.ImagePackages(ctx, "sha256:web", "", nil, after, 1)
		require.NoError(t, err)
		require.Equal(t, 3, p.Total, "Total ignores After")
		seen = append(seen, names(p)...)
		if after = p.Next; after == "" {
			break
		}
	}
	require.Equal(t, []string{"libssl3", "lodash", "openssl"}, seen)
	_, err = s.ImagePackages(ctx, "sha256:web", "", nil, "!!", 1)
	require.ErrorIs(t, err, ErrBadCursor)

	// a node group's host packages
	put(t, s, "nodegroup:g1", model.Package{Ecosystem: "deb", Name: "openssl", Version: "3.0.13-0ubuntu3"})
	apply(t, s, uiFinding(exNodes, "host", "CVE-2026-0012", model.PriorityHigh, func(f *model.Finding) {
		f.Digests = []string{"nodegroup:g1"}
		f.Packages = []model.FindingPackage{{Name: "openssl", Ecosystem: "deb", Installed: "3.0.13-0ubuntu3"}}
	}))
	p, err = s.ImagePackages(ctx, "nodegroup:g1", "", nil, "", 0)
	require.NoError(t, err)
	require.Equal(t, []string{"openssl"}, names(p))
	require.Equal(t, 1, p.Rows[0].Findings)
	require.Equal(t, model.PriorityHigh, p.Rows[0].Worst)

	eco, err := s.ImageEcosystems(ctx, "sha256:web")
	require.NoError(t, err)
	require.Equal(t, []FacetValue{{"deb", 2}, {"npm", 1}}, eco)
}
