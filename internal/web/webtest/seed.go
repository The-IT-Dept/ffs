// Package webtest builds the seeded fixture the API and dashboard tests share.
package webtest

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"testing"
	"time"

	_ "github.com/glebarez/go-sqlite" // the driver the store uses, for ExecSQL

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/the-it-dept/ffs/api/v1alpha1"
	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/eol"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
	"github.com/the-it-dept/ffs/internal/web/api"
)

// Now is the clock of every service Seed and Empty build.
var Now = time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)

const (
	DigestWeb          = "sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	DigestWorker       = "sha256:" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	DigestUnresolvable = "sha256:" + "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	DigestFailed       = "sha256:" + "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

	clusterName = "test"
	repoNginx   = "docker.io/library/nginx"
	repoWorker  = "ghcr.io/example/worker"
	digestK8s   = "k8s:1.34.2"
	digestRT    = "runtime:containerd@2.2.1"
)

var (
	// Owners of the seed.
	Web     = model.OwnerRef{Kind: "Deployment", Namespace: "shop", Name: "web"}
	Worker  = model.OwnerRef{Kind: "Deployment", Namespace: "shop", Name: "worker"}
	Backup  = model.OwnerRef{Kind: "CronJob", Namespace: "ops", Name: "backup"}
	Cluster = model.OwnerRef{Kind: "Cluster", Name: clusterName}
	Runtime = model.OwnerRef{Kind: "ContainerRuntime", Name: "containerd"}
)

var feedInfos = []api.FeedInfo{{Name: "eol", StaleAfter: 72 * time.Hour}, {Name: "kev", StaleAfter: 24 * time.Hour}, {Name: "osv", StaleAfter: 2 * time.Hour}}

func service(t testing.TB, st *store.Store, kube client.Reader) *api.Service {
	t.Helper()
	cfg := config.Default()
	cfg.ClusterName = clusterName
	ev := eol.New(st, func() time.Time { return Now })
	require.NoError(t, ev.Reload(context.Background()))
	return api.NewService(api.Options{Store: st, Config: cfg, Feeds: feedInfos, EOL: ev, Kube: kube, Now: func() time.Time { return Now }})
}

// dbPaths records the database file of every store openStore opened, for ExecSQL.
var dbPaths sync.Map // *store.Store → string

func openStore(t testing.TB) *store.Store {
	t.Helper()
	path := t.TempDir() + "/ffs.db"
	st, err := store.Open(context.Background(), path)
	require.NoError(t, err)
	dbPaths.Store(st, path)
	t.Cleanup(func() { dbPaths.Delete(st); require.NoError(t, st.Close()) })
	return st
}

// ExecSQL runs a raw SQL statement against the database behind st, which Seed or Empty opened, and
// requires it to change a row: for states the store API cannot produce, such as a row it cannot
// decode, which proves a page never reads that row.
func ExecSQL(t testing.TB, st *store.Store, query string, args ...any) {
	t.Helper()
	path, ok := dbPaths.Load(st)
	require.True(t, ok, "store not opened by webtest")
	db, err := sql.Open("sqlite", path.(string))
	require.NoError(t, err)
	defer func() { require.NoError(t, db.Close()) }()
	res, err := db.ExecContext(context.Background(), query, args...)
	require.NoError(t, err)
	n, err := res.RowsAffected()
	require.NoError(t, err)
	require.Positive(t, n, query)
}

func scheme(t testing.TB) *runtime.Scheme {
	t.Helper()
	sc := runtime.NewScheme()
	require.NoError(t, v1alpha1.AddToScheme(sc))
	return sc
}

// Empty is the service over a fresh store and an empty fake client.
func Empty(t testing.TB) *api.Service {
	t.Helper()
	return service(t, openStore(t), fake.NewClientBuilder().WithScheme(scheme(t)).Build())
}

// Seed builds the seeded fixture for cluster "test": five owners, their images, packages,
// advisories, findings, two suggestions (a patch, and a tier none whose only fix is the next
// major), feed states, end-of-life cycles, a node, and one Exception.
func Seed(t testing.TB) (*api.Service, *store.Store) {
	t.Helper()
	ctx := context.Background()
	st := openStore(t)
	must := func(err error) { t.Helper(); require.NoError(t, err) }

	date := func(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 0, 0, 0, 0, time.UTC) }
	cycle := func(product, cycleName string, eolDate time.Time, latest string) store.EOLCycle {
		c := store.EOLCycle{Product: product, Cycle: cycleName, Latest: latest}
		if !eolDate.IsZero() {
			c.EOLDate = &eolDate
		}
		return c
	}
	must(st.ReplaceEOL(ctx, []store.EOLCycle{
		cycle("kubernetes", "1.34", date(2026, 10, 27), "1.34.13"),
		cycle("ubuntu", "24.04", date(2029, 4, 25), "24.04.4"),
		cycle("debian", "12", date(2026, 6, 10), "12.13"),
		cycle("containerd", "2.2", date(2026, 11, 6), "2.2.1"),
		cycle("php", "8.3", date(2027, 12, 31), "8.3.30"),
	}))

	owners := []model.Owner{
		{Ref: Web, ServiceAccount: "web", PullSecrets: []string{"regcred"}, UpdatedAt: Now,
			Context: model.WorkloadContext{Exposed: true, ExposurePaths: []string{"HTTPRoute shop/web on Gateway public/edge"}},
			Containers: []model.ContainerUse{{Name: "nginx", Kind: model.ContainerRegular, ImageRef: "nginx:1.30.6", Repo: repoNginx,
				Digest: DigestWeb, Platform: "linux/amd64"}}},
		{Ref: Worker, UpdatedAt: Now, Containers: []model.ContainerUse{
			{Name: "app", Kind: model.ContainerRegular, ImageRef: repoWorker + ":2.1.0", Repo: repoWorker, Digest: DigestWorker},
			{Name: "sidecar", Kind: model.ContainerSidecar, ImageRef: "ghcr.io/example/sidecar:1.0", Repo: "ghcr.io/example/sidecar", Digest: DigestFailed},
		}},
		{Ref: Backup, NotRunning: true, UpdatedAt: Now, Containers: []model.ContainerUse{
			{Name: "backup", Kind: model.ContainerRegular, ImageRef: "ghcr.io/example/backup:3", Repo: "ghcr.io/example/backup", Digest: DigestUnresolvable}}},
		{Ref: Cluster, UpdatedAt: Now, Containers: []model.ContainerUse{
			{Name: "kubernetes", Kind: model.ContainerRegular, ImageRef: "v1.34.2", Repo: "kubernetes", Digest: digestK8s}}},
		{Ref: Runtime, UpdatedAt: Now, Containers: []model.ContainerUse{
			{Name: "containerd", Kind: model.ContainerRegular, ImageRef: "containerd://2.2.1", Repo: "containerd", Digest: digestRT}}},
	}
	for _, o := range owners {
		must(st.UpsertOwner(ctx, o))
	}

	images := []model.Image{
		{Digest: DigestWeb, Repo: repoNginx, Platform: "linux/amd64", Status: model.ImageCatalogued, Source: "registry", CataloguedAt: Now,
			Coverage: model.Coverage{UnattributedELF: 2, Notes: []string{"2 executables not attributed to any package"}}},
		{Digest: DigestWorker, Repo: repoWorker, Platform: "linux/amd64", Status: model.ImageCatalogued, Source: "registry", CataloguedAt: Now},
		{Digest: DigestUnresolvable, Repo: "ghcr.io/example/backup", Status: model.ImageUnresolvable, StatusReason: "bare config digest"},
		{Digest: DigestFailed, Repo: "ghcr.io/example/sidecar", Status: model.ImageCatalogFailed, StatusReason: "catalogue timed out"},
		{Digest: digestRT, Repo: "containerd", Status: model.ImageCatalogued, Source: "inventory", CataloguedAt: Now},
		{Digest: digestK8s, Repo: "kubernetes", Status: model.ImageCatalogued, Source: "inventory", CataloguedAt: Now,
			Coverage: model.Coverage{Notes: []string{"kernel, runc and other bundled components (flannel) are not inventoried"}}},
	}
	for _, img := range images {
		must(st.UpsertImage(ctx, img))
	}
	debian12 := &model.Distro{ID: "debian", VersionID: "12", Codename: "bookworm"}
	must(st.PutSBOM(ctx, DigestWeb, nil, []model.Package{
		{Ecosystem: "deb", Distro: debian12, Name: "openssl", Version: "3.0.15-1~deb12u1", Arch: "amd64"},
		{Ecosystem: "binary", Name: "php-cli", Version: "8.3.14", Classifier: "php-cli-binary", Path: "/usr/local/bin/php"},
	}))
	must(st.PutSBOM(ctx, DigestWorker, nil, []model.Package{
		{Ecosystem: "binary", Name: "traefik", Version: "3.2.0", Classifier: "traefik-binary", Path: "/usr/local/bin/traefik"},
	}))
	must(st.PutSBOM(ctx, digestK8s, nil, []model.Package{{Ecosystem: "kubernetes", Name: "kubernetes", Version: "1.34.2"}}))
	must(st.PutSBOM(ctx, digestRT, nil, []model.Package{{Ecosystem: "containerd", Name: "containerd", Version: "2.2.1"}}))

	kev := date(2026, 11, 2)
	for _, a := range []model.Advisory{
		{ID: "CVE-2026-0001", Title: "OpenSSL buffer overflow", CNASeverity: model.SeverityCritical, KEVAdded: &kev, Published: date(2026, 10, 1)},
		{ID: "CVE-2026-0002", Aliases: []string{"GHSA-aaaa-bbbb-cccc"}, Title: "<script>alert(1)</script>", CNASeverity: model.SeverityHigh},
		{ID: "CVE-2026-0003", Title: "Kubernetes API server flaw", CNASeverity: model.SeverityHigh},
		{ID: "CVE-2026-0004", Title: "Medium issue", CNASeverity: model.SeverityMedium},
		{ID: "CVE-2026-0005", Title: "Low issue", CNASeverity: model.SeverityLow},
	} {
		a.Observed = Now
		must(st.UpsertAdvisory(ctx, a))
	}

	finding := func(o model.OwnerRef, repo, adv string, sev model.Severity, p model.Priority, state model.FindingState, pkg model.FindingPackage) model.Finding {
		return model.Finding{
			Fingerprint: model.FindingFingerprint(clusterName, o, repo, adv), Owner: o, ImageRepo: repo, AdvisoryID: adv,
			Packages: []model.FindingPackage{pkg}, Severity: sev, FixState: model.FixFixed, FixAvailable: len(pkg.Fixed) > 0,
			Priority: p, State: state, Published: Now, Observed: Now, Matched: Now, LastSeen: Now,
		}
	}
	f1 := finding(Web, repoNginx, "CVE-2026-0001", model.SeverityCritical, model.PriorityUrgent, model.StateOpen,
		model.FindingPackage{Name: "openssl", Ecosystem: "deb", Installed: "3.0.15-1~deb12u1", Fixed: []string{"3.0.16-1~deb12u1"}})
	f1.Reasons = []string{"actively exploited (CISA KEV, added 2026-11-02)", "exposed via HTTPRoute shop/web on Gateway public/edge"}
	f2 := finding(Web, repoNginx, "CVE-2026-0002", model.SeverityHigh, model.PriorityHigh, model.StateOpen,
		model.FindingPackage{Name: "php-cli", Ecosystem: "binary", Installed: "8.3.14", Fixed: []string{"8.3.15"}})
	f3 := finding(Worker, repoWorker, "CVE-2026-0004", model.SeverityMedium, model.PriorityMedium, model.StateOpen,
		model.FindingPackage{Name: "traefik", Ecosystem: "binary", Installed: "3.2.0"})
	f4 := finding(Worker, repoWorker, "CVE-2026-0005", model.SeverityLow, model.PriorityLow, model.StateExcepted,
		model.FindingPackage{Name: "traefik", Ecosystem: "binary", Installed: "3.2.0"})
	f4.ExceptedBy = "shop/accept-risk"
	f5 := finding(Cluster, "kubernetes", "CVE-2026-0003", model.SeverityHigh, model.PriorityHigh, model.StateOpen,
		model.FindingPackage{Name: "kubernetes", Ecosystem: "kubernetes", Installed: "1.34.2"})
	must(st.ApplyFindings(ctx, []model.Finding{f1, f2, f3, f4, f5}, nil))

	must(st.PutSuggestion(ctx, Web.Key(), model.Suggestion{
		Repo: repoNginx, FromTag: "1.30.6", ToTag: "1.30.7", Tier: model.TierPatch,
		Fixes:    map[model.Priority]int{model.PriorityUrgent: 1, model.PriorityHigh: 1},
		FixedIDs: []string{"CVE-2026-0001", "CVE-2026-0002"}, ComputedAt: Now,
	}, nil))
	// Nothing in the worker's 2.x line fixes its finding; only the next major does.
	must(st.PutSuggestion(ctx, Worker.Key(), model.Suggestion{
		Repo: repoWorker, FromTag: "2.1.0", Tier: model.TierNone, ComputedAt: Now,
		Alternatives: []model.Suggestion{{Repo: repoWorker, FromTag: "2.1.0", ToTag: "3.0.0", Tier: model.TierMajor,
			Fixes: map[model.Priority]int{model.PriorityMedium: 1}, FixedIDs: []string{"CVE-2026-0004"}, ComputedAt: Now}},
	}, nil))

	for _, f := range []struct {
		name string
		ago  time.Duration
	}{{"osv", 10 * time.Minute}, {"kev", 30 * time.Hour}, {"eol", 2 * time.Hour}} {
		must(st.PutFeedState(ctx, store.FeedState{Name: f.name, LastSuccess: Now.Add(-f.ago), LastAttempt: Now.Add(-f.ago)}))
	}

	must(st.ReplaceNodes(ctx, []model.Node{{Name: "node-a", OS: "linux", OSImage: "Ubuntu 24.04.4 LTS", KernelVersion: "6.8.0-88-generic",
		KubeletVersion: "v1.34.2", ContainerRuntimeVersion: "containerd://2.2.1", Arch: "amd64", Ready: true, UpdatedAt: Now}}))
	must(st.PutClusterInfo(ctx, model.ClusterInfo{Name: clusterName, GitVersion: "v1.34.2", Version: "1.34.2", UpdatedAt: Now}))

	exc := &v1alpha1.Exception{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "accept-risk"},
		Spec: v1alpha1.ExceptionSpec{Advisories: []string{"CVE-2026-0005"}, Reason: "Not reachable in our configuration",
			Expires: metav1.NewTime(date(2027, 1, 1))},
	}
	kube := fake.NewClientBuilder().WithScheme(scheme(t)).WithObjects(exc).Build()
	return service(t, st, kube), st
}

// DigestGo is the image of the Go standard library fixture.
const DigestGo = "sha256:" + "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

// SeedGoStdlib adds owner Deployment/tools/gotool running DigestGo, with three open medium
// findings on the Go 1.22.3 standard library.
func SeedGoStdlib(t testing.TB, st *store.Store) {
	t.Helper()
	ctx := context.Background()
	must := func(err error) { t.Helper(); require.NoError(t, err) }
	const repo = "ghcr.io/example/gotool"
	ref := model.OwnerRef{Kind: "Deployment", Namespace: "tools", Name: "gotool"}
	must(st.UpsertOwner(ctx, model.Owner{Ref: ref, UpdatedAt: Now, Containers: []model.ContainerUse{
		{Name: "gotool", Kind: model.ContainerRegular, ImageRef: repo + ":1.0", Repo: repo, Digest: DigestGo}}}))
	must(st.UpsertImage(ctx, model.Image{Digest: DigestGo, Repo: repo, Platform: "linux/amd64", Status: model.ImageCatalogued,
		Source: "registry", CataloguedAt: Now}))
	must(st.PutSBOM(ctx, DigestGo, nil, []model.Package{
		{Ecosystem: "go-module", Name: "stdlib", Version: "go1.22.3", GoStdlib: true, Path: "/usr/local/bin/gotool"}}))
	var fs []model.Finding
	for i, fix := range []string{"1.22.4", "1.22.12", "1.22.7"} {
		id := fmt.Sprintf("GO-2024-000%d", i+1)
		must(st.UpsertAdvisory(ctx, model.Advisory{ID: id, Title: "Standard library flaw " + fmt.Sprint(i+1), CNASeverity: model.SeverityMedium, Observed: Now}))
		fs = append(fs, model.Finding{
			Fingerprint: model.FindingFingerprint(clusterName, ref, repo, id), Owner: ref, ImageRepo: repo, AdvisoryID: id,
			Packages: []model.FindingPackage{{Name: "stdlib", Ecosystem: "go-module", Installed: "go1.22.3", Fixed: []string{fix}}},
			Severity: model.SeverityMedium, FixState: model.FixFixed, FixAvailable: true, Priority: model.PriorityMedium,
			State: model.StateOpen, GoStdlib: true, Published: Now, Observed: Now, Matched: Now, LastSeen: Now,
		})
	}
	must(st.ApplyFindings(ctx, fs, nil))
}

// DigestPlaceholder is the ID inventory gives an image whose tag could not be resolved: it holds
// the reference, slashes included.
const DigestPlaceholder = "unknown:ghcr.io/example/private:1.0"

// Report is the owner SeedPlaceholder adds.
var Report = model.OwnerRef{Kind: "CronJob", Namespace: "ops", Name: "report"}

// SeedPlaceholder adds owner CronJob/ops/report running the unresolvable placeholder image
// DigestPlaceholder.
func SeedPlaceholder(t testing.TB, st *store.Store) {
	t.Helper()
	ctx := context.Background()
	must := func(err error) { t.Helper(); require.NoError(t, err) }
	const repo = "ghcr.io/example/private"
	must(st.UpsertOwner(ctx, model.Owner{Ref: Report, NotRunning: true, UpdatedAt: Now, Containers: []model.ContainerUse{
		{Name: "report", Kind: model.ContainerRegular, ImageRef: repo + ":1.0", Repo: repo, Digest: DigestPlaceholder}}}))
	must(st.UpsertImage(ctx, model.Image{Digest: DigestPlaceholder, Repo: repo, Status: model.ImageUnresolvable,
		StatusReason: "registry refused the tag lookup"}))
}
