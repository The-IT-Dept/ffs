// Package webtest builds the seeded fixture the API handler tests, the development server and the
// browser tests share.
package webtest

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
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
	"github.com/the-it-dept/ffs/internal/inventory"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/nodegroup"
	"github.com/the-it-dept/ffs/internal/registry"
	"github.com/the-it-dept/ffs/internal/store"
	"github.com/the-it-dept/ffs/internal/web/apiserver"
)

// Now is the clock of every fixture.
var Now = time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)

// ClusterName is the cluster every fixture describes.
const ClusterName = "test"

// Image digests of Small.
const (
	DigestWeb          = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	DigestProxy        = "sha256:9999999999999999999999999999999999999999999999999999999999999999"
	DigestWorker       = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	DigestFailed       = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	DigestPayments     = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	DigestUnresolvable = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	DigestExporter     = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	DigestAttested     = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	DigestCoreDNS      = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	// DigestPlaceholder is the ID inventory gives an image whose tag could not be resolved: it
	// holds the reference, slashes included.
	DigestPlaceholder = "unknown:ghcr.io/example/private:1.0"

	digestK8s     = "k8s:1.34.2"
	digestRuntime = "runtime:containerd@2.2.1"
)

const (
	repoNginx    = "docker.io/library/nginx"
	repoProxy    = "ghcr.io/example/proxy"
	repoWorker   = "ghcr.io/example/worker"
	repoSidecar  = "ghcr.io/example/sidecar"
	repoPayments = "ghcr.io/example/payments"
	repoMigrate  = "ghcr.io/example/migrate"
	repoExporter = "quay.io/prometheus/node-exporter"
	repoBackup   = "ghcr.io/example/backup"
	repoPrivate  = "ghcr.io/example/private"
	repoCoreDNS  = "registry.k8s.io/coredns/coredns"

	webPath = "HTTPRoute shop/web on Gateway gateway/public"
)

// Node groups of Small: worker-1 and worker-2 report through the node agent and share one host
// fingerprint; cp-1 never reports, so it is grouped by its node status alone.
var (
	// AgentGroupID is the host fingerprint of worker-1 and worker-2 (label "ubuntu-24.04-k6.8.0-88-3f9c1a").
	AgentGroupID = "3f9c1a" + strings.Repeat("0", 58)
	// CP1GroupID is the nodeinfo group of cp-1: nodegroup.FallbackID of its Node.
	CP1GroupID = nodegroup.FallbackID(smallNode("cp-1", kernelCP1))

	// AgentGroupKey and CP1GroupKey are the keys the API names the two groups by: their stable names,
	// which no other group shares.
	AgentGroupKey = agentGroupName
	CP1GroupKey   = nodegroup.GroupName(nil, osImage, kernelCP1)
)

// agentGroupName is the stable name of the agent group.
const agentGroupName = "ubuntu-24.04-k6.8.0-88"

const (
	kernelCP1    = "6.8.0-85-generic"
	kernelWorker = "6.8.0-88-generic"
	osImage      = "Ubuntu 24.04.4 LTS"
)

// Owners of Small.
var (
	Web      = model.OwnerRef{Kind: "Deployment", Namespace: "shop", Name: "web"}
	Worker   = model.OwnerRef{Kind: "Deployment", Namespace: "shop", Name: "worker"}
	Payments = model.OwnerRef{Kind: "Deployment", Namespace: "payments", Name: "api"}
	Exporter = model.OwnerRef{Kind: "DaemonSet", Namespace: "ops", Name: "node-exporter"}
	Backup   = model.OwnerRef{Kind: "CronJob", Namespace: "ops", Name: "backup"}
	Report   = model.OwnerRef{Kind: "CronJob", Namespace: "ops", Name: "report"}
	CoreDNS  = model.OwnerRef{Kind: "Deployment", Namespace: "kube-system", Name: "coredns"}
	Cluster  = model.OwnerRef{Kind: model.OwnerKindCluster, Name: ClusterName}
	Runtime  = model.OwnerRef{Kind: model.OwnerKindContainerRuntime, Name: "containerd"}
	Nodes    = model.NodesOwner(ClusterName)
)

// PodCounts is a fixed pod count per owner key. It implements apiserver.PodCounter.
type PodCounts map[string]int

// PodCounts returns the counts.
func (p PodCounts) PodCounts() map[string]int { return p }

// Fixture is a seeded store and what the API server reads besides it.
type Fixture struct {
	Store  *store.Store
	Kube   client.Reader
	Pods   PodCounts
	Config config.Config
	Feeds  []apiserver.FeedInfo
	EOL    *eol.Evaluator
}

// Options returns the API server options over f, with the clock fixed to Now. A nil Pods leaves
// the server without pod counts.
func (f *Fixture) Options() apiserver.Options {
	o := apiserver.Options{
		Store: f.Store, Config: f.Config, Feeds: f.Feeds, EOL: f.EOL, Kube: f.Kube,
		Now: func() time.Time { return Now },
	}
	if f.Pods != nil {
		o.Pods = f.Pods
	}
	return o
}

// Close closes the store.
func (f *Fixture) Close() error {
	dbPaths.Delete(f.Store)
	return f.Store.Close()
}

// dbPaths records the database file of every store a fixture opened, for ExecSQL.
var dbPaths sync.Map // *store.Store → string

// Open builds Small in a temporary directory and closes it when the test ends.
func Open(t testing.TB) *Fixture {
	t.Helper()
	f, err := Small(context.Background(), t.TempDir()+"/ffs.db")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, f.Close()) })
	return f
}

// ExecSQL runs a raw SQL statement against the database behind st, which a fixture opened, and
// requires it to change a row: for states the store API cannot produce.
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

// Small opens a store at path and seeds the deterministic fixture of cluster "test": seven
// workloads in shop, payments, ops and kube-system, the cluster and container runtime owners, ten
// in-use container images in every catalogue state, findings F1–F12 in every priority, fix kind and
// state, transitions T1–T4, two suggestions, feed states (kev stale), lifecycle cycles, three nodes
// and one Exception; then the node agent's data: an agent group of worker-1 (reporting) and
// worker-2 (stale) with its host SBOM, a nodeinfo group of cp-1 (never reported), the Nodes owner
// with host finding F13, and one image cached on worker-1.
func Small(ctx context.Context, path string) (*Fixture, error) {
	st, err := store.Open(ctx, path)
	if err != nil {
		return nil, err
	}
	dbPaths.Store(st, path)
	f := &Fixture{Store: st, Pods: PodCounts{Web.Key(): 2, Worker.Key(): 1}}
	if err := f.seed(ctx); err != nil {
		return nil, errors.Join(fmt.Errorf("webtest: seed: %w", err), f.Close())
	}
	return f, nil
}

func date(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 0, 0, 0, 0, time.UTC) }

func (f *Fixture) seed(ctx context.Context) error {
	f.Config = config.Default()
	f.Config.ClusterName = ClusterName
	f.Feeds = []apiserver.FeedInfo{{Name: "eol", StaleAfter: 72 * time.Hour}, {Name: "kev", StaleAfter: 24 * time.Hour},
		{Name: "osv", StaleAfter: 2 * time.Hour}}
	for _, step := range []func(context.Context) error{
		f.seedLifecycle, f.seedInventory, f.seedImages, f.seedAdvisories, f.seedMatches, f.seedFindings,
		f.seedSuggestions, f.seedFeedsAndNodes, f.seedExceptions, f.seedNodeAgent,
	} {
		if err := step(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (f *Fixture) seedLifecycle(ctx context.Context) error {
	cycle := func(product, name string, eolDate time.Time, latest string) store.EOLCycle {
		return store.EOLCycle{Product: product, Cycle: name, EOLDate: &eolDate, Latest: latest}
	}
	if err := f.Store.ReplaceEOL(ctx, []store.EOLCycle{
		cycle("kubernetes", "1.34", date(2026, 10, 27), "1.34.13"),
		cycle("debian", "12", date(2026, 6, 10), "12.13"),
		cycle("ubuntu", "24.04", date(2029, 4, 25), "24.04.4"),
		cycle("containerd", "2.2", date(2026, 11, 6), "2.2.1"),
	}); err != nil {
		return err
	}
	f.EOL = eol.New(f.Store, func() time.Time { return Now })
	return f.EOL.Reload(ctx)
}

func container(name string, kind model.ContainerKind, ref, repo, digest string) model.ContainerUse {
	return model.ContainerUse{Name: name, Kind: kind, ImageRef: ref, Repo: repo, Digest: digest, Platform: "linux/amd64"}
}

func (f *Fixture) seedInventory(ctx context.Context) error {
	owners := []model.Owner{
		{Ref: Web, ServiceAccount: "web", PullSecrets: []string{"regcred"}, UpdatedAt: Now,
			ManagedBy: &model.ManagedBy{Tool: "helm", Name: "web", Namespace: "shop"},
			Context: model.WorkloadContext{Exposed: true, ExposurePaths: []string{webPath},
				Exposure: []model.ExposureEdge{{Entry: model.EntryGateway, EntryName: "gateway/public", Listener: "https",
					Hostname: "shop.example.com", Route: "HTTPRoute shop/web", Service: "shop/web:8080", Path: webPath}}},
			Containers: []model.ContainerUse{
				container("app", model.ContainerRegular, repoNginx+":1.30.6", repoNginx, DigestWeb),
				container("proxy", model.ContainerRegular, repoProxy+":2.0", repoProxy, DigestProxy),
			}},
		{Ref: Worker, ServiceAccount: "worker", UpdatedAt: Now,
			Context: model.WorkloadContext{PowerfulSA: true, SAReasons: []string{"can read Secrets in namespace shop"}},
			Containers: []model.ContainerUse{
				container("app", model.ContainerRegular, repoWorker+":2.1.0", repoWorker, DigestWorker),
				container("sidecar", model.ContainerSidecar, repoSidecar+":1.0", repoSidecar, DigestFailed),
			}},
		{Ref: Payments, ServiceAccount: "default", UpdatedAt: Now,
			Context: model.WorkloadContext{Privileged: true, PrivilegeReasons: []string{"container app is privileged"},
				Exposure: []model.ExposureEdge{{Entry: model.EntryGateway, EntryName: "gateway/internal", Hostname: "api.payments.example.com",
					Route: "HTTPRoute payments/api", Service: "payments/api:8443", Internal: true}}},
			Containers: []model.ContainerUse{
				container("app", model.ContainerRegular, repoPayments+":4.2.0", repoPayments, DigestPayments),
				container("migrate", model.ContainerInit, repoMigrate, repoMigrate, DigestUnresolvable),
			}},
		{Ref: Exporter, ServiceAccount: "node-exporter", UpdatedAt: Now,
			Context: model.WorkloadContext{Exposed: true, ExposurePaths: []string{"hostNetwork"},
				Exposure:   []model.ExposureEdge{{Entry: model.EntryHostNetwork, Path: "hostNetwork"}},
				Privileged: true, PrivilegeReasons: []string{"uses the host network"}},
			Containers: []model.ContainerUse{container("node-exporter", model.ContainerRegular, repoExporter+":v1.9.1", repoExporter, DigestExporter)}},
		{Ref: Backup, ServiceAccount: "default", NotRunning: true, UpdatedAt: Now,
			Containers: []model.ContainerUse{container("backup", model.ContainerRegular, repoBackup+":3", repoBackup, DigestAttested)}},
		{Ref: Report, ServiceAccount: "default", NotRunning: true, UpdatedAt: Now,
			Containers: []model.ContainerUse{container("report", model.ContainerRegular, repoPrivate+":1.0", repoPrivate, DigestPlaceholder)}},
		{Ref: CoreDNS, ServiceAccount: "coredns", UpdatedAt: Now,
			Containers: []model.ContainerUse{container("coredns", model.ContainerRegular, repoCoreDNS+":v1.12.1", repoCoreDNS, DigestCoreDNS)}},
		{Ref: Cluster, UpdatedAt: Now,
			Containers: []model.ContainerUse{{Name: "kubernetes", Kind: model.ContainerRegular, ImageRef: "v1.34.2", Repo: "kubernetes", Digest: digestK8s}}},
		{Ref: Runtime, UpdatedAt: Now,
			Containers: []model.ContainerUse{{Name: "containerd", Kind: model.ContainerRegular, ImageRef: "containerd://2.2.1", Repo: "containerd", Digest: digestRuntime}}},
	}
	for _, o := range owners {
		if err := f.Store.UpsertOwner(ctx, o); err != nil {
			return err
		}
	}
	return nil
}

var debian12 = &model.Distro{ID: "debian", VersionID: "12", Codename: "bookworm"}

func (f *Fixture) seedImages(ctx context.Context) error {
	catalogued := func(digest, repo, source string, cov model.Coverage) model.Image {
		return model.Image{Digest: digest, Repo: repo, Platform: "linux/amd64", Status: model.ImageCatalogued, Source: source,
			Coverage: cov, CataloguedAt: Now}
	}
	images := []model.Image{
		catalogued(DigestWeb, repoNginx, "registry", model.Coverage{}),
		{Digest: DigestProxy, Repo: repoProxy, Status: model.ImagePending},
		catalogued(DigestWorker, repoWorker, "registry", model.Coverage{UnattributedELF: 2, Notes: []string{"2 executables not attributed to any package"}}),
		{Digest: DigestFailed, Repo: repoSidecar, Status: model.ImageCatalogFailed, StatusReason: "catalogue timed out"},
		catalogued(DigestPayments, repoPayments, "registry", model.Coverage{}),
		{Digest: DigestUnresolvable, Repo: repoMigrate, Status: model.ImageUnresolvable, StatusReason: inventory.ReasonSideLoadedNoTag},
		catalogued(DigestExporter, repoExporter, "registry", model.Coverage{}),
		catalogued(DigestAttested, repoBackup, "attestation", model.Coverage{}),
		{Digest: DigestPlaceholder, Repo: repoPrivate, Status: model.ImageUnresolvable,
			StatusReason: fmt.Sprintf(registry.ReasonUnauthorized, repoPrivate)},
		catalogued(DigestCoreDNS, repoCoreDNS, "registry", model.Coverage{}),
		{Digest: digestK8s, Repo: "kubernetes", Status: model.ImageCatalogued, Source: "inventory", CataloguedAt: Now},
		{Digest: digestRuntime, Repo: "containerd", Status: model.ImageCatalogued, Source: "inventory", CataloguedAt: Now},
	}
	for _, img := range images {
		if err := f.Store.UpsertImage(ctx, img); err != nil {
			return err
		}
	}
	if err := f.Store.PutTagDigest(ctx, repoNginx, "1.30.6", DigestWeb, Now); err != nil {
		return err
	}
	syft := []byte(`{"artifacts":[],"descriptor":{"name":"syft","version":"1.57.2"}}`)
	sboms := []struct {
		digest string
		syft   []byte
		pkgs   []model.Package
	}{
		{DigestWeb, syft, []model.Package{
			{Ecosystem: "deb", Distro: debian12, Name: "openssl", Version: "3.0.15-1~deb12u1", Arch: "amd64"},
			{Ecosystem: "deb", Distro: debian12, Name: "zlib1g", Version: "1.2.13.dfsg-1", Arch: "amd64"},
			{Ecosystem: "binary", Name: "php-cli", Version: "8.3.14", Classifier: "php-cli-binary", Path: "/usr/local/bin/php"},
		}},
		{DigestWorker, nil, []model.Package{
			{Ecosystem: "binary", Name: "traefik", Version: "3.2.0", Classifier: "traefik-binary", Path: "/usr/local/bin/traefik"},
		}},
		{DigestPayments, nil, []model.Package{
			{Ecosystem: "deb", Distro: debian12, Name: "openssl", Version: "3.0.15-1~deb12u1", Arch: "amd64"},
		}},
		{DigestExporter, nil, []model.Package{
			{Ecosystem: "go-module", Name: "stdlib", Version: "go1.24.1", GoStdlib: true, Path: "/bin/node_exporter"},
		}},
		{DigestAttested, nil, []model.Package{{Ecosystem: "python", Name: "requests", Version: "2.31.0"}}},
		{DigestCoreDNS, nil, []model.Package{
			{Ecosystem: "go-module", Name: "stdlib", Version: "go1.25.3", GoStdlib: true, Path: "/coredns"},
		}},
		{digestK8s, nil, []model.Package{{Ecosystem: "kubernetes", Name: "kubernetes", Version: "1.34.2"}}},
		{digestRuntime, nil, []model.Package{{Ecosystem: "containerd", Name: "containerd", Version: "2.2.1"}}},
	}
	for _, s := range sboms {
		if err := f.Store.PutSBOM(ctx, s.digest, s.syft, s.pkgs); err != nil {
			return err
		}
	}
	return nil
}

func (f *Fixture) seedAdvisories(ctx context.Context) error {
	kev := date(2026, 11, 2)
	for _, a := range []model.Advisory{
		{ID: "CVE-2026-0001", Title: "OpenSSL buffer overflow", CNASeverity: model.SeverityCritical, KEVAdded: &kev,
			EPSS: 0.42, EPSSPercentile: 0.97, Published: date(2026, 10, 1),
			Links: []string{"https://advisories.example.com/CVE-2026-0001"}},
		{ID: "CVE-2026-0002", Aliases: []string{"GHSA-aaaa-bbbb-cccc"}, Title: "<script>alert(1)</script>", CNASeverity: model.SeverityHigh},
		{ID: "CVE-2026-0003", Title: "Kubernetes API server flaw", CNASeverity: model.SeverityHigh},
		{ID: "CVE-2026-0004", Title: "Traefik header parsing flaw", CNASeverity: model.SeverityMedium},
		{ID: "CVE-2026-0005", Title: "Traefik error page flaw", CNASeverity: model.SeverityLow},
		{ID: "CVE-2026-0006", Title: "zlib inflate flaw", CNASeverity: model.SeverityMedium},
		{ID: "CVE-2026-0007", Title: "Traefik access log flaw", CNASeverity: model.SeverityLow},
		{ID: "CVE-2026-0008", Title: "Requests certificate verification flaw", CNASeverity: model.SeverityHigh},
		{ID: "CVE-2026-0009", Title: "Traefik routing flaw", CNASeverity: model.SeverityMedium},
		{ID: "GO-2026-0010", Title: "Standard library flaw", CNASeverity: model.SeverityHigh},
		{ID: "CVE-2026-0011", Title: "containerd image pull flaw", CNASeverity: model.SeverityMedium},
	} {
		a.Observed = Now
		if err := f.Store.UpsertAdvisory(ctx, a); err != nil {
			return err
		}
	}
	return nil
}

// seedMatches records the grype matches of openssl on the web and payments images.
func (f *Fixture) seedMatches(ctx context.Context) error {
	var ms []model.Match
	for _, m := range []struct {
		digest string
		ago    time.Duration
	}{{DigestWeb, 2 * time.Hour}, {DigestPayments, 3 * time.Hour}} {
		pkgs, err := f.Store.PackagesForImage(ctx, m.digest)
		if err != nil {
			return err
		}
		for _, p := range pkgs {
			if p.Name != "openssl" {
				continue
			}
			ms = append(ms, model.Match{ImageDigest: m.digest, PackageID: p.ID, AdvisoryID: "CVE-2026-0001", Source: model.SourceGrype,
				FixState: model.FixFixed, FixedVersions: []string{"3.0.16-1~deb12u1"}, VendorSeverity: model.SeverityCritical,
				VendorSeveritySource: "debian", Namespace: "debian:distro:debian:12", ObservedAt: Now.Add(-m.ago)})
		}
	}
	if len(ms) != 2 {
		return fmt.Errorf("want 2 openssl matches, built %d", len(ms))
	}
	_, err := f.Store.ReplaceMatches(ctx, store.MatchScope{Source: model.SourceGrype, Digests: []string{DigestWeb, DigestPayments}}, ms)
	return err
}

func rebuildFix(d *model.Distro) *model.FixAction {
	return &model.FixAction{Kind: model.FixKindRebuild, Key: "rebuild:" + d.ID + ":" + d.VersionID,
		Label: d.ID + " " + d.VersionID + " rebuild", Distro: d}
}

func packageFix(eco, name, from, to string) *model.FixAction {
	return &model.FixAction{Kind: model.FixKindPackage, Key: "package:" + eco + ":" + name + ":" + from + ":" + to,
		Label: name + " " + from + " → " + to, Package: name, Ecosystem: eco, From: from, To: to}
}

var (
	noFix   = &model.FixAction{Kind: model.FixKindNone, Key: "none", Label: model.FixLabelNone}
	wontFix = &model.FixAction{Kind: model.FixKindWontFix, Key: "wontfix", Label: model.FixLabelWontFix}
)

// smallFinding is one row of Small's finding table.
type smallFinding struct {
	owner         model.OwnerRef
	repo, digest  string
	advisory      string
	pkg           model.FindingPackage
	severity      model.Severity
	priority      model.Priority
	state         model.FindingState
	fixState      model.FixState
	fix           *model.FixAction
	signals       model.FindingSignals
	provisional   bool
	goStdlib      bool
	reasons       []string
	resolvedAgo   time.Duration
	exceptedBy    string
	severitySrc   string
	publishedDate time.Time
}

func (s smallFinding) finding() model.Finding {
	f := model.Finding{
		Fingerprint: model.FindingFingerprint(ClusterName, s.owner, s.repo, s.advisory), Owner: s.owner, ImageRepo: s.repo,
		AdvisoryID: s.advisory, Packages: []model.FindingPackage{s.pkg}, Digests: []string{s.digest}, Severity: s.severity,
		SeveritySource: s.severitySrc, FixState: s.fixState, FixAvailable: len(s.pkg.Fixed) > 0, Priority: s.priority,
		Reasons: s.reasons, Provisional: s.provisional, GoStdlib: s.goStdlib, State: s.state, ExceptedBy: s.exceptedBy,
		Published: s.publishedDate, Observed: Now, Matched: Now, LastSeen: Now, Signals: s.signals, Fix: s.fix,
	}
	if s.state == model.StateResolved {
		at := Now.Add(-s.resolvedAgo)
		f.ResolvedAt = &at
	}
	return f
}

func (f *Fixture) seedFindings(ctx context.Context) error {
	openssl := model.FindingPackage{Name: "openssl", Ecosystem: "deb", Installed: "3.0.15-1~deb12u1", Fixed: []string{"3.0.16-1~deb12u1"}}
	traefik := func(fixed ...string) model.FindingPackage {
		return model.FindingPackage{Name: "traefik", Ecosystem: "binary", Installed: "3.2.0", Path: "/usr/local/bin/traefik", Fixed: fixed}
	}
	kev := model.FindingSignals{KEV: true, EPSS: 0.42, EPSSElevated: true}
	exposedKEV, privilegedKEV := kev, kev
	exposedKEV.Exposed, privilegedKEV.Privileged = true, true
	exposed := model.FindingSignals{Exposed: true}
	powerfulSA := model.FindingSignals{PowerfulSA: true}
	rows := []smallFinding{
		{owner: Web, repo: repoNginx, digest: DigestWeb, advisory: "CVE-2026-0001", pkg: openssl, severity: model.SeverityCritical,
			priority: model.PriorityUrgent, state: model.StateOpen, fixState: model.FixFixed, fix: rebuildFix(debian12), signals: exposedKEV,
			severitySrc: "debian", publishedDate: date(2026, 10, 1),
			reasons: []string{"actively exploited (CISA KEV, added 2026-11-02)", "exposed via " + webPath}},
		{owner: Web, repo: repoNginx, digest: DigestWeb, advisory: "CVE-2026-0002",
			pkg:      model.FindingPackage{Name: "php-cli", Ecosystem: "binary", Installed: "8.3.14", Path: "/usr/local/bin/php", Fixed: []string{"8.3.15"}},
			severity: model.SeverityHigh, priority: model.PriorityHigh, state: model.StateOpen, fixState: model.FixFixed,
			fix: packageFix("binary", "php-cli", "8.3.14", "8.3.15"), signals: exposed},
		{owner: Web, repo: repoNginx, digest: DigestWeb, advisory: "CVE-2026-0006",
			pkg:      model.FindingPackage{Name: "zlib1g", Ecosystem: "deb", Installed: "1.2.13.dfsg-1"},
			severity: model.SeverityMedium, priority: model.PriorityMedium, state: model.StateOpen, fixState: model.FixNotFixed,
			fix: noFix, signals: exposed},
		{owner: Worker, repo: repoWorker, digest: DigestWorker, advisory: "CVE-2026-0004", pkg: traefik("3.2.1"),
			severity: model.SeverityMedium, priority: model.PriorityMedium, state: model.StateOpen, fixState: model.FixFixed,
			fix: packageFix("binary", "traefik", "3.2.0", "3.2.1"), signals: powerfulSA},
		{owner: Worker, repo: repoWorker, digest: DigestWorker, advisory: "CVE-2026-0005", pkg: traefik(),
			severity: model.SeverityLow, priority: model.PriorityLow, state: model.StateExcepted, exceptedBy: "shop/accept-risk",
			fixState: model.FixNotFixed, fix: noFix, signals: powerfulSA},
		{owner: Worker, repo: repoWorker, digest: DigestWorker, advisory: "CVE-2026-0007", pkg: traefik(),
			severity: model.SeverityLow, priority: model.PriorityLow, state: model.StateOpen, fixState: model.FixWontFix,
			fix: wontFix, signals: powerfulSA},
		{owner: Worker, repo: repoWorker, digest: DigestWorker, advisory: "CVE-2026-0009", pkg: traefik("3.2.1"),
			severity: model.SeverityMedium, priority: model.PriorityMedium, state: model.StateResolved, resolvedAgo: 10 * 24 * time.Hour,
			fixState: model.FixFixed, fix: packageFix("binary", "traefik", "3.2.0", "3.2.1"), signals: powerfulSA},
		{owner: Payments, repo: repoPayments, digest: DigestPayments, advisory: "CVE-2026-0001", pkg: openssl,
			severity: model.SeverityCritical, priority: model.PriorityHigh, state: model.StateOpen, fixState: model.FixFixed,
			fix: rebuildFix(debian12), signals: privilegedKEV, severitySrc: "debian", publishedDate: date(2026, 10, 1),
			reasons: []string{"actively exploited (CISA KEV, added 2026-11-02)"}},
		{owner: Exporter, repo: repoExporter, digest: DigestExporter, advisory: "GO-2026-0010",
			pkg:      model.FindingPackage{Name: "stdlib", Ecosystem: "go-module", Installed: "go1.24.1", Path: "/bin/node_exporter", Fixed: []string{"1.24.5"}},
			severity: model.SeverityHigh, priority: model.PriorityUrgent, state: model.StateOpen, fixState: model.FixFixed, goStdlib: true,
			fix: packageFix("go-module", "stdlib", "go1.24.1", "1.24.5"), signals: model.FindingSignals{Exposed: true, Privileged: true},
			reasons: []string{"exposed via hostNetwork", "privileged: uses the host network"}},
		{owner: Backup, repo: repoBackup, digest: DigestAttested, advisory: "CVE-2026-0008",
			pkg:      model.FindingPackage{Name: "requests", Ecosystem: "python", Installed: "2.31.0", Fixed: []string{"2.32.0"}},
			severity: model.SeverityHigh, priority: model.PriorityLow, state: model.StateOpen, fixState: model.FixFixed, provisional: true,
			fix: packageFix("python", "requests", "2.31.0", "2.32.0"), signals: model.FindingSignals{NotRunning: true},
			reasons: []string{"not running"}},
		{owner: Cluster, repo: "kubernetes", digest: digestK8s, advisory: "CVE-2026-0003",
			pkg:      model.FindingPackage{Name: "kubernetes", Ecosystem: "kubernetes", Installed: "1.34.2", Fixed: []string{"1.34.3"}},
			severity: model.SeverityHigh, priority: model.PriorityHigh, state: model.StateOpen, fixState: model.FixFixed,
			fix: packageFix("kubernetes", "kubernetes", "1.34.2", "1.34.3")},
		{owner: Runtime, repo: "containerd", digest: digestRuntime, advisory: "CVE-2026-0011",
			pkg:      model.FindingPackage{Name: "containerd", Ecosystem: "containerd", Installed: "2.2.1", Fixed: []string{"2.2.2"}},
			severity: model.SeverityMedium, priority: model.PriorityMedium, state: model.StateOpen, fixState: model.FixFixed,
			fix: packageFix("containerd", "containerd", "2.2.1", "2.2.2")},
	}
	fs := make([]model.Finding, len(rows))
	for i, r := range rows {
		fs[i] = r.finding()
	}
	f1, f5, f7 := fs[0], fs[4], fs[6]
	transition := func(fd model.Finding, from, to model.FindingState, fromP, toP model.Priority, trig model.Trigger, ago time.Duration) model.Transition {
		return model.Transition{Fingerprint: fd.Fingerprint, Owner: fd.Owner, AdvisoryID: fd.AdvisoryID, FromState: from, ToState: to,
			FromPriority: fromP, ToPriority: toP, Trigger: trig, At: Now.Add(-ago)}
	}
	ts := []model.Transition{
		transition(f7, "", model.StateOpen, model.PriorityNone, model.PriorityMedium, model.TriggerNewAdvisory, 20*24*time.Hour),
		transition(f7, model.StateOpen, model.StateResolved, model.PriorityMedium, model.PriorityMedium, model.TriggerInventoryChange, 10*24*time.Hour),
		transition(f5, model.StateOpen, model.StateExcepted, model.PriorityLow, model.PriorityLow, model.TriggerInventoryChange, 24*time.Hour),
		transition(f1, "", model.StateOpen, model.PriorityNone, model.PriorityUrgent, model.TriggerNewAdvisory, 2*time.Hour),
	}
	return f.Store.ApplyFindings(ctx, fs, ts)
}

func (f *Fixture) seedSuggestions(ctx context.Context) error {
	if err := f.Store.PutSuggestion(ctx, Web.Key(), model.Suggestion{
		Repo: repoNginx, FromTag: "1.30.6", ToTag: "1.30.7", Tier: model.TierPatch,
		Fixes:    map[model.Priority]int{model.PriorityUrgent: 1, model.PriorityHigh: 1},
		FixedIDs: []string{"CVE-2026-0001", "CVE-2026-0002"}, ComputedAt: Now,
	}, nil); err != nil {
		return err
	}
	// Nothing in the worker's 2.x line fixes its findings; only the next major does.
	return f.Store.PutSuggestion(ctx, Worker.Key(), model.Suggestion{
		Repo: repoWorker, FromTag: "2.1.0", Tier: model.TierNone, ComputedAt: Now,
		Alternatives: []model.Suggestion{{Repo: repoWorker, FromTag: "2.1.0", ToTag: "3.0.0", Tier: model.TierMajor,
			Fixes: map[model.Priority]int{model.PriorityMedium: 1}, FixedIDs: []string{"CVE-2026-0004"}, ComputedAt: Now}},
	}, nil)
}

func (f *Fixture) seedFeedsAndNodes(ctx context.Context) error {
	for _, fs := range []struct {
		name string
		ago  time.Duration
	}{{"osv", 10 * time.Minute}, {"kev", 30 * time.Hour}, {"eol", 2 * time.Hour}} {
		if err := f.Store.PutFeedState(ctx, store.FeedState{Name: fs.name, LastSuccess: Now.Add(-fs.ago), LastAttempt: Now.Add(-fs.ago)}); err != nil {
			return err
		}
	}
	if err := f.Store.ReplaceNodes(ctx, []model.Node{
		smallNode("cp-1", kernelCP1), smallNode("worker-1", kernelWorker), smallNode("worker-2", kernelWorker),
	}); err != nil {
		return err
	}
	return f.Store.PutClusterInfo(ctx, model.ClusterInfo{Name: ClusterName, GitVersion: "v1.34.2", Version: "1.34.2", UpdatedAt: Now})
}

// smallNode is one of Small's nodes, as the inventory stores it.
func smallNode(name, kernel string) model.Node {
	return model.Node{Name: name, OS: "linux", Arch: "amd64", OSImage: osImage, KernelVersion: kernel,
		KubeletVersion: "v1.34.2", ContainerRuntimeVersion: "containerd://2.2.1", Ready: true, UpdatedAt: Now}
}

func (f *Fixture) seedExceptions(context.Context) error {
	sc := runtime.NewScheme()
	if err := v1alpha1.AddToScheme(sc); err != nil {
		return err
	}
	exc := &v1alpha1.Exception{
		ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "accept-risk"},
		Spec: v1alpha1.ExceptionSpec{Advisories: []string{"CVE-2026-0005"}, Reason: "Not reachable in our configuration",
			Expires: metav1.NewTime(date(2027, 1, 1))},
		Status: v1alpha1.ExceptionStatus{MatchedFindings: 1},
	}
	f.Kube = fake.NewClientBuilder().WithScheme(sc).WithObjects(exc).Build()
	return nil
}

// seedNodeAgent writes the node agent's data in the order its reconciler does: the agent reports,
// their host fingerprints, then the group and the grouping. It then stores the group's host SBOM,
// the Nodes owner with finding F13, the agent state and worker-1's cached image.
func (f *Fixture) seedNodeAgent(ctx context.Context) error {
	ubuntu := &model.Distro{ID: "ubuntu", VersionID: "24.04", Codename: "noble"}
	digest := nodegroup.GroupDigest(AgentGroupID)
	for _, r := range []struct {
		node string
		ago  time.Duration
	}{{"worker-1", 5 * time.Minute}, {"worker-2", 2 * time.Hour}} {
		at := Now.Add(-r.ago)
		if _, err := f.Store.AcceptAgentReport(ctx, store.AgentReport{Node: r.node, AgentVersion: "v0.1.0", BootID: "boot-" + r.node,
			StartedAt: at.Add(-time.Minute), Seq: 1, At: at, Full: true, KernelRelease: kernelWorker, Arch: "amd64",
			PackageDB: "dpkg"}); err != nil {
			return err
		}
	}
	for _, node := range []string{"worker-1", "worker-2"} {
		if err := f.Store.SetAgentFingerprint(ctx, node, AgentGroupID); err != nil {
			return err
		}
	}
	name := agentGroupName
	group := model.NodeGroup{ID: AgentGroupID, Kind: model.NodeGroupAgent, Name: name, Label: nodegroup.GroupLabel(name, AgentGroupID),
		Digest: digest, Distro: ubuntu, OSImage: osImage, KernelRelease: kernelWorker,
		ContainerRuntimeVersion: "containerd://2.2.1", KubeletVersion: "v1.34.2", Arch: "amd64",
		Kernel:    &model.NodeKernel{Release: kernelWorker, Package: "linux-image-" + kernelWorker, Version: "6.8.0-88.89", SourceName: "linux"},
		PackageDB: "dpkg", PackageCount: 2}
	if err := f.Store.PutNodeGroup(ctx, group, Now); err != nil {
		return err
	}
	if err := f.Store.ApplyNodeGrouping(ctx, store.NodeGrouping{
		Members:  map[string]string{"worker-1": AgentGroupID, "worker-2": AgentGroupID, "cp-1": CP1GroupID},
		Fallback: nodegroup.FallbackGroups([]model.Node{smallNode("cp-1", kernelCP1)}, Now),
		Exposed:  map[string][]string{AgentGroupID: {"worker-1"}},
		Now:      Now,
	}); err != nil {
		return err
	}

	if err := f.Store.UpsertImage(ctx, model.Image{Digest: digest, Repo: model.HostRepo, Platform: "linux/amd64",
		Status: model.ImageCatalogued, Source: "agent", CataloguedAt: Now}); err != nil {
		return err
	}
	if err := f.Store.PutSBOM(ctx, digest, nil, []model.Package{
		{Ecosystem: "deb", Distro: ubuntu, Name: "linux-image-" + kernelWorker, Version: "6.8.0-88.89", Arch: "amd64"},
		{Ecosystem: "deb", Distro: ubuntu, Name: "openssl", Version: "3.0.13-0ubuntu3", Arch: "amd64"},
	}); err != nil {
		return err
	}
	if err := f.Store.PutAgentProvenance(ctx, store.AgentProvenance{Digest: digest, Node: "worker-1", AgentVersion: "v0.1.0",
		ReceivedAt: Now.Add(-5 * time.Minute)}); err != nil {
		return err
	}

	if err := f.Store.UpsertOwner(ctx, model.Owner{Ref: Nodes, UpdatedAt: Now, Containers: []model.ContainerUse{{
		Name: group.Label, Kind: model.ContainerRegular, ImageRef: group.Label, Repo: model.HostRepo, Digest: digest,
		Platform: "linux/amd64", ExposurePaths: []string{fmt.Sprintf(model.NodeExposurePathFmt, "worker-1")},
	}}}); err != nil {
		return err
	}
	if err := f.Store.UpsertAdvisory(ctx, model.Advisory{ID: "CVE-2026-0012", Title: "OpenSSL host flaw",
		CNASeverity: model.SeverityHigh, Observed: Now}); err != nil {
		return err
	}
	f13 := smallFinding{owner: Nodes, repo: model.HostRepo, digest: digest, advisory: "CVE-2026-0012",
		pkg:      model.FindingPackage{Name: "openssl", Ecosystem: "deb", Installed: "3.0.13-0ubuntu3", Fixed: []string{"3.0.13-0ubuntu3.1"}},
		severity: model.SeverityHigh, priority: model.PriorityHigh, state: model.StateOpen, fixState: model.FixFixed,
		fix: packageFix("deb", "openssl", "3.0.13-0ubuntu3", "3.0.13-0ubuntu3.1"), signals: model.FindingSignals{Exposed: true},
		reasons: []string{"exposed via node worker-1"}}
	if err := f.Store.ApplyFindings(ctx, []model.Finding{f13.finding()}, nil); err != nil {
		return err
	}

	if err := f.Store.PutNodesState(ctx, store.NodesState{AgentEnabled: true}); err != nil {
		return err
	}
	return f.Store.ReplaceNodeImages(ctx, "worker-1", []model.NodeImage{{Digest: DigestWeb, Names: []string{repoNginx + ":1.30.6"},
		Kind: "manifest", Complete: true, InUse: true, Source: "both"}})
}
