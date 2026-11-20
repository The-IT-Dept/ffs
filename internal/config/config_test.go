package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func writeFile(t *testing.T, s string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(p, []byte(s), 0o600))
	return p
}

func TestDefault(t *testing.T) {
	h := time.Hour
	want := Config{
		ClusterName: "default", Namespace: "ffs", DeploymentName: "ffs",
		StorePath: "/var/lib/ffs/ffs.db", DataDir: "/var/lib/ffs", Listen: "127.0.0.1:8080",
		Catalog:  CatalogConfig{Socket: "/run/ffs/catalog.sock", Timeout: 10 * time.Minute, MaxImageBytes: 10 << 30, Concurrency: 2},
		Registry: RegistryConfig{ReadPullSecrets: true},
		Feeds: FeedsConfig{
			GrypeDB:       GrypeDBConfig{true, "https://grype.anchore.io/databases/v6/latest.json", 1 * h, 48 * h, 1000},
			OSV:           FeedConfig{true, "https://osv-vulnerabilities.storage.googleapis.com", 5 * time.Minute, 2 * h},
			CVEList:       FeedConfig{true, "https://github.com/CVEProject/cvelistV5/releases/download", 1 * h, 6 * h},
			KEV:           FeedConfig{true, "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", 1 * h, 24 * h},
			EPSS:          FeedConfig{true, "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz", 24 * h, 72 * h},
			EOL:           FeedConfig{true, "https://endoflife.date/api/v1", 24 * h, 72 * h},
			NVD:           FeedConfig{false, "https://services.nvd.nist.gov/rest/json/cves/2.0", 0, 0},
			ChainguardOSV: FeedConfig{false, "https://packages.cgr.dev/chainguard/osv", 0, 0},
		},
		Priority:    PriorityConfig{EPSSHigh: 0.5, EPSSBump: 0.1},
		CRD:         CRDConfig{MinPriority: "high", MaxFindings: 2000},
		Events:      EventsConfig{MinPriority: "high"},
		OpenReports: OpenReportsConfig{Mode: "auto", MaxResults: 100},
		Exceptions:  ExceptionsConfig{MaxDuration: 8760 * h},
		Retention:   RetentionConfig{Resolved: 2160 * h},
		Upgrades:    UpgradesConfig{Enabled: true, MaxCandidatesPerRepo: 4, DailyAt: "03:00"},
		NodeAgent: NodeAgentConfig{Enabled: true, Listen: ":8444", CertDir: "/etc/ffs/agent-tls", Namespace: "ffs-agent",
			ServiceAccount: "ffs-agent", MaxReportBytes: 32 << 20, ReportInterval: 6 * h, ImageListInterval: 5 * time.Minute,
			StaleAfter: 30 * time.Minute, RuntimeGrace: 2 * h, WorkPerReport: 3, WorkTimeout: 20 * time.Minute,
			Architectures: []string{"amd64"}, NodeSelector: map[string]string{"kubernetes.io/os": "linux"}},
	}
	require.Equal(t, want, Default())
	require.NoError(t, Default().Validate())
	require.Len(t, Default().Feeds.ByName(), 8)
	require.Equal(t, Default().Feeds.ChainguardOSV, Default().Feeds.ByName()["chainguard-osv"])
}

func TestLoad_Overlay(t *testing.T) {
	c, err := Load(writeFile(t, "clusterName: prod\nfeeds:\n  osv:\n    interval: 10m\ncrd:\n  maxFindings: 500\nregistry:\n  mirrors:\n    docker.io: mirror.gcr.io\n"))
	require.NoError(t, err)
	require.Equal(t, "prod", c.ClusterName)
	require.Equal(t, 10*time.Minute, c.Feeds.OSV.Interval)
	require.Equal(t, 2*time.Hour, c.Feeds.OSV.StaleAfter) // untouched siblings keep defaults
	require.True(t, c.Feeds.OSV.Enabled)
	require.Equal(t, Default().Feeds.OSV.URL, c.Feeds.OSV.URL)
	require.Equal(t, 500, c.CRD.MaxFindings)
	require.Equal(t, "high", c.CRD.MinPriority)
	require.Equal(t, map[string]string{"docker.io": "mirror.gcr.io"}, c.Registry.Mirrors)
}

func TestLoad_GrypeDBDiffMinImages(t *testing.T) {
	c, err := Load(writeFile(t, "feeds:\n  grypedb:\n    diffMinImages: 0\n    interval: 2h\n"))
	require.NoError(t, err)
	require.Zero(t, c.Feeds.GrypeDB.DiffMinImages)
	require.Equal(t, FeedConfig{true, "https://grype.anchore.io/databases/v6/latest.json", 2 * time.Hour, 48 * time.Hour},
		c.Feeds.GrypeDB.Feed())
	require.Equal(t, c.Feeds.GrypeDB.Feed(), c.Feeds.ByName()["grypedb"])
}

func TestLoad_EmptyFileIsDefault(t *testing.T) {
	c, err := Load(writeFile(t, ""))
	require.NoError(t, err)
	require.Equal(t, Default(), c)
}

func TestLoad_Rejects(t *testing.T) {
	for in, want := range map[string]string{
		"crd:\n  maxFindngs: 5\n":             "maxFindngs",      // unknown keys are errors, not ignored
		"crd:\n  minPriority: severe\n":       "crd.minPriority", // Load runs Validate
		"feeds:\n  osv:\n    interval: 300\n": "time.Duration",   // durations must be strings like "5m"
	} {
		_, err := Load(writeFile(t, in))
		require.ErrorContains(t, err, want, in)
	}
	_, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	require.Error(t, err)
}

func TestValidate(t *testing.T) {
	for name, tc := range map[string]struct {
		mut  func(*Config)
		want string
	}{
		"empty cluster name":        {func(c *Config) { c.ClusterName = "" }, "clusterName"},
		"bad crd priority":          {func(c *Config) { c.CRD.MinPriority = "severe" }, "crd.minPriority"},
		"empty events priority":     {func(c *Config) { c.Events.MinPriority = "" }, "events.minPriority"},
		"negative max findings":     {func(c *Config) { c.CRD.MaxFindings = -1 }, "crd.maxFindings"},
		"negative report cap":       {func(c *Config) { c.OpenReports.MaxResults = -1 }, "openReports.maxResults"},
		"bad openreports mode":      {func(c *Config) { c.OpenReports.Mode = "sometimes" }, "openReports.mode"},
		"zero concurrency":          {func(c *Config) { c.Catalog.Concurrency = 0 }, "catalog.concurrency"},
		"exception over a year":     {func(c *Config) { c.Exceptions.MaxDuration = 8761 * time.Hour }, "exceptions.maxDuration"},
		"bad daily time":            {func(c *Config) { c.Upgrades.DailyAt = "25:00" }, "upgrades.dailyAt"},
		"too many candidates":       {func(c *Config) { c.Upgrades.MaxCandidatesPerRepo = 5 }, "upgrades.maxCandidatesPerRepo"},
		"enabled feed, no interval": {func(c *Config) { c.Feeds.KEV.Interval = 0 }, "feeds.kev.interval"},
		"nvd not supported":         {func(c *Config) { c.Feeds.NVD.Enabled = true }, "feeds.nvd: not supported in this release"},
		"stale before interval":     {func(c *Config) { c.Feeds.OSV.StaleAfter = time.Minute }, "feeds.osv.staleAfter"},
		"grypedb stale too soon":    {func(c *Config) { c.Feeds.GrypeDB.StaleAfter = time.Minute }, "feeds.grypedb.staleAfter"},
		"negative diff size":        {func(c *Config) { c.Feeds.GrypeDB.DiffMinImages = -1 }, "feeds.grypedb.diffMinImages"},
		"epss bump above high":      {func(c *Config) { c.Priority.EPSSBump = 0.6 }, "priority.epssBump"},
		"allowed host with scheme":  {func(c *Config) { c.AllowedHosts = []string{"https://ffs.example.com"} }, "allowedHosts[0]"},
		"allowed host with port":    {func(c *Config) { c.AllowedHosts = []string{"ffs.example.com", "ffs.example.com:443"} }, "allowedHosts[1]"},
		"empty allowed host":        {func(c *Config) { c.AllowedHosts = []string{""} }, "allowedHosts[0]"},
		"override without version group": {func(c *Config) {
			c.Upgrades.Overrides = map[string]TagOverride{"docker.io/bitnami/postgresql": {Pattern: `^(\d+)-debian`}}
		}, "upgrades.overrides[docker.io/bitnami/postgresql].pattern"},
	} {
		c := Default()
		tc.mut(&c)
		require.ErrorContains(t, c.Validate(), tc.want, name)
	}
	c := Default()
	c.Feeds.ChainguardOSV.Enabled = true // switch only: interval 0 and staleAfter 0 are fine
	c.AllowedHosts = []string{"ffs.example.com", "ffs-web.ffs.svc.cluster.local", "FFS.Example.com."}
	require.NoError(t, c.Validate())
	c.CRD.MaxFindings, c.Catalog.Concurrency = -1, 0
	err := c.Validate()
	require.ErrorContains(t, err, "crd.maxFindings")
	require.ErrorContains(t, err, "catalog.concurrency") // all problems reported together
}
