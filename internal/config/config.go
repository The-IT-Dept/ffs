// Package config loads and validates the ffs YAML configuration.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/the-it-dept/ffs/internal/model"
)

type Config struct {
	ClusterName    string            `yaml:"clusterName"`
	Namespace      string            `yaml:"namespace"`      // ffs install namespace; cluster-wide Exceptions, cluster-level Findings
	DeploymentName string            `yaml:"deploymentName"` // controller Deployment; target of FeedStale/cap/cluster Events
	StorePath      string            `yaml:"storePath"`
	DataDir        string            `yaml:"dataDir"`
	Listen         string            `yaml:"listen"`
	AllowedHosts   []string          `yaml:"allowedHosts"` // Host names served besides localhost and IP literals (proxy mode)
	DashboardURL   string            `yaml:"dashboardURL"`
	Catalog        CatalogConfig     `yaml:"catalog"`
	Registry       RegistryConfig    `yaml:"registry"`
	Feeds          FeedsConfig       `yaml:"feeds"`
	Priority       PriorityConfig    `yaml:"priority"`
	Exposure       ExposureConfig    `yaml:"exposure"`
	CRD            CRDConfig         `yaml:"crd"`
	Events         EventsConfig      `yaml:"events"`
	OpenReports    OpenReportsConfig `yaml:"openReports"`
	Exceptions     ExceptionsConfig  `yaml:"exceptions"`
	Retention      RetentionConfig   `yaml:"retention"`
	Upgrades       UpgradesConfig    `yaml:"upgrades"`
	NodeAgent      NodeAgentConfig   `yaml:"nodeAgent"`
}

type CatalogConfig struct {
	Socket        string        `yaml:"socket"`
	Timeout       time.Duration `yaml:"timeout"`
	MaxImageBytes int64         `yaml:"maxImageBytes"`
	Concurrency   int           `yaml:"concurrency"`
}

type RegistryConfig struct {
	OperatorSecret  string            `yaml:"operatorSecret"`
	Mirrors         map[string]string `yaml:"mirrors"`
	ReadPullSecrets bool              `yaml:"readPullSecrets"`
}

type FeedConfig struct {
	Enabled    bool          `yaml:"enabled"`
	URL        string        `yaml:"url"`
	Interval   time.Duration `yaml:"interval"`
	StaleAfter time.Duration `yaml:"staleAfter"`
}

// GrypeDBConfig is the grypedb feed's FeedConfig and the size rule for its updates.
type GrypeDBConfig struct {
	Enabled    bool          `yaml:"enabled"`
	URL        string        `yaml:"url"`
	Interval   time.Duration `yaml:"interval"`
	StaleAfter time.Duration `yaml:"staleAfter"`
	// DiffMinImages is the number of catalogued SBOMs (images and node groups) from which a new
	// build is diffed against the current one to re-match only the changed packages; below it, a
	// new build re-matches everything. 0 always diffs.
	DiffMinImages int `yaml:"diffMinImages"`
}

// Feed returns the feed's schedule and source.
func (c GrypeDBConfig) Feed() FeedConfig {
	return FeedConfig{Enabled: c.Enabled, URL: c.URL, Interval: c.Interval, StaleAfter: c.StaleAfter}
}

type FeedsConfig struct {
	GrypeDB GrypeDBConfig `yaml:"grypedb"`
	OSV     FeedConfig    `yaml:"osv"`
	CVEList FeedConfig    `yaml:"cvelist"`
	KEV     FeedConfig    `yaml:"kev"`
	EPSS    FeedConfig    `yaml:"epss"`
	EOL     FeedConfig    `yaml:"eol"`
	// NVD is reserved: there is no NVD feed in v0.0.1 and Validate rejects enabled: true.
	NVD FeedConfig `yaml:"nvd"`
	// ChainguardOSV is an on/off switch only: it adds the Wolfi/Chainguard buckets to the osv feed and rides its schedule.
	ChainguardOSV FeedConfig `yaml:"chainguardOSV"`
}

// ByName returns the feeds keyed by Feed.Name().
func (f FeedsConfig) ByName() map[string]FeedConfig {
	return map[string]FeedConfig{
		"grypedb": f.GrypeDB.Feed(), "osv": f.OSV, "cvelist": f.CVEList, "kev": f.KEV,
		"epss": f.EPSS, "eol": f.EOL, "nvd": f.NVD, "chainguard-osv": f.ChainguardOSV,
	}
}

type PriorityConfig struct {
	EPSSHigh float64 `yaml:"epssHigh"`
	EPSSBump float64 `yaml:"epssBump"`
}

type ExposureConfig struct {
	InternalIngressClasses []string          `yaml:"internalIngressClasses"`
	InternalGatewayClasses []string          `yaml:"internalGatewayClasses"`
	InternalGateways       []string          `yaml:"internalGateways"` // "namespace/name"
	InternalLBAnnotations  map[string]string `yaml:"internalLBAnnotations"`
}

type CRDConfig struct {
	MinPriority string `yaml:"minPriority"`
	MaxFindings int    `yaml:"maxFindings"`
}

type EventsConfig struct {
	MinPriority string `yaml:"minPriority"`
}

type OpenReportsConfig struct {
	Mode       string `yaml:"mode"`
	MaxResults int    `yaml:"maxResults"`
	WGPolicy   bool   `yaml:"wgPolicy"`
}

type ExceptionsConfig struct {
	MaxDuration time.Duration `yaml:"maxDuration"`
}

type RetentionConfig struct {
	Resolved time.Duration `yaml:"resolved"`
}

type UpgradesConfig struct {
	Enabled              bool                   `yaml:"enabled"`
	MaxCandidatesPerRepo int                    `yaml:"maxCandidatesPerRepo"`
	DailyAt              string                 `yaml:"dailyAt"`
	Overrides            map[string]TagOverride `yaml:"overrides"`            // key: normalised repo, e.g. "docker.io/bitnami/postgresql"
	KubernetesReleaseURL string                 `yaml:"kubernetesReleaseURL"` // "" = "https://dl.k8s.io/release"
}

// TagOverride customises tag parsing for one repo. Pattern is a regexp with a required named
// group "version" and optional "suffix" and "revision"; tags that do not match are ignored.
// Ignore lists path.Match globs dropped before parsing.
type TagOverride struct {
	Pattern string   `yaml:"pattern"`
	Ignore  []string `yaml:"ignore"`
}

// DefaultDiffMinImages is the default feeds.grypedb.diffMinImages. Measured on one machine with the
// 2026-11-18 and 2026-11-20 production builds: the diff took 228 CPU-seconds, and a full re-match as
// the engine runs it (every matcher, matches stored) 0.4 CPU-seconds per small image, 4 per large
// image and 5 per Ubuntu node group. The diff selected every one of those SBOMs for re-matching, so
// the diff path cost the diff plus a full re-match. It pays off only where a diff leaves enough
// SBOMs untouched to save more than it costs: at 1000 SBOMs, over half of a cluster of small images,
// or about 5% of one of large images.
const DefaultDiffMinImages = 1000

// Default returns the built-in configuration.
func Default() Config {
	const h = time.Hour
	return Config{
		ClusterName: "default", Namespace: "ffs", DeploymentName: "ffs",
		StorePath: "/var/lib/ffs/ffs.db", DataDir: "/var/lib/ffs", Listen: "127.0.0.1:8080",
		Catalog:  CatalogConfig{Socket: "/run/ffs/catalog.sock", Timeout: 10 * time.Minute, MaxImageBytes: 10 << 30, Concurrency: 2},
		Registry: RegistryConfig{ReadPullSecrets: true},
		Feeds: FeedsConfig{
			GrypeDB:       GrypeDBConfig{true, "https://grype.anchore.io/databases/v6/latest.json", 1 * h, 48 * h, DefaultDiffMinImages},
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
		NodeAgent:   defaultNodeAgent(),
	}
}

// Load overlays the YAML file at path on Default() and validates the result.
// Unknown keys are errors.
func Load(path string) (Config, error) {
	f, err := os.Open(path) //nolint:gosec // operator-supplied config path
	if err != nil {
		return Config{}, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(f)
	if err != nil {
		return Config{}, fmt.Errorf("read %s: %w", path, err)
	}
	c := Default()
	clearReplacedDefaults(data, &c)
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return c, c.Validate()
}

// clearReplacedDefaults clears the defaults that are lists or maps and that the file sets, so the file's
// value replaces them: the decoder would merge a map into its default, and an explicitly empty or null
// value would then not mean what it says.
func clearReplacedDefaults(data []byte, c *Config) {
	var set struct {
		NodeAgent struct {
			Architectures yaml.Node `yaml:"architectures"`
			NodeSelector  yaml.Node `yaml:"nodeSelector"`
		} `yaml:"nodeAgent"`
	}
	if yaml.Unmarshal(data, &set) != nil {
		return // the strict decode reports it
	}
	if set.NodeAgent.Architectures.Kind != 0 {
		c.NodeAgent.Architectures = nil
	}
	if set.NodeAgent.NodeSelector.Kind != 0 {
		c.NodeAgent.NodeSelector = nil
	}
}

// Validate reports every problem at once, each prefixed with its YAML path.
func (c Config) Validate() error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	for _, s := range []struct{ path, val string }{
		{"clusterName", c.ClusterName}, {"namespace", c.Namespace}, {"deploymentName", c.DeploymentName},
		{"storePath", c.StorePath}, {"dataDir", c.DataDir}, {"catalog.socket", c.Catalog.Socket},
	} {
		if s.val == "" {
			bad("%s: must not be empty", s.path)
		}
	}
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		bad("listen: %v", err)
	}
	for i, h := range c.AllowedHosts {
		if !hostName.MatchString(h) {
			bad("allowedHosts[%d]: %q must be a host name, without scheme, port or path", i, h)
		}
	}
	if c.DashboardURL != "" && !absHTTP(c.DashboardURL) {
		bad("dashboardURL: must be an absolute http(s) URL")
	}
	if c.Catalog.Timeout <= 0 {
		bad("catalog.timeout: must be > 0")
	}
	if c.Catalog.MaxImageBytes <= 0 {
		bad("catalog.maxImageBytes: must be > 0")
	}
	if c.Catalog.Concurrency < 1 {
		bad("catalog.concurrency: must be >= 1")
	}

	for _, n := range []struct {
		path string
		f    FeedConfig
	}{
		{"grypedb", c.Feeds.GrypeDB.Feed()}, {"osv", c.Feeds.OSV}, {"cvelist", c.Feeds.CVEList},
		{"kev", c.Feeds.KEV}, {"epss", c.Feeds.EPSS}, {"eol", c.Feeds.EOL},
	} {
		if !n.f.Enabled {
			continue
		}
		if !absHTTP(n.f.URL) {
			bad("feeds.%s.url: must be an absolute http(s) URL", n.path)
		}
		if n.f.Interval <= 0 {
			bad("feeds.%s.interval: must be > 0", n.path)
		}
		if n.f.StaleAfter <= n.f.Interval {
			bad("feeds.%s.staleAfter: must be greater than interval", n.path)
		}
	}
	if c.Feeds.GrypeDB.DiffMinImages < 0 {
		bad("feeds.grypedb.diffMinImages: must be >= 0")
	}
	if c.Feeds.NVD.Enabled {
		bad("feeds.nvd: not supported in this release")
	}

	if p := c.Priority; !(p.EPSSBump > 0 && p.EPSSBump <= p.EPSSHigh && p.EPSSHigh <= 1) {
		bad("priority.epssBump: need 0 < epssBump <= epssHigh <= 1")
	}
	if _, err := model.ParsePriority(c.CRD.MinPriority); err != nil {
		bad("crd.minPriority: %v", err)
	}
	if _, err := model.ParsePriority(c.Events.MinPriority); err != nil {
		bad("events.minPriority: %v", err)
	}
	if c.CRD.MaxFindings < 0 {
		bad("crd.maxFindings: must be >= 0")
	}
	if c.OpenReports.MaxResults < 0 {
		bad("openReports.maxResults: must be >= 0")
	}
	switch c.OpenReports.Mode {
	case "auto", "on", "off":
	default:
		bad("openReports.mode: must be auto, on or off")
	}
	if c.Exceptions.MaxDuration <= 0 || c.Exceptions.MaxDuration > 8760*time.Hour {
		bad("exceptions.maxDuration: must be in (0, 8760h]")
	}
	if c.Retention.Resolved <= 0 {
		bad("retention.resolved: must be > 0")
	}

	if u := c.Upgrades; u.Enabled {
		if u.MaxCandidatesPerRepo < 1 || u.MaxCandidatesPerRepo > 4 {
			bad("upgrades.maxCandidatesPerRepo: must be in 1..4")
		}
		if _, err := time.Parse("15:04", u.DailyAt); err != nil {
			bad("upgrades.dailyAt: must be HH:MM: %v", err)
		}
	}
	for repo, o := range c.Upgrades.Overrides {
		re, err := regexp.Compile(o.Pattern)
		if err != nil {
			bad("upgrades.overrides[%s].pattern: %v", repo, err)
			continue
		}
		if re.SubexpIndex("version") < 0 {
			bad("upgrades.overrides[%s].pattern: must have a named group \"version\"", repo)
		}
	}
	c.NodeAgent.validate(bad)
	return errors.Join(errs...)
}

// hostName is a DNS host name, any case, with an optional trailing dot.
var hostName = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.?$`)

func absHTTP(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}
