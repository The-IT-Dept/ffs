package osv

import (
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

// Buckets: the directories of the OSV.dev bucket, one per ecosystem. Go and GIT are polled whatever
// the inventory holds: Go vulndb is the authority for the Go standard library and container
// runtimes, and GIT carries the upstream-runtime and Kubernetes records.
const (
	BucketGo  = "Go"
	BucketGIT = "GIT"
)

const (
	bucketDebian     = "Debian"
	bucketUbuntu     = "Ubuntu"
	bucketAlpine     = "Alpine"
	bucketWolfi      = "Wolfi"
	bucketChainguard = "Chainguard"
	bucketAlmaLinux  = "AlmaLinux"
	bucketRocky      = "Rocky Linux"
	bucketPyPI       = "PyPI"
	bucketMaven      = "Maven"
)

// languageBuckets maps the Syft type of a language package to its OSV ecosystem, which is also its
// bucket.
var languageBuckets = map[string]string{
	"python":       bucketPyPI,
	"npm":          "npm",
	"go-module":    BucketGo,
	"java-archive": bucketMaven,
	"gem":          "RubyGems",
	"rust-crate":   "crates.io",
	"dotnet":       "NuGet",
	"php-composer": "Packagist",
	"hex":          "Hex",
	"dart-pub":     "Pub",
}

// distroBuckets maps the Syft type and distro ID of an OS package to its bucket. rpm on rhel, sles,
// amzn and ol is deliberately absent: Grype is authoritative there.
var distroBuckets = map[[2]string]string{
	{"deb", "debian"}:     bucketDebian,
	{"deb", "ubuntu"}:     bucketUbuntu,
	{"apk", "alpine"}:     bucketAlpine,
	{"apk", "wolfi"}:      bucketWolfi,
	{"apk", "chainguard"}: bucketChainguard,
	{"rpm", "almalinux"}:  bucketAlmaLinux,
	{"rpm", "rocky"}:      bucketRocky,
}

// bucketSyftTypes inverts languageBuckets and distroBuckets.
var bucketSyftTypes = func() map[string]string {
	m := make(map[string]string, len(languageBuckets)+len(distroBuckets))
	for typ, b := range languageBuckets {
		m[b] = typ
	}
	for k, b := range distroBuckets {
		m[b] = k[0]
	}
	return m
}()

// knownBuckets returns every bucket the feed can cache records in, sorted.
func knownBuckets() []string {
	out := []string{BucketGIT}
	for b := range bucketSyftTypes {
		out = append(out, b)
	}
	slices.Sort(out)
	return out
}

// recordEcosystem returns the normalised OSV record ecosystem for a package of Syft type syftType on
// the given distro.
func recordEcosystem(syftType, distroID, distroVersion string) (string, bool) {
	if eco, ok := languageBuckets[syftType]; ok {
		return eco, true
	}
	b, ok := distroBuckets[[2]string{syftType, distroID}]
	if !ok {
		return "", false
	}
	var v string
	switch b {
	case bucketWolfi, bucketChainguard:
		return b, true
	case bucketUbuntu:
		v = distroVersion
	case bucketAlpine:
		if mm := majorMinor(distroVersion); mm != "" {
			v = "v" + mm
		}
	default: // Debian, AlmaLinux, Rocky Linux
		v, _, _ = strings.Cut(distroVersion, ".")
	}
	if v == "" {
		return "", false
	}
	return b + ":" + v, true
}

// majorMinor returns the first two dot-separated components of v, or "" when it has fewer.
func majorMinor(v string) string {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	return parts[0] + "." + parts[1]
}

// BucketFor returns the bucket to poll for packages of k, or "" when that ecosystem is not polled.
// Wolfi and Chainguard are polled only when chainguard is set.
func BucketFor(k store.EcosystemKey, chainguard bool) string {
	eco, ok := recordEcosystem(k.Ecosystem, k.DistroID, k.DistroVersion)
	if !ok {
		return ""
	}
	b := BucketOf(eco)
	if !chainguard && (b == bucketWolfi || b == bucketChainguard) {
		return ""
	}
	return b
}

// PackageEcosystem returns the normalised OSV record ecosystem p is matched in, e.g. "Debian:12",
// "Alpine:v3.20" or "PyPI".
func PackageEcosystem(p model.Package) (eco string, ok bool) {
	var id, version string
	if p.Distro != nil {
		id, version = p.Distro.ID, p.Distro.VersionID
	}
	return recordEcosystem(p.Ecosystem, id, version)
}

// NormalizeRecordEcosystem brings a record's affected ecosystem to the form PackageEcosystem
// returns: "Ubuntu:24.04:LTS" becomes "Ubuntu:24.04". Ubuntu Pro ecosystems keep their "Pro"
// segment, so they never equal a package ecosystem.
func NormalizeRecordEcosystem(eco string) string {
	if strings.HasPrefix(eco, bucketUbuntu+":") && !strings.HasPrefix(eco, bucketUbuntu+":Pro:") {
		return strings.TrimSuffix(eco, ":LTS")
	}
	return eco
}

// BucketOf returns the bucket of a record ecosystem: the text before the first ":".
func BucketOf(eco string) string {
	b, _, _ := strings.Cut(eco, ":")
	return b
}

// SourceJoin reports whether bucket's records name source (Debian, Ubuntu) or origin (Alpine, Wolfi,
// Chainguard) packages rather than binary packages.
func SourceJoin(bucket string) bool {
	switch bucket {
	case bucketDebian, bucketUbuntu, bucketAlpine, bucketWolfi, bucketChainguard:
		return true
	}
	return false
}

// SyftType returns the Syft package type of bucket's packages, e.g. "deb" for Debian, "python" for
// PyPI and "go-module" for Go, or "" for a bucket with no package type (GIT, or not polled).
func SyftType(bucket string) string { return bucketSyftTypes[bucket] }

var pep503 = regexp.MustCompile(`[-_.]+`)

// IndexName normalises a package name the way bucket compares names: PEP 503 for PyPI, lowercase
// for Maven and NormalizeRepo for GIT. Other names are unchanged.
func IndexName(bucket, name string) string {
	switch bucket {
	case bucketPyPI:
		return strings.ToLower(pep503.ReplaceAllString(name, "-"))
	case bucketMaven:
		return strings.ToLower(name)
	case BucketGIT:
		return NormalizeRepo(name)
	}
	return name
}

// PackageIndexNames returns the index names p is looked up by in the bucket of its ecosystem: the
// source or origin name in source-join buckets (else the package name), "group:artifact" from the
// PURL for Maven, and IndexName of the package name otherwise. It is nil for packages outside the
// polled ecosystems.
func PackageIndexNames(p model.Package) []string {
	eco, ok := PackageEcosystem(p)
	if !ok {
		return nil
	}
	b := BucketOf(eco)
	name := p.Name
	switch {
	case SourceJoin(b):
		if p.SourceName != "" {
			name = p.SourceName
		}
	case b == bucketMaven:
		name = mavenName(p.PURL)
	}
	if name == "" {
		return nil
	}
	return []string{IndexName(b, name)}
}

// mavenName returns "group:artifact" from a pkg:maven PURL, or "".
func mavenName(purl string) string {
	const prefix = "pkg:maven/"
	if len(purl) < len(prefix) || !strings.EqualFold(purl[:len(prefix)], prefix) {
		return ""
	}
	rest := purl[len(prefix):]
	if i := strings.IndexAny(rest, "@?#"); i >= 0 {
		rest = rest[:i]
	}
	i := strings.LastIndexByte(rest, '/')
	if i < 0 {
		return ""
	}
	group, err1 := url.PathUnescape(rest[:i])
	artifact, err2 := url.PathUnescape(rest[i+1:])
	if err1 != nil || err2 != nil || group == "" || artifact == "" {
		return ""
	}
	return group + ":" + artifact
}

// SkipID reports whether a record of bucket is a notice rather than a per-package advisory: Debian
// keeps only "DEBIAN-" records (not DSA/DLA/DTSA) and Ubuntu only "UBUNTU-" records (not USN/LSN).
func SkipID(bucket, id string) bool {
	switch bucket {
	case bucketDebian:
		return !strings.HasPrefix(id, "DEBIAN-")
	case bucketUbuntu:
		return !strings.HasPrefix(id, "UBUNTU-")
	}
	return false
}

// NormalizeRepo reduces a git repository URL to host and path, lowercased, without scheme,
// credentials, ".git" suffix or trailing slash: "https://github.com/PHP/php-src.git/" becomes
// "github.com/php/php-src".
func NormalizeRepo(u string) string {
	s := strings.TrimSpace(u)
	if _, rest, ok := strings.Cut(s, "://"); ok {
		s = rest
	}
	host, _, _ := strings.Cut(s, "/")
	if i := strings.LastIndexByte(host, '@'); i >= 0 {
		s = s[i+1:]
	}
	s = strings.TrimRight(s, "/")
	s = strings.TrimSuffix(s, ".git")
	return strings.ToLower(strings.TrimRight(s, "/"))
}
