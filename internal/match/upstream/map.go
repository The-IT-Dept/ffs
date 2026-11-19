// Package upstream is the upstream-runtime fast path (spec §6.5): php, node, python and the other
// runtimes and servers built from source, which Syft finds only through binary classifiers. A
// curated map ties each classifier package to its upstream git repository (OSV GIT records, matched
// by release tag or extracted version range) and to its CVE Numbering Authority product (cvelistV5
// affected ranges). Both sources are the authority for these packages and are never provisional.
package upstream

import (
	"slices"
	"strings"

	"github.com/the-it-dept/ffs/internal/model"
)

// binaryEcosystem is the Syft package type of packages found by a binary classifier.
const binaryEcosystem = "binary"

// VendorProduct is a CNA vendor and product name, compared case-insensitively.
type VendorProduct struct{ Vendor, Product string }

// Entry maps one upstream product to its sources.
type Entry struct {
	// Key names the product: the upstream_ranges product key and the "cna:" match namespace.
	Key string
	// Classifiers are the Syft classifier classes and Names the package names a package must have
	// (both) to be this product. They are exact Syft v1.57.2 strings.
	Classifiers, Names []string
	// Repo is the upstream repository in osv.NormalizeRepo form.
	Repo string
	// TagFormats turn a version into the repository's release tags: "{v}" is the version and
	// "{v_}" the version with "." replaced by "_".
	TagFormats []string
	// CNA are the vendor/product pairs CVE records name the product by.
	CNA []VendorProduct
}

// Map is the curated upstream-runtime map. Golden tests cover it.
var Map = []Entry{
	{Key: "php", Classifiers: []string{"php-cli-binary", "php-fpm-binary", "php-apache-binary"},
		Names: []string{"php-cli", "php-fpm", "libphp"}, Repo: "github.com/php/php-src",
		TagFormats: []string{"php-{v}"}, CNA: []VendorProduct{{"PHP Group", "PHP"}, {"php", "php"}}},
	{Key: "node", Classifiers: []string{"nodejs-binary"}, Names: []string{"node"}, Repo: "github.com/nodejs/node",
		TagFormats: []string{"v{v}"}, CNA: []VendorProduct{{"nodejs", "node"}, {"nodejs", "node.js"}}},
	{Key: "python", Classifiers: []string{"python-binary", "python-binary-lib"}, Names: []string{"python"},
		Repo: "github.com/python/cpython", TagFormats: []string{"v{v}"},
		CNA: []VendorProduct{{"Python Software Foundation", "CPython"}}},
	{Key: "ruby", Classifiers: []string{"ruby-binary"}, Names: []string{"ruby"}, Repo: "github.com/ruby/ruby",
		TagFormats: []string{"v{v}", "v{v_}"}, CNA: []VendorProduct{{"ruby-lang", "ruby"}}},
	{Key: "nginx", Classifiers: []string{"nginx-binary"}, Names: []string{"nginx"}, Repo: "github.com/nginx/nginx",
		TagFormats: []string{"release-{v}"}, CNA: []VendorProduct{{"F5", "NGINX Open Source"}, {"nginx", "nginx"}}},
	{Key: "httpd", Classifiers: []string{"httpd-binary"}, Names: []string{"httpd"}, Repo: "github.com/apache/httpd",
		TagFormats: []string{"{v}"}, CNA: []VendorProduct{{"Apache Software Foundation", "Apache HTTP Server"}}},
	{Key: "haproxy", Classifiers: []string{"haproxy-binary"}, Names: []string{"haproxy"}, Repo: "github.com/haproxy/haproxy",
		TagFormats: []string{"v{v}"}, CNA: []VendorProduct{{"haproxy", "haproxy"}}},
	{Key: "redis", Classifiers: []string{"redis-binary"}, Names: []string{"redis"}, Repo: "github.com/redis/redis",
		TagFormats: []string{"{v}"}, CNA: []VendorProduct{{"redis", "redis"}}},
	{Key: "valkey", Classifiers: []string{"valkey-binary"}, Names: []string{"valkey"}, Repo: "github.com/valkey-io/valkey",
		TagFormats: []string{"{v}"}, CNA: []VendorProduct{{"valkey-io", "valkey"}}},
	{Key: "postgresql", Classifiers: []string{"postgresql-binary"}, Names: []string{"postgresql"},
		Repo: "github.com/postgres/postgres", TagFormats: []string{"REL_{v_}"},
		CNA: []VendorProduct{{"n/a", "PostgreSQL"}, {"PostgreSQL", "PostgreSQL"}}},
	{Key: "mysql", Classifiers: []string{"mysql-binary", "mysqld-mysql-server-binary"}, Names: []string{"mysql", "mysql-server"},
		Repo: "github.com/mysql/mysql-server", TagFormats: []string{"mysql-{v}"},
		CNA: []VendorProduct{{"Oracle Corporation", "MySQL Server"}}},
	{Key: "mariadb", Classifiers: []string{"mariadb-binary"}, Names: []string{"mariadb"}, Repo: "github.com/mariadb/server",
		TagFormats: []string{"mariadb-{v}"}, CNA: []VendorProduct{{"MariaDB", "MariaDB Server"}}},
	{Key: "openssl", Classifiers: []string{"openssl-binary"}, Names: []string{"openssl"}, Repo: "github.com/openssl/openssl",
		TagFormats: []string{"openssl-{v}", "OpenSSL_{v_}"}, CNA: []VendorProduct{{"OpenSSL", "OpenSSL"}}},
	{Key: "curl", Classifiers: []string{"curl-binary"}, Names: []string{"curl"}, Repo: "github.com/curl/curl",
		TagFormats: []string{"curl-{v_}"}, CNA: []VendorProduct{{"curl", "curl"}}},
	{Key: "busybox", Classifiers: []string{"busybox-binary"}, Names: []string{"busybox"}, Repo: "git.busybox.net/busybox",
		TagFormats: []string{"{v_}"}, CNA: []VendorProduct{{"busybox", "busybox"}}},
}

// Lookup returns the entry of a package found by a binary classifier: its ecosystem is "binary"
// and both its classifier and its name belong to the entry.
func Lookup(p model.Package) (Entry, bool) {
	if p.Ecosystem != binaryEcosystem || p.Classifier == "" {
		return Entry{}, false
	}
	for _, e := range Map {
		if slices.Contains(e.Classifiers, p.Classifier) && slices.Contains(e.Names, p.Name) {
			return e, true
		}
	}
	return Entry{}, false
}

// ForCNA returns the entry a CVE record's affected vendor and product name, compared
// case-insensitively.
func ForCNA(vendor, product string) (Entry, bool) {
	vendor, product = strings.TrimSpace(vendor), strings.TrimSpace(product)
	for _, e := range Map {
		for _, vp := range e.CNA {
			if strings.EqualFold(vp.Vendor, vendor) && strings.EqualFold(vp.Product, product) {
				return e, true
			}
		}
	}
	return Entry{}, false
}

// Repos returns the repository of every entry, in osv.NormalizeRepo form: the GIT records the OSV
// feed keeps for this matcher.
func Repos() []string {
	out := make([]string, len(Map))
	for i, e := range Map {
		out[i] = e.Repo
	}
	return out
}

// Tags returns the release tags of version in the entry's repository, one per tag format, without
// repeats.
func (e Entry) Tags(version string) []string {
	r := strings.NewReplacer("{v_}", strings.ReplaceAll(version, ".", "_"), "{v}", version)
	out := make([]string, 0, len(e.TagFormats))
	for _, f := range e.TagFormats {
		if t := r.Replace(f); !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out
}

// UncoveredClassified returns the sorted, distinct names of the packages found by a binary
// classifier that the map does not cover. They get daily, CPE-based coverage only, which the
// image's coverage note says.
func UncoveredClassified(pkgs []model.Package) []string {
	var out []string
	for _, p := range pkgs {
		if p.Classifier == "" {
			continue
		}
		if _, ok := Lookup(p); !ok {
			out = append(out, p.Name)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}
