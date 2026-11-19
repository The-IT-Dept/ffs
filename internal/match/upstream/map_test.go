package upstream_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/feeds/osv"
	"github.com/the-it-dept/ffs/internal/match/upstream"
	"github.com/the-it-dept/ffs/internal/model"
)

func bin(class, name string) model.Package {
	return model.Package{Ecosystem: "binary", Classifier: class, Name: name}
}

func TestMap_Golden(t *testing.T) {
	lookup := func(class, name string) (upstream.Entry, bool) { return upstream.Lookup(bin(class, name)) }

	e, ok := lookup("php-cli-binary", "php-cli")
	require.True(t, ok)
	require.Equal(t, "php", e.Key)
	require.Equal(t, []string{"php-8.3.14"}, e.Tags("8.3.14"))

	tags := map[[2]string]struct {
		version string
		tags    []string
	}{
		{"php-fpm-binary", "php-fpm"}:                  {"8.2.26", []string{"php-8.2.26"}},
		{"php-apache-binary", "libphp"}:                {"8.1.31", []string{"php-8.1.31"}},
		{"nodejs-binary", "node"}:                      {"20.11.1", []string{"v20.11.1"}},
		{"python-binary", "python"}:                    {"3.12.8", []string{"v3.12.8"}},
		{"python-binary-lib", "python"}:                {"3.12.8", []string{"v3.12.8"}},
		{"ruby-binary", "ruby"}:                        {"3.3.6", []string{"v3.3.6", "v3_3_6"}},
		{"nginx-binary", "nginx"}:                      {"1.27.3", []string{"release-1.27.3"}},
		{"httpd-binary", "httpd"}:                      {"2.4.62", []string{"2.4.62"}},
		{"haproxy-binary", "haproxy"}:                  {"3.0.6", []string{"v3.0.6"}},
		{"redis-binary", "redis"}:                      {"7.4.1", []string{"7.4.1"}},
		{"valkey-binary", "valkey"}:                    {"8.0.1", []string{"8.0.1"}},
		{"postgresql-binary", "postgresql"}:            {"16.4", []string{"REL_16_4"}},
		{"mysql-binary", "mysql"}:                      {"8.0.40", []string{"mysql-8.0.40"}},
		{"mysqld-mysql-server-binary", "mysql-server"}: {"8.4.3", []string{"mysql-8.4.3"}},
		{"mariadb-binary", "mariadb"}:                  {"11.4.4", []string{"mariadb-11.4.4"}},
		{"openssl-binary", "openssl"}:                  {"3.0.15", []string{"openssl-3.0.15", "OpenSSL_3_0_15"}},
		{"curl-binary", "curl"}:                        {"8.11.0", []string{"curl-8_11_0"}},
		{"busybox-binary", "busybox"}:                  {"1.36.1", []string{"1_36_1"}},
	}
	for pkg, want := range tags {
		e, ok := lookup(pkg[0], pkg[1])
		require.True(t, ok, pkg)
		require.Equal(t, want.tags, e.Tags(want.version), pkg)
	}

	// The classifier and the name must both belong to the entry, in the binary ecosystem.
	for _, p := range []model.Package{
		bin("mysql-binary", "percona-server"),
		bin("nodejs-binary", "php-cli"),
		bin("", "node"),
		{Ecosystem: "deb", Classifier: "nodejs-binary", Name: "node"},
	} {
		_, ok := upstream.Lookup(p)
		require.False(t, ok, p)
	}

	e, ok = upstream.ForCNA("PHP GROUP", "php")
	require.True(t, ok)
	require.Equal(t, "php", e.Key)
	for vp, key := range map[[2]string]string{
		{"php", "php"}: "php", {"NodeJS", "Node"}: "node", {"nodejs", "node.js"}: "node",
		{"Python Software Foundation", "CPython"}: "python", {"F5", "NGINX Open Source"}: "nginx",
		{"n/a", "PostgreSQL"}: "postgresql", {"OpenSSL", "OpenSSL"}: "openssl", {"curl", "curl"}: "curl",
	} {
		e, ok := upstream.ForCNA(vp[0], vp[1])
		require.True(t, ok, vp)
		require.Equal(t, key, e.Key, vp)
	}
	_, ok = upstream.ForCNA("Linux", "Linux")
	require.False(t, ok)

	repos := upstream.Repos()
	require.Len(t, repos, 15)
	for _, r := range repos {
		require.Equal(t, osv.NormalizeRepo(r), r)
	}
	require.Contains(t, repos, "github.com/php/php-src")

	traefik := bin("traefik-binary", "traefik")
	require.Equal(t, []string{"traefik"}, upstream.UncoveredClassified([]model.Package{
		bin("php-cli-binary", "php-cli"),
		traefik,
		traefik,
		{Ecosystem: "deb", Name: "openssl", Version: "3.0.15-1~deb12u1"},
	}))
	require.Empty(t, upstream.UncoveredClassified(nil))
}
