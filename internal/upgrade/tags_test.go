package upgrade

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/model"
)

func mustParse(t *testing.T, tag string) TagVersion {
	t.Helper()
	v, ok := ParseTag(tag)
	require.True(t, ok, tag)
	return v
}

func TestParseTag(t *testing.T) {
	v := mustParse(t, "1.25")
	require.Equal(t, []int{1, 25}, v.Release)
	v = mustParse(t, "v1.20.4")
	require.Equal(t, "v", v.Prefix)
	require.Equal(t, []int{1, 20, 4}, v.Release)
	v = mustParse(t, "1.30.7-alpine3.24-slim")
	require.Equal(t, []int{1, 30, 7}, v.Release)
	require.Equal(t, "alpine3.24-slim", v.Suffix)
	v = mustParse(t, "17.12-bookworm")
	require.Equal(t, []int{17, 12}, v.Release)
	require.Equal(t, "bookworm", v.Suffix)
	v = mustParse(t, "19rc2-trixie")
	require.Equal(t, []int{19}, v.Release)
	require.Equal(t, "rc2", v.Pre)
	require.Equal(t, "trixie", v.Suffix)
	require.Equal(t, "beta.0", mustParse(t, "v1.21.0-beta.0").Suffix)
	v = mustParse(t, "20241010")
	require.True(t, v.Date)
	require.Equal(t, []int{20241010}, v.Release)
	for _, tag := range []string{"latest", "stable-alpine", "main", "0a1b2c3d", "sha-4f1c2e9"} {
		_, ok := ParseTag(tag)
		require.False(t, ok, tag)
	}
}

func TestCompatible(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"1.25", "1.26", true},
		{"1.25", "1.25.1", false},
		{"17.12-bookworm", "17.13-trixie", false},
		{"v1.20.4", "1.20.5", false},
		{"20241010", "20241115", true},
		{"20241010", "202410101200", false},
		{"20241010", "1.2.3", false},
	} {
		require.Equal(t, tc.want, Compatible(mustParse(t, tc.a), mustParse(t, tc.b)), "%s %s", tc.a, tc.b)
	}
}

func TestTierBetween(t *testing.T) {
	p, err := NewParser(nil)
	require.NoError(t, err)
	pp := func(repo, tag string) TagVersion {
		v, ok := p.Parse(repo, tag)
		require.True(t, ok, tag)
		return v
	}
	g := func(a, b string) model.Tier { return TierBetween(mustParse(t, a), mustParse(t, b)) }
	require.Equal(t, model.TierPatch, g("1.30.6", "1.30.7"))
	require.Equal(t, model.TierMinor, g("1.30.7", "1.31.9"))
	require.Equal(t, model.TierMajor, g("17.12", "18.7"))
	require.Equal(t, model.TierMinor, g("1.30", "1.31"))
	require.Equal(t, model.TierRefresh, g("1.30", "1.30"))
	require.Equal(t, model.TierPatch, g("20241010", "20241115"))
	const bn = "docker.io/bitnami/postgresql"
	require.Equal(t, model.TierPatch, TierBetween(pp(bn, "17.5.0-debian-12-r3"), pp(bn, "17.5.0-debian-12-r20")))
}

func TestCompare(t *testing.T) {
	require.Negative(t, Compare(mustParse(t, "19rc2"), mustParse(t, "19")))
	p, err := NewParser(nil)
	require.NoError(t, err)
	const gr = "docker.io/grafana/grafana"
	pp := func(repo, tag string) TagVersion {
		v, ok := p.Parse(repo, tag)
		require.True(t, ok, tag)
		return v
	}
	require.Negative(t, Compare(pp(gr, "12.3.6"), pp(gr, "12.3.6-security-04")))
	require.Negative(t, Compare(pp(gr, "12.3.6-security-04"), pp(gr, "12.3.7")))
	const bn = "docker.io/bitnami/postgresql"
	require.Negative(t, Compare(pp(bn, "17.5.0-debian-12-r9"), pp(bn, "17.5.0-debian-12-r20")))
}

func TestFloatingVersion(t *testing.T) {
	v, ok := FloatingVersion("stable-alpine", "1.30.7")
	require.True(t, ok)
	require.Equal(t, []int{1, 30, 7}, v.Release)
	require.Equal(t, "alpine", v.Suffix)
	v, ok = FloatingVersion("latest", "2.1.0")
	require.True(t, ok)
	require.Equal(t, []int{2, 1, 0}, v.Release)
	require.Equal(t, "", v.Suffix)
	_, ok = FloatingVersion("latest", "")
	require.False(t, ok)
}

func fixture(t *testing.T, name string) []string {
	t.Helper()
	b, err := os.ReadFile("testdata/tags/" + name) //nolint:gosec // G304: name is a constant fixture filename from this test file
	require.NoError(t, err)
	return strings.Fields(string(b))
}

func best(t *testing.T, p *Parser, repo, cur string, tags []string) map[model.Tier]string {
	t.Helper()
	cv, ok := p.Parse(repo, cur)
	require.True(t, ok, cur)
	out := map[model.Tier]string{}
	for tier, v := range p.Best(repo, cv, tags) {
		out[tier] = v.Tag
	}
	return out
}

func TestParser_Fixtures(t *testing.T) {
	p, err := NewParser(nil)
	require.NoError(t, err)
	const (
		nginx = "docker.io/library/nginx"
		pg    = "docker.io/library/postgres"
		bn    = "docker.io/bitnamilegacy/postgresql"
		gr    = "docker.io/grafana/grafana"
		cm    = "quay.io/jetstack/cert-manager-controller"
	)
	T := model.TierPatch
	M := model.TierMinor
	J := model.TierMajor
	nt := fixture(t, "nginx.txt")
	require.Equal(t, map[model.Tier]string{T: "1.30.7", M: "1.31.9"}, best(t, p, nginx, "1.30.6", nt))
	require.Equal(t, map[model.Tier]string{M: "1.31-alpine-slim"}, best(t, p, nginx, "1.30-alpine-slim", nt))
	pt := fixture(t, "postgres.txt")
	require.Equal(t, map[model.Tier]string{J: "18.7-bookworm"}, best(t, p, pg, "16.16-bookworm", pt))
	require.Equal(t, map[model.Tier]string{M: "17.12", J: "18.7"}, best(t, p, pg, "17.10", pt))
	bt := fixture(t, "bitnami-postgresql.txt")
	require.Equal(t, map[model.Tier]string{T: "17.5.0-debian-12-r20", M: "17.6.0-debian-12-r4"}, best(t, p, bn, "17.5.0-debian-12-r3", bt))
	for _, tag := range bt {
		if strings.HasPrefix(tag, "sha256-") || strings.HasSuffix(tag, "-metadata") {
			_, ok := p.Parse(bn, tag)
			require.False(t, ok, tag)
		}
	}
	gt := fixture(t, "grafana.txt")
	require.Equal(t, map[model.Tier]string{T: "12.3.11", M: "12.4.15", J: "13.3.1"}, best(t, p, gr, "12.3.6", gt))
	require.Equal(t, map[model.Tier]string{T: "12.3.11-ubuntu", M: "12.4.15-ubuntu", J: "13.3.1-ubuntu"}, best(t, p, gr, "12.3.6-ubuntu", gt))
	_, ok := p.Parse(gr, "12.3.0-17718666199")
	require.False(t, ok)
	ct := fixture(t, "cert-manager.txt")
	require.Equal(t, map[model.Tier]string{T: "v1.20.5", M: "v1.21.3"}, best(t, p, cm, "v1.20.4", ct))
	for _, tag := range []string{"608111629", "v1.21.0-alpha.1"} {
		_, ok := p.Parse(cm, tag)
		require.False(t, ok, tag)
	}
}

func TestParser_Velero(t *testing.T) {
	p, err := NewParser(nil)
	require.NoError(t, err)
	const repo = "docker.io/velero/velero"
	_, ok := p.Parse(repo, "v1.18.4")
	require.True(t, ok)
	for _, tag := range []string{"1220", "v1.18.4-linux-amd64", "release-1.19-dev"} {
		_, ok := p.Parse(repo, tag)
		require.False(t, ok, tag)
	}
}

func TestParser_ConfigOverride(t *testing.T) {
	const repo = "registry.example.com/team/app"
	p, err := NewParser(map[string]config.TagOverride{
		repo:                                 {Pattern: `^release-(?P<version>\d+\.\d+\.\d+)$`, Ignore: []string{"release-0.*"}},
		"docker.io/bitnamilegacy/postgresql": {Pattern: `^pg(?P<version>\d+)$`},
	})
	require.NoError(t, err)
	v, ok := p.Parse(repo, "release-1.4.2")
	require.True(t, ok)
	require.Equal(t, []int{1, 4, 2}, v.Release)
	_, ok = p.Parse(repo, "1.4.3")
	require.False(t, ok)
	_, ok = p.Parse(repo, "release-0.9.0")
	require.False(t, ok)
	_, ok = p.Parse("docker.io/bitnamilegacy/postgresql", "17.5.0-debian-12-r3")
	require.False(t, ok)
	v, ok = p.Parse("docker.io/bitnamilegacy/postgresql", "pg17")
	require.True(t, ok)
	require.Equal(t, []int{17}, v.Release)

	_, err = NewParser(map[string]config.TagOverride{"x": {Pattern: "("}})
	require.ErrorContains(t, err, "x")
}
