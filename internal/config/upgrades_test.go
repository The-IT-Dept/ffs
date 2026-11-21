package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeRepoKey(t *testing.T) {
	for key, want := range map[string]string{
		"postgres":                      "docker.io/library/postgres",
		"docker.io/postgres":            "docker.io/library/postgres",
		"index.docker.io/postgres":      "docker.io/library/postgres",
		"bitnami/postgresql":            "docker.io/bitnami/postgresql",
		"bitnami/*":                     "docker.io/bitnami/*",
		"docker.io/library/postgres":    "docker.io/library/postgres",
		"registry.example.com/team/app": "registry.example.com/team/app",
		"localhost/app":                 "localhost/app",
		"localhost:5000/app":            "localhost:5000/app",
		"*.example.com/app":             "*.example.com/app",
		`registry\-1/app`:               `registry\-1/app`, // an escape makes the first component a host glob too
	} {
		require.Equal(t, want, NormalizeRepoKey(key), key)
	}
}

func TestValidate_UpgradeOverrides(t *testing.T) {
	good := TagOverride{Pattern: `^(?P<version>\d+)$`}
	for name, tc := range map[string]struct {
		overrides map[string]TagOverride
		want      string
	}{
		"bad repository glob": {map[string]TagOverride{"docker.io/[bitnami": good}, "upgrades.overrides[docker.io/[bitnami]: not a valid repository glob"},
		"bad ignore glob": {map[string]TagOverride{"postgres": {Pattern: good.Pattern, Ignore: []string{"*-rc", "17[.x"}}},
			`upgrades.overrides[postgres].ignore[1]: "17[.x" is not a valid tag glob`},
		"same repository twice": {map[string]TagOverride{"postgres": good, "docker.io/library/postgres": good},
			"upgrades.overrides[postgres]: names the same repository as docker.io/library/postgres"},
		"bad pattern": {map[string]TagOverride{"postgres": {Pattern: "("}}, "upgrades.overrides[postgres].pattern"},
	} {
		c := Default()
		c.Upgrades.Overrides = tc.overrides
		require.ErrorContains(t, c.Validate(), tc.want, name)
	}
	c := Default()
	c.Upgrades.Overrides = map[string]TagOverride{"postgres": {Pattern: good.Pattern, Ignore: []string{"*-rc*", "1[0-6].*"}},
		"bitnami/*": good, "docker.io/bitnami/postgres*": good}
	require.NoError(t, c.Validate())
}
