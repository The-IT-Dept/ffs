package config

import (
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"
)

// GlobChars are the characters that make an upgrades.overrides key, or a part of one, a path.Match
// glob: the metacharacters and the escape.
const GlobChars = "*?[\\"

// NormalizeRepoKey returns an upgrades.overrides key in the form ffs records image repositories in,
// as image references are normalised: a key whose first component is not a registry host (it has
// no "." or ":", is not "localhost" and holds none of GlobChars) is on Docker Hub, and a Docker Hub
// repository with a single path component is under "library". So "postgres" becomes
// "docker.io/library/postgres" and "bitnami/*" becomes "docker.io/bitnami/*".
func NormalizeRepoKey(key string) string {
	host, rest, found := strings.Cut(key, "/")
	if !found || (!strings.ContainsAny(host, ".:"+GlobChars) && host != "localhost") {
		host, rest = "docker.io", key
	}
	switch host {
	case "index.docker.io", "registry-1.docker.io":
		host = "docker.io"
	}
	if host == "docker.io" && !strings.Contains(rest, "/") {
		rest = "library/" + rest
	}
	return host + "/" + rest
}

// validGlob reports whether p is a valid path.Match pattern. path.Match checks the whole pattern
// whatever the name, so matching the empty name is enough.
func validGlob(p string) bool {
	_, err := path.Match(p, "")
	return err == nil
}

// validateOverrides checks every upgrades.overrides entry: the key is a valid repository glob, no
// two keys name the same repository once normalised, the pattern compiles with a named group
// "version", and every ignore entry is a valid tag glob.
func (u UpgradesConfig) validateOverrides(bad func(format string, a ...any)) {
	seen := map[string]string{}
	for _, repo := range slices.Sorted(maps.Keys(u.Overrides)) {
		o := u.Overrides[repo]
		if !validGlob(repo) {
			bad("upgrades.overrides[%s]: not a valid repository glob", repo)
		} else if n := NormalizeRepoKey(repo); seen[n] != "" {
			bad("upgrades.overrides[%s]: names the same repository as %s (%s)", repo, seen[n], n)
		} else {
			seen[n] = repo
		}
		re, err := regexp.Compile(o.Pattern)
		switch {
		case err != nil:
			bad("upgrades.overrides[%s].pattern: %v", repo, err)
		case re.SubexpIndex("version") < 0:
			bad("upgrades.overrides[%s].pattern: must have a named group \"version\"", repo)
		}
		for i, g := range o.Ignore {
			if !validGlob(g) {
				bad("upgrades.overrides[%s].ignore[%d]: %q is not a valid tag glob", repo, i, g)
			}
		}
	}
}
