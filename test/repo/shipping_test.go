package repo

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

func TestShipping_NodeVersionPinnedConsistently(t *testing.T) {
	v := strings.TrimSpace(readFile(t, "../../ui/.nvmrc"))
	require.Equal(t, "26.13.1", v)
	major, err := strconv.Atoi(strings.SplitN(v, ".", 2)[0])
	require.NoError(t, err)
	var pkg struct {
		Engines struct {
			Node string `json:"node"`
		} `json:"engines"`
	}
	require.NoError(t, json.Unmarshal([]byte(readFile(t, "../../ui/package.json")), &pkg))
	require.Equal(t, fmt.Sprintf(">=%s <%d", v, major+1), pkg.Engines.Node)
	require.Regexp(t, `(?m)^FROM --platform=\$BUILDPLATFORM node:`+regexp.QuoteMeta(v)+`-trixie-slim@sha256:[0-9a-f]{64} AS ui$`,
		readFile(t, "../../Dockerfile"))
}

func TestShipping_DockerfileBuildsUIAndShipsManifests(t *testing.T) {
	df := readFile(t, "../../Dockerfile")
	require.Contains(t, df, "FROM --platform=$BUILDPLATFORM node:26.13.1-trixie-slim@sha256:e6bedef217677b276c591795e169840edd9096dbf13f29df8ef8d1856b8820bc AS ui\n")
	require.Contains(t, df, "RUN npm ci\n")
	require.NotContains(t, df, "npm install")
	require.NotRegexp(t, `NODE_ENV[= ]+production`, df) // npm ci would skip the devDependencies the build needs
	require.Contains(t, df, "RUN npm run build && node scripts/prodtree.mjs manifests /out/ui-sbom\n")
	dist, build := strings.Index(df, "COPY --from=ui /src/internal/web/ui/dist ./internal/web/ui/dist\n"), strings.Index(df, "go build")
	require.Positive(t, dist)
	require.Less(t, dist, build)
	require.Greater(t, strings.Index(df, "COPY --from=ui /out/ui-sbom /usr/share/ffs/ui/\n"), strings.LastIndex(df, "\nFROM "))
}

func TestShipping_DockerignoreKeepsUIBuildOutputOut(t *testing.T) {
	lines := strings.Split(readFile(t, "../../.dockerignore"), "\n")
	for _, want := range []string{"ui/node_modules", "ui/test-results", "ui/playwright-report", "ui/e2e/screenshots",
		"internal/web/ui/dist/*", "!internal/web/ui/dist/.keep"} {
		require.Contains(t, lines, want)
	}
	require.Less(t, slices.Index(lines, "internal/web/ui/dist/*"), slices.Index(lines, "!internal/web/ui/dist/.keep")) // exception must follow
}

// dependabotUpdate is one updates entry of .github/dependabot.yml.
type dependabotUpdate struct {
	Ecosystem string `json:"package-ecosystem"`
	Directory string `json:"directory"`
	Schedule  struct {
		Interval string `json:"interval"`
	} `json:"schedule"`
	Cooldown struct {
		DefaultDays int `json:"default-days"`
	} `json:"cooldown"`
	Groups map[string]dependabotGroup `json:"groups"`
}

type dependabotGroup struct {
	Patterns []string `json:"patterns"`
}

func TestShipping_DependabotUpdatesUIWeeklyInOneGroup(t *testing.T) {
	var cfg struct {
		Updates []dependabotUpdate `json:"updates"`
	}
	require.NoError(t, yaml.Unmarshal([]byte(readFile(t, "../../.github/dependabot.yml")), &cfg))
	npm := slices.DeleteFunc(slices.Clone(cfg.Updates), func(u dependabotUpdate) bool { return u.Ecosystem != "npm" })
	require.Len(t, npm, 1)
	u := npm[0]
	require.Equal(t, "/ui", u.Directory)
	require.Equal(t, "weekly", u.Schedule.Interval)
	require.Equal(t, 7, u.Cooldown.DefaultDays)
	require.Equal(t, map[string]dependabotGroup{"ui": {Patterns: []string{"*"}}}, u.Groups)
}

// ciStep and ciJob are the parts of a workflow the shipping checks read.
type ciStep struct {
	Uses             string         `json:"uses"`
	Run              string         `json:"run"`
	If               string         `json:"if"`
	With             map[string]any `json:"with"`
	TimeoutMinutes   int            `json:"timeout-minutes"`
	WorkingDirectory string         `json:"working-directory"`
}

type ciJob struct {
	Env   map[string]any `json:"env"`
	Steps []ciStep       `json:"steps"`
}

func readWorkflow(t *testing.T, path string) map[string]ciJob {
	t.Helper()
	var wf struct {
		Jobs map[string]ciJob `json:"jobs"`
	}
	require.NoError(t, yaml.Unmarshal([]byte(readFile(t, path)), &wf), path)
	return wf.Jobs
}

// runs is every step's run of a job, one per line.
func runs(j ciJob) string {
	var out []string
	for _, s := range j.Steps {
		if s.Run != "" {
			out = append(out, s.Run)
		}
	}
	return strings.Join(out, "\n")
}

func TestShipping_CIRunsUIJobs(t *testing.T) {
	jobs := readWorkflow(t, "../../.github/workflows/ci.yml")
	for _, name := range []string{"test", "lint", "licenses", "ui", "ui-e2e", "bench"} {
		require.Contains(t, jobs, name)
	}

	test := runs(jobs["test"])
	require.Contains(t, test, "npm ci")
	require.Contains(t, test,
		"make generate && git diff --exit-code -- api config charts/ffs/crds internal/web/apigen ui/src/api/schema.d.ts")

	ui := jobs["ui"]
	for _, want := range []string{"npm ci", "npm run check:scripts", "npm run licenses", "npm run typecheck", "npm test", "npm run build",
		"npm run lint:api"} {
		require.Contains(t, runs(ui), want)
	}
	i := slices.IndexFunc(ui.Steps, func(s ciStep) bool { return s.Run == "npm run build" })
	require.GreaterOrEqual(t, i, 0, "the ui job builds")
	require.Equal(t, 2, ui.Steps[i].TimeoutMinutes, "the build has two minutes (spec §9)")
	require.Equal(t, "off", ui.Env["REDOCLY_TELEMETRY"])

	e2e := jobs["ui-e2e"]
	require.Contains(t, runs(e2e), "npx playwright install --with-deps chromium")
	require.Contains(t, runs(e2e), "make ui-e2e")
	require.True(t, slices.ContainsFunc(e2e.Steps, func(s ciStep) bool {
		return strings.HasPrefix(s.Uses, "actions/upload-artifact@") && s.If == "always()" && s.With["name"] == "ui-screenshots" &&
			s.With["path"] == "ui/e2e/screenshots/"
	}), "the screenshots are uploaded on every run")

	require.Contains(t, runs(jobs["bench"]), "make bench-api")

	files, err := filepath.Glob("../../.github/workflows/*.yml")
	require.NoError(t, err)
	require.NotEmpty(t, files)
	setupNodes := 0
	for _, path := range files {
		for name, j := range readWorkflow(t, path) {
			require.NotContains(t, runs(j), "npm install", "%s %s: install only with npm ci", path, name)
			for _, s := range j.Steps {
				if !strings.HasPrefix(s.Uses, "actions/setup-node@") {
					continue
				}
				setupNodes++
				require.Equal(t, "actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1", s.Uses, "%s %s", path, name)
				require.Equal(t, "ui/.nvmrc", s.With["node-version-file"], "%s %s", path, name)
			}
		}
	}
	require.Positive(t, setupNodes)

	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}
	require.NoError(t, json.Unmarshal([]byte(readFile(t, "../../ui/package.json")), &pkg))
	require.True(t, strings.HasPrefix(pkg.Scripts["lint:api"], "REDOCLY_TELEMETRY=off "), "local runs never report to Redocly either")
}
