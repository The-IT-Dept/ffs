// Package repo checks repository files that are not Go code: workflows and user docs.
package repo

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

var pinnedAction = regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+@[0-9a-f]{40}$`)

func TestWorkflows_PinnedAndLeastPrivilege(t *testing.T) {
	files, err := filepath.Glob("../../.github/workflows/*.yml")
	require.NoError(t, err)
	require.NotEmpty(t, files)

	var idToken []string // "<file>/<job>" for every job granted id-token: write
	for _, path := range files {
		base := filepath.Base(path)
		data, err := os.ReadFile(path) //nolint:gosec // path comes from a fixed glob in the repo
		require.NoError(t, err)
		var wf map[string]any
		require.NoError(t, yaml.Unmarshal(data, &wf), base)
		problems, jobs := workflowProblems(wf)
		require.Empty(t, problems, base)
		for _, j := range jobs {
			idToken = append(idToken, base+"/"+j)
		}
	}
	slices.Sort(idToken)
	require.Equal(t, []string{"release.yml/chart", "release.yml/image"}, idToken, "id-token: write is only for the release image and chart jobs")
}

// workflowProblems checks one workflow: no forbidden trigger, top-level permissions {}, every job's own permissions
// as a map of scopes, actions pinned to a commit and checkouts that keep no credentials. It returns what is wrong, and
// the jobs granted id-token: write.
func workflowProblems(wf map[string]any) (problems, idToken []string) {
	bad := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }
	on, err := triggers(wf)
	if err != nil {
		bad("%v", err)
	}
	for _, trigger := range on {
		if trigger == "pull_request_target" || trigger == "workflow_run" {
			bad("forbidden trigger %s", trigger)
		}
	}
	if perms, ok := wf["permissions"]; !ok {
		bad("top-level permissions missing")
	} else if m, ok := perms.(map[string]any); !ok || len(m) != 0 {
		bad("top-level permissions must be {}, not %v", perms)
	}

	jobs, ok := wf["jobs"].(map[string]any)
	if !ok {
		bad("jobs missing")
		return problems, nil
	}
	for _, name := range slices.Sorted(maps.Keys(jobs)) {
		job, ok := jobs[name].(map[string]any)
		if !ok {
			bad("job %s is not a map", name)
			continue
		}
		switch jp := job["permissions"].(type) {
		case nil:
			bad("job %s declares no permissions", name)
		case map[string]any:
			if jp["id-token"] == "write" {
				idToken = append(idToken, name)
			}
		default:
			// write-all and read-all grant every scope, id-token included for write-all.
			bad("job %s: permissions %v: list each scope it needs instead", name, jp)
		}
		if uses, ok := job["uses"].(string); ok && !pinned(uses) {
			bad("job %s: %s is not pinned to a full commit SHA", name, uses)
		}
		steps, _ := job["steps"].([]any)
		for i, s := range steps {
			step, ok := s.(map[string]any)
			if !ok {
				bad("job %s step %d is not a map", name, i)
				continue
			}
			uses, ok := step["uses"].(string)
			if !ok {
				continue
			}
			if !pinned(uses) {
				bad("job %s step %d: %s is not pinned to a full commit SHA", name, i, uses)
			}
			if strings.HasPrefix(uses, "actions/checkout@") {
				if with, _ := step["with"].(map[string]any); with["persist-credentials"] != false {
					bad("job %s step %d: checkout must set persist-credentials: false", name, i)
				}
			}
		}
	}
	return problems, idToken
}

// TestWorkflows_CheckerRejects: the checks above catch what they exist for, the string forms of permissions included
// (F55): write-all on a job grants id-token: write without naming it.
func TestWorkflows_CheckerRejects(t *testing.T) {
	const pin = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
	ok := `
on: {push: {branches: [main]}}
permissions: {}
jobs:
  build:
    permissions: {contents: read}
    steps:
      - uses: ` + pin + `
        with: {persist-credentials: false}
  sign:
    permissions: {contents: read, id-token: write}
    steps:
      - run: true
`
	parse := func(doc string) map[string]any {
		t.Helper()
		var wf map[string]any
		require.NoError(t, yaml.Unmarshal([]byte(doc), &wf))
		return wf
	}
	problems, idToken := workflowProblems(parse(ok))
	require.Empty(t, problems)
	require.Equal(t, []string{"sign"}, idToken)

	for name, c := range map[string]struct{ from, to, want string }{
		"job write-all":         {"permissions: {contents: read}\n    steps", "permissions: write-all\n    steps", "job build: permissions write-all"},
		"job read-all":          {"permissions: {contents: read}\n    steps", "permissions: read-all\n    steps", "job build: permissions read-all"},
		"job without":           {"    permissions: {contents: read}\n", "", "job build declares no permissions"},
		"top-level write-all":   {"permissions: {}\njobs", "permissions: write-all\njobs", "top-level permissions must be {}"},
		"top-level missing":     {"permissions: {}\njobs", "jobs", "top-level permissions missing"},
		"unpinned action":       {pin, "actions/checkout@v7", "is not pinned to a full commit SHA"},
		"checkout credentials":  {"with: {persist-credentials: false}", "with: {fetch-depth: 0}", "checkout must set persist-credentials: false"},
		"pull_request_target":   {"on: {push: {branches: [main]}}", "on: [pull_request_target]", "forbidden trigger pull_request_target"},
		"workflow_run as a map": {"on: {push: {branches: [main]}}", "on: {workflow_run: {workflows: [ci]}}", "forbidden trigger workflow_run"},
	} {
		doc := strings.Replace(ok, c.from, c.to, 1)
		require.NotEqual(t, ok, doc, name)
		problems, _ := workflowProblems(parse(doc))
		require.NotEmpty(t, problems, name)
		require.Contains(t, strings.Join(problems, "\n"), c.want, name)
	}
}

// triggers returns the event names of the workflow's "on". YAML 1.1 reads a bare on key as the
// boolean true, which sigs.k8s.io/yaml renders as the key "true".
func triggers(wf map[string]any) ([]string, error) {
	on, ok := wf["on"]
	if !ok {
		on, ok = wf["true"]
	}
	if !ok {
		return nil, fmt.Errorf("workflow has no on")
	}
	switch v := on.(type) {
	case string:
		return []string{v}, nil
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			s, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("on entry %v is not a string", e)
			}
			out = append(out, s)
		}
		return out, nil
	case map[string]any:
		out := make([]string, 0, len(v))
		for k := range v {
			out = append(out, k)
		}
		return out, nil
	}
	return nil, fmt.Errorf("unexpected on: %T", on)
}

func pinned(uses string) bool {
	return strings.HasPrefix(uses, "./") || pinnedAction.MatchString(uses)
}

// releaseJob is the part of a release or e2e workflow job the release checks read.
type releaseJob struct {
	Needs    any    `json:"needs"` // a job name or a list of them
	RunsOn   string `json:"runs-on"`
	Strategy struct {
		Matrix struct {
			Include []map[string]string `json:"include"`
		} `json:"matrix"`
	} `json:"strategy"`
	Steps []ciStep `json:"steps"`
}

func readJobs(t *testing.T, path string) map[string]releaseJob {
	t.Helper()
	var wf struct {
		Jobs map[string]releaseJob `json:"jobs"`
	}
	require.NoError(t, yaml.Unmarshal([]byte(readFile(t, path)), &wf), path)
	return wf.Jobs
}

// needs returns the jobs j needs directly.
func (j releaseJob) needs() []string {
	switch v := j.Needs.(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, e := range v {
			out = append(out, fmt.Sprint(e))
		}
		return out
	}
	return nil
}

// stepRuns joins the run of every step.
func stepRuns(steps []ciStep) string {
	var out []string
	for _, s := range steps {
		out = append(out, s.Run)
	}
	return strings.Join(out, "\n")
}

// archRunners maps a matrix's arch entries to their runners.
func archRunners(j releaseJob) map[string]string {
	out := map[string]string{}
	for _, e := range j.Strategy.Matrix.Include {
		out[e["arch"]] = e["runner"]
	}
	return out
}

var nativeRunners = map[string]string{"amd64": "ubuntu-24.04", "arm64": "ubuntu-24.04-arm"}

// TestWorkflows_ReleaseIsGatedAndMultiArch: a tag publishes only a commit on main that passes make test (F116), and the
// image is an index of linux/amd64 and linux/arm64 built natively, signed and attested per platform (#17).
func TestWorkflows_ReleaseIsGatedAndMultiArch(t *testing.T) {
	jobs := readJobs(t, "../../.github/workflows/release.yml")

	gate := jobs["test"]
	require.Contains(t, stepRuns(gate.Steps), "git merge-base --is-ancestor HEAD origin/main")
	require.Contains(t, stepRuns(gate.Steps), "make test")
	i := slices.IndexFunc(gate.Steps, func(s ciStep) bool { return strings.HasPrefix(s.Uses, "actions/checkout@") })
	require.GreaterOrEqual(t, i, 0)
	require.EqualValues(t, 0, gate.Steps[i].With["fetch-depth"], "origin/main must be fetched")

	// Every other job needs the gate, directly or through another job.
	var gated func(name string) bool
	gated = func(name string) bool {
		return slices.ContainsFunc(jobs[name].needs(), func(n string) bool { return n == "test" || gated(n) })
	}
	for name := range jobs {
		if name != "test" {
			require.True(t, gated(name), "release job %s does not wait for the test job", name)
		}
	}

	build := jobs["build"]
	require.Equal(t, nativeRunners, archRunners(build))
	require.Equal(t, "${{ matrix.runner }}", build.RunsOn)
	i = slices.IndexFunc(build.Steps, func(s ciStep) bool { return strings.HasPrefix(s.Uses, "docker/build-push-action@") })
	require.GreaterOrEqual(t, i, 0)
	require.Equal(t, "linux/${{ matrix.arch }}", build.Steps[i].With["platforms"], "one native platform per runner")
	require.Contains(t, build.Steps[i].With["outputs"], "push-by-digest=true")

	image := stepRuns(jobs["image"].Steps)
	require.Contains(t, image, "docker buildx imagetools create")
	require.Contains(t, image, `cosign sign --yes --recursive "ghcr.io/the-it-dept/ffs@${DIGEST}"`)
	require.Contains(t, image, `for p in "amd64 ${AMD64}" "arm64 ${ARM64}"; do`, "an SBOM attestation per platform")
	var provenance []any
	for _, s := range jobs["image"].Steps {
		if strings.HasPrefix(s.Uses, "actions/attest-build-provenance@") {
			provenance = append(provenance, s.With["subject-digest"])
		}
	}
	require.Equal(t, []any{"${{ steps.index.outputs.digest }}", "${{ steps.index.outputs.amd64 }}", "${{ steps.index.outputs.arm64 }}"},
		provenance, "SLSA provenance for the index and each platform")

	notes := stepRuns(jobs["release"].Steps)
	require.Contains(t, notes, `= "linux/amd64 linux/arm64"`, "the release notes check both platforms are in the index")
	require.Contains(t, notes, "gh attestation verify oci://ghcr.io/the-it-dept/ffs@$pd", "and each platform's provenance")
}

// TestWorkflows_E2EOnBothArchitectures: the kind suite runs natively on amd64 and arm64 (#17), and kind is installed
// once, by make e2e at the Makefile's pinned version (F55).
func TestWorkflows_E2EOnBothArchitectures(t *testing.T) {
	jobs := readJobs(t, "../../.github/workflows/e2e.yml")
	require.Len(t, jobs, 1)
	e2e := jobs["e2e"]
	require.Equal(t, nativeRunners, archRunners(e2e))
	require.Equal(t, "${{ matrix.runner }}", e2e.RunsOn)
	require.Contains(t, stepRuns(e2e.Steps), "make e2e")
	for _, s := range e2e.Steps {
		require.False(t, strings.HasPrefix(s.Uses, "helm/kind-action@"), "kind comes from make e2e only")
	}
	require.Regexp(t, `(?m)^\tGOBIN=\$\(CURDIR\)/bin go install sigs\.k8s\.io/kind@\$\(KIND_VERSION\)$`, readFile(t, "../../Makefile"))
}
