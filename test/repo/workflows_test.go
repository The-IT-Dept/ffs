// Package repo checks repository files that are not Go code: workflows and user docs.
package repo

import (
	"fmt"
	"maps"
	"os"
	"os/exec"
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

// TestWorkflows_ReleaseIsGatedAndMultiArch: a tag publishes only a commit on main or a release branch that passes make
// test (F116, W49; TestWorkflows_ReleaseGate runs the check), and the image is an index of linux/amd64 and linux/arm64
// built natively, signed and attested per platform (#17).
func TestWorkflows_ReleaseIsGatedAndMultiArch(t *testing.T) {
	jobs := readJobs(t, "../../.github/workflows/release.yml")

	gate := jobs["test"]
	require.GreaterOrEqual(t, stepIndex(gate, releaseGateStep), 0)
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
	require.Contains(t, notes, `gh attestation verify "oci://ghcr.io/the-it-dept/ffs@$pd"`, "and each platform's provenance")
	require.Contains(t, notes, `test "$(printf '%s\n' "$PDS" | grep -c .)" = 2`, "the platform loop fails closed: exactly two platform images")
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

	// kubectl is installed at the Kubernetes version of the kind node image, read from hack/e2e-kind.sh rather than
	// repeated in the workflow.
	i := stepIndex(e2e, "Install kubectl")
	require.GreaterOrEqual(t, i, 0)
	run := e2e.Steps[i].Run
	require.NotContains(t, run, "v1.")
	lines := strings.Split(run, "\n")
	j := slices.IndexFunc(lines, func(l string) bool { return strings.HasPrefix(l, "base=") })
	require.Positive(t, j)
	out, err := command(t, "../..", nil, "bash", "-c", strings.Join(lines[:j], "\n")+"\necho \"${version}\"\n").CombinedOutput()
	require.NoError(t, err, "%s", out)
	node := regexp.MustCompile(`(?m)^node_image='kindest/node:(v\d+\.\d+\.\d+)@sha256:[0-9a-f]{64}'$`).FindStringSubmatch(readFile(t, "../../hack/e2e-kind.sh"))
	require.NotNil(t, node)
	require.Equal(t, node[1]+"\n", string(out))
}

// stepIndex returns the index of the job's step called name, or -1.
func stepIndex(j releaseJob, name string) int {
	return slices.IndexFunc(j.Steps, func(s ciStep) bool { return s.Name == name })
}

// command runs name with args in dir, with the test's environment less any git or GitHub Actions settings, plus env.
// git reads no global or system configuration and commits as a fixed test identity.
func command(t *testing.T, dir string, env []string, name string, args ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), name, args...) //nolint:gosec // G204: git and bash on this repository's own workflow scripts
	cmd.Dir = dir
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "GIT_") && !strings.HasPrefix(kv, "GITHUB_") && !strings.HasPrefix(kv, "RUNNER_") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(cmd.Env, "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com", "GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com")
	cmd.Env = append(cmd.Env, env...)
	return cmd
}

const releaseGateStep = "Require the tagged commit to be on main or a release branch"

// TestWorkflows_ReleaseGate runs the release gate's script in a scratch repository (W49): a tag publishes a commit on
// main or on a release/* branch, where release candidates are tagged before the branch is merged, and nothing else.
func TestWorkflows_ReleaseGate(t *testing.T) {
	gate := readJobs(t, "../../.github/workflows/release.yml")["test"]
	i := stepIndex(gate, releaseGateStep)
	require.GreaterOrEqual(t, i, 0)
	script := gate.Steps[i].Run

	dir := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		out, err := command(t, dir, nil, "git", args...).CombinedOutput()
		require.NoError(t, err, "git %v: %s", args, out)
		return strings.TrimSpace(string(out))
	}
	commit := func(msg string) string {
		t.Helper()
		git("commit", "-q", "--allow-empty", "-m", msg)
		return git("rev-parse", "HEAD")
	}
	git("init", "-q", "-b", "main")
	base := commit("base")
	onMain := commit("on main")
	git("checkout", "-q", "-b", "release/v0.0.2", base)
	onRelease := commit("on release/v0.0.2")
	git("checkout", "-q", "-b", "release/v0.0.3/fixes", base)
	onNested := commit("on release/v0.0.3/fixes")
	git("checkout", "-q", "-b", "feature", base)
	onFeature := commit("on feature")
	git("checkout", "-q", "-b", "release-notes", base) // starts like a release branch, but is not one
	onLookalike := commit("on release-notes")
	// As actions/checkout with fetch-depth 0 leaves them: the remote's branches under refs/remotes/origin.
	for branch, sha := range map[string]string{"main": onMain, "release/v0.0.2": onRelease, "release/v0.0.3/fixes": onNested,
		"feature": onFeature, "release-notes": onLookalike} {
		git("update-ref", "refs/remotes/origin/"+branch, sha)
	}

	for _, c := range []struct {
		name, commit string
		released     bool
	}{
		{"main's history", base, true},
		{"main", onMain, true},
		{"a release branch", onRelease, true},
		{"a nested release branch", onNested, true},
		{"another branch", onFeature, false},
		{"a branch named like a release branch", onLookalike, false},
	} {
		git("checkout", "-q", "--detach", c.commit)
		out, err := command(t, dir, []string{"GITHUB_REF_NAME=v0.0.2-rc.1"}, "bash", "-c", script).CombinedOutput()
		if c.released {
			require.NoError(t, err, "%s: %s", c.name, out)
		} else {
			require.Error(t, err, "%s: %s", c.name, out)
			require.Contains(t, string(out), "which is not on main or a release/* branch", c.name)
		}
	}
}

// TestWorkflows_ReleaseVerifiesBeforePublishing (W16): the release job writes its notes' Verify block to verify.sh,
// runs it against the published image and chart, and only then creates and publishes the release. Any failing command
// fails the step, and so does a last line other than "pinned".
func TestWorkflows_ReleaseVerifiesBeforePublishing(t *testing.T) {
	job := readJobs(t, "../../.github/workflows/release.yml")["release"]
	write := stepIndex(job, "Write the release notes")
	verify := stepIndex(job, "Verify the published image and chart with the notes' commands")
	create := slices.IndexFunc(job.Steps, func(s ciStep) bool { return strings.Contains(s.Run, "gh release create") })
	require.True(t, write >= 0 && write < verify && verify < create, "write %d, verify %d, create %d", write, verify, create)
	for _, action := range []string{"sigstore/cosign-installer@", "azure/setup-helm@", "docker/login-action@"} {
		require.True(t, slices.ContainsFunc(job.Steps[:verify], func(s ciStep) bool { return strings.HasPrefix(s.Uses, action) }),
			"the release job sets up %s before verifying", action)
	}
	require.Contains(t, stepRuns(job.Steps[:verify]), "go install \"github.com/google/go-containerregistry/cmd/crane@${v}\"")

	// The notes' sh block is verify.sh, byte for byte.
	dir := t.TempDir()
	d, cd := "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64)
	out, err := command(t, dir, []string{"GITHUB_REF_NAME=v1.2.3-rc.1", "VERSION=1.2.3-rc.1", "DIGEST=" + d, "CHART_DIGEST=" + cd},
		"bash", "-c", job.Steps[write].Run).CombinedOutput()
	require.NoError(t, err, "%s", out)
	script := readFile(t, filepath.Join(dir, "verify.sh"))
	notes := readFile(t, filepath.Join(dir, "notes.md"))
	block := regexp.MustCompile("(?s)\n## Verify\n\n```sh\n(.*)```\n$").FindStringSubmatch(notes)
	require.NotNil(t, block, notes)
	require.Equal(t, script, block[1])
	require.True(t, strings.HasPrefix(script, "TAG=v1.2.3-rc.1 V=1.2.3-rc.1\nD="+d+"\nCD="+cd+"\n"), script)
	loop := regexp.MustCompile(`(?s)\nfor pd in [^\n]*; do\n(.*?)\ndone\n`).FindStringSubmatch(script)
	require.NotNil(t, loop, script)
	for _, want := range []string{
		`cosign verify "ghcr.io/the-it-dept/ffs@$pd" --certificate-identity "$ID"`,
		`cosign verify-attestation --type spdxjson "ghcr.io/the-it-dept/ffs@$pd" --certificate-identity "$ID"`,
		`gh attestation verify "oci://ghcr.io/the-it-dept/ffs@$pd"`,
	} {
		require.Contains(t, loop[1], want, "each platform image is verified")
	}
	require.True(t, strings.HasSuffix(script, " && echo pinned\n"), script)
	out, err = command(t, dir, nil, "bash", "-n", "verify.sh").CombinedOutput()
	require.NoError(t, err, "%s", out)

	for body, passes := range map[string]bool{
		"echo checked\necho pinned\n":         true,
		"false\necho pinned\n":                false, // a failing command anywhere
		"echo pinned\nfalse\n":                false,
		"echo checked\n":                      false, // no pinned
		"test a = b && echo pinned\n":         false, // the image digest the chart pins differs
		"echo $FFS_TEST_UNSET\necho pinned\n": false, // an unset variable
	} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "verify.sh"), []byte(body), 0o600))
		out, err := command(t, dir, nil, "bash", "-c", job.Steps[verify].Run).CombinedOutput()
		require.Equal(t, passes, err == nil, "%q: %s", body, out)
	}
}
