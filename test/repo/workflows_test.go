// Package repo checks repository files that are not Go code: workflows and user docs.
package repo

import (
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
		t.Run(base, func(t *testing.T) {
			data, err := os.ReadFile(path) //nolint:gosec // path comes from a fixed glob in the repo
			require.NoError(t, err)
			var wf map[string]any
			require.NoError(t, yaml.Unmarshal(data, &wf))

			for _, trigger := range triggers(t, wf) {
				require.NotContains(t, []string{"pull_request_target", "workflow_run"}, trigger, "forbidden trigger")
			}

			perms, ok := wf["permissions"]
			require.True(t, ok, "top-level permissions missing")
			require.Equal(t, map[string]any{}, perms, "top-level permissions must be {}")

			jobs, ok := wf["jobs"].(map[string]any)
			require.True(t, ok, "jobs missing")
			for name, j := range jobs {
				job, ok := j.(map[string]any)
				require.True(t, ok, "job %s", name)
				jp, ok := job["permissions"]
				require.True(t, ok, "job %s declares no permissions", name)
				if m, ok := jp.(map[string]any); ok && m["id-token"] == "write" {
					idToken = append(idToken, base+"/"+name)
				}
				if uses, ok := job["uses"].(string); ok {
					requirePinned(t, name, uses)
				}
				steps, _ := job["steps"].([]any)
				for i, s := range steps {
					step, ok := s.(map[string]any)
					require.True(t, ok, "job %s step %d", name, i)
					uses, ok := step["uses"].(string)
					if !ok {
						continue
					}
					requirePinned(t, name, uses)
					if strings.HasPrefix(uses, "actions/checkout@") {
						with, _ := step["with"].(map[string]any)
						require.Equal(t, false, with["persist-credentials"], "job %s step %d: checkout must set persist-credentials: false", name, i)
					}
				}
			}
		})
	}
	slices.Sort(idToken)
	require.Equal(t, []string{"release.yml/chart", "release.yml/image"}, idToken, "id-token: write is only for the release image and chart jobs")
}

// triggers returns the event names of the workflow's "on". YAML 1.1 reads a bare on key as the
// boolean true, which sigs.k8s.io/yaml renders as the key "true".
func triggers(t *testing.T, wf map[string]any) []string {
	t.Helper()
	on, ok := wf["on"]
	if !ok {
		on, ok = wf["true"]
	}
	require.True(t, ok, "workflow has no on")
	switch v := on.(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			s, ok := e.(string)
			require.True(t, ok, "on entry %v", e)
			out = append(out, s)
		}
		return out
	case map[string]any:
		out := make([]string, 0, len(v))
		for k := range v {
			out = append(out, k)
		}
		return out
	}
	t.Fatalf("unexpected on: %T", on)
	return nil
}

func requirePinned(t *testing.T, job, uses string) {
	t.Helper()
	if strings.HasPrefix(uses, "./") {
		return
	}
	require.Regexp(t, pinnedAction, uses, "job %s: actions must be pinned to a full commit SHA", job)
}
