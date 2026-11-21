package chart

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

// v001Chart is a copy of the chart whose defaults are v0.0.1's values.yaml (testdata/values-v0.0.1.yaml, from the
// v0.0.1 tag), which is what helm upgrade --reuse-values renders from v0.0.1: Helm replaces the new chart's defaults
// with the previous release's values, and the --set values of the upgrade go on top.
func v001Chart(t *testing.T) string {
	t.Helper()
	dir := copyChart(t, nil)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "values.yaml"), []byte(readFile(t, "testdata/values-v0.0.1.yaml")), 0o600))
	return dir
}

// TestChart_ReuseValuesFromV001 (W47): under --reuse-values from v0.0.1 the chart renders, keeps v0.0.1's defaults
// (the README says so), and counts nodeAgent.networkPolicy.enabled as set only when it differs from v0.0.1's
// default, so the deprecation notice appears only for a value the user chose.
func TestChart_ReuseValuesFromV001(t *testing.T) {
	const deprecated = "nodeAgent.networkPolicy.enabled is deprecated"
	for _, c := range []struct {
		name   string
		sets   []string
		policy bool
		notice bool
	}{
		{"v0.0.1 defaults", nil, true, false},
		{"new key on", []string{"networkPolicy.enabled=true"}, true, false},
		{"new key off", []string{"networkPolicy.enabled=false"}, false, false},
		// v0.0.1's default is true, so a false was set in v0.0.1 and is still honoured.
		{"old key off from v0.0.1", []string{"nodeAgent.networkPolicy.enabled=false"}, false, true},
		{"old key off, new key on", []string{"nodeAgent.networkPolicy.enabled=false", "networkPolicy.enabled=true"}, false, true},
		{"old key unset, new key off", []string{"nodeAgent.networkPolicy.enabled=null", "networkPolicy.enabled=false"}, false, false},
	} {
		notes, o := renderNotesIn(t, v001Chart(t), c.sets...)
		require.Equal(t, c.policy, o.has("NetworkPolicy", "ffs"), c.name)
		require.Contains(t, notes, "kubectl -n ffs port-forward deploy/ffs 8080", c.name)
		if c.notice {
			require.Contains(t, notes, deprecated, c.name)
		} else {
			require.NotContains(t, notes, "deprecated", c.name)
		}
	}

	// v0.0.1's defaults are kept: the agent on amd64 only and the 2Gi controller limit. A value v0.0.1 did not have
	// takes the template's default.
	_, o := renderNotesIn(t, v001Chart(t))
	ds := as[appsv1.DaemonSet](t, o.get(t, "DaemonSet", "ffs-agent"))
	terms := ds.Spec.Template.Spec.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms
	require.Equal(t, []string{"amd64"}, terms[0].MatchExpressions[0].Values)
	ps := as[appsv1.Deployment](t, o.get(t, "Deployment", "ffs")).Spec.Template.Spec
	ctl := container(t, ps, "controller")
	require.Equal(t, resource.MustParse("2Gi"), ctl.Resources.Limits[corev1.ResourceMemory])
	require.Contains(t, ctl.Args, "--zap-log-level=info")
}
