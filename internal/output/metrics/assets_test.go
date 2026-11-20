package metrics_test

import (
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"

	"github.com/the-it-dept/ffs/internal/output/metrics"
)

var (
	metricName   = regexp.MustCompile(`ffs_[a-z_]+`)
	histSuffixes = regexp.MustCompile(`_(bucket|sum|count)$`)
)

// assertKnownMetrics fails for any ffs_ identifier in expr that is not an exported metric family.
func assertKnownMetrics(t *testing.T, expr string) {
	t.Helper()
	ids := metricName.FindAllString(expr, -1)
	assert.NotEmpty(t, ids, expr)
	for _, id := range ids {
		assert.Contains(t, metrics.Names(), histSuffixes.ReplaceAllString(id, ""), "expr %q", expr)
	}
}

// ruleGroup is a Prometheus rule group as the chart's rule files hold it.
type ruleGroup struct {
	Name  string `json:"name"`
	Rules []struct {
		Alert       string            `json:"alert"`
		Expr        string            `json:"expr"`
		For         string            `json:"for"`
		Labels      map[string]string `json:"labels"`
		Annotations map[string]string `json:"annotations"`
	} `json:"rules"`
}

func TestPrometheusRules_File(t *testing.T) {
	raw, err := os.ReadFile("../../../charts/ffs/files/prometheusrules.yaml")
	require.NoError(t, err)
	var f struct {
		Groups []ruleGroup `json:"groups"`
	}
	require.NoError(t, yaml.UnmarshalStrict(raw, &f))
	var alerts []string
	for _, g := range f.Groups {
		assert.NotEmpty(t, g.Name)
		for _, r := range g.Rules {
			alerts = append(alerts, r.Alert)
			assert.NotEmpty(t, r.For, r.Alert)
			assert.NotEmpty(t, r.Labels["severity"], r.Alert)
			assert.NotEmpty(t, r.Annotations["summary"], r.Alert)
			assert.NotEmpty(t, r.Annotations["description"], r.Alert)
			assertKnownMetrics(t, r.Expr)
		}
	}
	assert.Equal(t, []string{"FFSUrgentFindings", "FFSFeedStale", "FFSDeliveryFailing"}, alerts)
}

func TestPrometheusRules_AgentFile(t *testing.T) {
	raw, err := os.ReadFile("../../../charts/ffs/files/prometheusrules-agent.yaml")
	require.NoError(t, err)
	var groups []ruleGroup // a list, appended under the chart's spec.groups
	require.NoError(t, yaml.UnmarshalStrict(raw, &groups))
	var alerts []string
	for _, g := range groups {
		assert.Equal(t, "ffs-node-agent", g.Name)
		for _, r := range g.Rules {
			alerts = append(alerts, r.Alert)
			assert.Contains(t, r.Expr, `state="stale"`)
			assert.NotContains(t, r.Expr, "never", "nodes the DaemonSet never schedules must not fire it")
			assert.Equal(t, "30m", r.For)
			assert.Equal(t, "warning", r.Labels["severity"])
			assert.NotEmpty(t, r.Annotations["summary"])
			assert.NotEmpty(t, r.Annotations["description"])
			assertKnownMetrics(t, r.Expr)
		}
	}
	assert.Equal(t, []string{"FFSNodeAgentNotReporting"}, alerts)
}

func TestGrafanaDashboard_File(t *testing.T) {
	raw, err := os.ReadFile("../../../charts/ffs/files/grafana-dashboard.json")
	require.NoError(t, err)
	var d struct {
		UID    string `json:"uid"`
		Title  string `json:"title"`
		Panels []struct {
			Title   string `json:"title"`
			Targets []struct {
				Expr string `json:"expr"`
			} `json:"targets"`
		} `json:"panels"`
	}
	require.NoError(t, json.Unmarshal(raw, &d))
	assert.Equal(t, "ffs-overview", d.UID)
	assert.Equal(t, "ffs", d.Title)
	require.Len(t, d.Panels, 11)
	var titles []string
	for _, p := range d.Panels {
		titles = append(titles, p.Title)
		require.NotEmpty(t, p.Targets, p.Title)
		for _, tg := range p.Targets {
			assertKnownMetrics(t, tg.Expr)
		}
	}
	assert.True(t, slices.Contains(titles, "Findings dropped by CR cap"))
}
