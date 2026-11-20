package chart

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// ruleGroups returns the rendered PrometheusRule's group names and, by group, its alert names.
func ruleGroups(t *testing.T, o objs) ([]string, map[string][]string) {
	t.Helper()
	groups, ok, err := unstructured.NestedSlice(o.get(t, "PrometheusRule", "ffs").Object, "spec", "groups")
	require.NoError(t, err)
	require.True(t, ok)
	var names []string
	alerts := map[string][]string{}
	for _, g := range groups {
		gm := g.(map[string]any)
		name, _ := gm["name"].(string)
		names = append(names, name)
		rules, _ := gm["rules"].([]any)
		for _, r := range rules {
			alert, _ := r.(map[string]any)["alert"].(string)
			alerts[name] = append(alerts[name], alert)
		}
	}
	return names, alerts
}

func TestChart_AgentRuleFollowsNodeAgent(t *testing.T) {
	names, alerts := ruleGroups(t, render(t, "prometheusRule.enabled=true"))
	require.Equal(t, []string{"ffs", "ffs-node-agent"}, names)
	require.Equal(t, []string{"FFSNodeAgentNotReporting"}, alerts["ffs-node-agent"])

	names, _ = ruleGroups(t, render(t, "prometheusRule.enabled=true", "nodeAgent.enabled=false"))
	require.Equal(t, []string{"ffs"}, names)
	out, err := helmTemplate(t, "prometheusRule.enabled=true", "nodeAgent.enabled=false")
	require.NoError(t, err, out)
	require.NotContains(t, out, "FFSNodeAgentNotReporting")
}
