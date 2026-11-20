package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/labels"
)

func TestNodeAgent_DefaultsAndLoad(t *testing.T) {
	require.Equal(t, NodeAgentConfig{Enabled: true, Listen: ":8444", CertDir: "/etc/ffs/agent-tls", Namespace: "ffs-agent",
		ServiceAccount: "ffs-agent", MaxReportBytes: 32 << 20, ReportInterval: 6 * time.Hour, ImageListInterval: 5 * time.Minute,
		StaleAfter: 30 * time.Minute, RuntimeGrace: 2 * time.Hour, WorkPerReport: 3, WorkTimeout: 20 * time.Minute}, Default().NodeAgent)
	c, err := Load(writeFile(t, "nodeAgent:\n  staleAfter: 1h\n  exposedNodes: node-role.example.com/edge\n"))
	require.NoError(t, err)
	require.Equal(t, time.Hour, c.NodeAgent.StaleAfter)
	require.Equal(t, "node-role.example.com/edge", c.NodeAgent.ExposedNodes)
	require.Equal(t, 5*time.Minute, c.NodeAgent.ImageListInterval) // siblings keep defaults
}

func TestNodeAgent_Validate(t *testing.T) {
	for name, tc := range map[string]struct {
		mut  func(*NodeAgentConfig)
		want string
	}{
		"listen without port":     {func(n *NodeAgentConfig) { n.Listen = "8444" }, "nodeAgent.listen"},
		"report cap below 1 MiB":  {func(n *NodeAgentConfig) { n.MaxReportBytes = 1<<20 - 1 }, "nodeAgent.maxReportBytes"},
		"report cap over 256 MiB": {func(n *NodeAgentConfig) { n.MaxReportBytes = 256<<20 + 1 }, "nodeAgent.maxReportBytes"},
		"zero report interval":    {func(n *NodeAgentConfig) { n.ReportInterval = 0 }, "nodeAgent.reportInterval"},
		"zero image interval":     {func(n *NodeAgentConfig) { n.ImageListInterval = 0 }, "nodeAgent.imageListInterval"},
		"zero stale":              {func(n *NodeAgentConfig) { n.StaleAfter = 0 }, "nodeAgent.staleAfter"},
		"zero runtime grace":      {func(n *NodeAgentConfig) { n.RuntimeGrace = 0 }, "nodeAgent.runtimeGrace"},
		"zero work timeout":       {func(n *NodeAgentConfig) { n.WorkTimeout = 0 }, "nodeAgent.workTimeout"},
		"image check not shorter": {func(n *NodeAgentConfig) { n.ImageListInterval = 6 * time.Hour }, "nodeAgent.imageListInterval"},
		"stale under two checks":  {func(n *NodeAgentConfig) { n.StaleAfter = 9 * time.Minute }, "nodeAgent.staleAfter"},
		"work outlasts stale": {func(n *NodeAgentConfig) { n.WorkTimeout = 25 * time.Minute },
			"nodeAgent.workTimeout: workTimeout (25m0s) plus imageListInterval (5m0s) must be shorter than staleAfter (30m0s)"},
		"too much work":         {func(n *NodeAgentConfig) { n.WorkPerReport = 11 }, "nodeAgent.workPerReport"},
		"negative work":         {func(n *NodeAgentConfig) { n.WorkPerReport = -1 }, "nodeAgent.workPerReport"},
		"bad selector":          {func(n *NodeAgentConfig) { n.ExposedNodes = "zone in (dmz" }, "nodeAgent.exposedNodes: "},
		"empty namespace":       {func(n *NodeAgentConfig) { n.Namespace = "" }, "nodeAgent.namespace"},
		"empty service account": {func(n *NodeAgentConfig) { n.ServiceAccount = "" }, "nodeAgent.serviceAccount"},
		"empty cert dir":        {func(n *NodeAgentConfig) { n.CertDir = "" }, "nodeAgent.certDir"},
	} {
		c := Default()
		tc.mut(&c.NodeAgent)
		require.ErrorContains(t, c.Validate(), tc.want, name)
	}
	c := Default()
	c.NodeAgent.MaxReportBytes, c.NodeAgent.WorkPerReport = 1<<20, 0
	c.NodeAgent.StaleAfter = 10 * time.Minute                // exactly twice imageListInterval
	c.NodeAgent.WorkTimeout = 4*time.Minute + 59*time.Second // with imageListInterval, just under staleAfter
	c.NodeAgent.ExposedNodes = "node-role.example.com/edge,zone in (dmz)"
	require.NoError(t, c.Validate())
}

func TestNodeAgent_ExposedSelector(t *testing.T) {
	edge := labels.Set{"node-role.example.com/edge": ""}
	for _, blank := range []string{"", "  "} {
		sel, err := NodeAgentConfig{ExposedNodes: blank}.ExposedSelector()
		require.NoError(t, err)
		require.False(t, sel.Matches(edge), "a blank selector exposes no node")
	}
	sel, err := NodeAgentConfig{ExposedNodes: "node-role.example.com/edge"}.ExposedSelector()
	require.NoError(t, err)
	require.True(t, sel.Matches(edge))
	require.False(t, sel.Matches(labels.Set{"kubernetes.io/os": "linux"}))
	_, err = NodeAgentConfig{ExposedNodes: "zone in (dmz"}.ExposedSelector()
	require.Error(t, err)
}
