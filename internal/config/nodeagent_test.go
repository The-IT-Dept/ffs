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
		StaleAfter: 30 * time.Minute, RuntimeGrace: 2 * time.Hour, WorkPerReport: 3, WorkTimeout: 20 * time.Minute,
		Architectures: []string{"amd64"}, NodeSelector: map[string]string{"kubernetes.io/os": "linux"},
		Tolerations: []Toleration{{Operator: "Exists"}}}, Default().NodeAgent)
	c, err := Load(writeFile(t, "nodeAgent:\n  staleAfter: 1h\n  exposedNodes: node-role.example.com/edge\n"))
	require.NoError(t, err)
	require.Equal(t, time.Hour, c.NodeAgent.StaleAfter)
	require.Equal(t, "node-role.example.com/edge", c.NodeAgent.ExposedNodes)
	require.Equal(t, 5*time.Minute, c.NodeAgent.ImageListInterval) // siblings keep defaults
}

// TestNodeAgent_SchedulingDefaultsMatchTheChart: the defaults are the chart's ([amd64], kubernetes.io/os:
// linux); a value in the file replaces them rather than merging, and an explicitly empty or null value
// means every node.
func TestNodeAgent_SchedulingDefaultsMatchTheChart(t *testing.T) {
	arm := map[string]string{"kubernetes.io/os": "linux", "kubernetes.io/arch": "arm64"}
	windows := map[string]string{"kubernetes.io/os": "windows", "kubernetes.io/arch": "amd64"}
	ok, _ := Default().NodeAgent.ScheduledOn(arm, "arm64")
	require.False(t, ok, "the default schedules on amd64 only")
	ok, _ = Default().NodeAgent.ScheduledOn(windows, "amd64")
	require.False(t, ok, "the default schedules on Linux only")

	for name, tc := range map[string]struct {
		yaml     string
		arch     []string
		selector map[string]string
	}{
		"absent keeps the defaults": {"nodeAgent:\n  staleAfter: 1h\n", []string{"amd64"}, map[string]string{"kubernetes.io/os": "linux"}},
		"explicitly empty":          {"nodeAgent:\n  architectures: []\n  nodeSelector: {}\n", []string{}, map[string]string{}},
		"null":                      {"nodeAgent:\n  architectures: null\n  nodeSelector:\n", nil, nil},
		"set replaces, not merges": {"nodeAgent:\n  architectures: [arm64]\n  nodeSelector:\n    pool: general\n",
			[]string{"arm64"}, map[string]string{"pool": "general"}},
	} {
		c, err := Load(writeFile(t, tc.yaml))
		require.NoError(t, err, name)
		require.Equal(t, tc.arch, c.NodeAgent.Architectures, name)
		require.Equal(t, tc.selector, c.NodeAgent.NodeSelector, name)
		if len(tc.arch) == 0 {
			ok, why := c.NodeAgent.ScheduledOn(windows, "arm64")
			require.True(t, ok, "%s: empty means every node", name)
			require.Empty(t, why, name)
		}
	}
	require.Equal(t, map[string]string{"kubernetes.io/os": "linux"}, Default().NodeAgent.NodeSelector,
		"loading never changes the defaults of a later Default()")
}

func TestNodeAgent_Validate(t *testing.T) {
	for name, tc := range map[string]struct {
		mut  func(*NodeAgentConfig)
		want string
	}{
		"listen without port":     {func(n *NodeAgentConfig) { n.Listen = "8444" }, "nodeAgent.listen"},
		"report cap below 1 MiB":  {func(n *NodeAgentConfig) { n.MaxReportBytes = 1<<20 - 1 }, "nodeAgent.maxReportBytes"},
		"report cap of 256 MiB":   {func(n *NodeAgentConfig) { n.MaxReportBytes = 256 << 20 }, "nodeAgent.maxReportBytes"},
		"zero report interval":    {func(n *NodeAgentConfig) { n.ReportInterval = 0 }, "nodeAgent.reportInterval"},
		"zero image interval":     {func(n *NodeAgentConfig) { n.ImageListInterval = 0 }, "nodeAgent.imageListInterval"},
		"zero stale":              {func(n *NodeAgentConfig) { n.StaleAfter = 0 }, "nodeAgent.staleAfter"},
		"zero runtime grace":      {func(n *NodeAgentConfig) { n.RuntimeGrace = 0 }, "nodeAgent.runtimeGrace"},
		"zero work timeout":       {func(n *NodeAgentConfig) { n.WorkTimeout = 0 }, "nodeAgent.workTimeout"},
		"image check not shorter": {func(n *NodeAgentConfig) { n.ImageListInterval = 6 * time.Hour }, "nodeAgent.imageListInterval"},
		"stale under two checks":  {func(n *NodeAgentConfig) { n.StaleAfter = 9 * time.Minute }, "nodeAgent.staleAfter"},
		"work outlasts stale": {func(n *NodeAgentConfig) { n.WorkTimeout = 25 * time.Minute },
			"nodeAgent.workTimeout: workTimeout (25m0s) plus imageListInterval (5m0s) must be shorter than staleAfter (30m0s)"},
		"report cap over the report budget": {func(n *NodeAgentConfig) { n.MaxReportBytes = NodeAgentReportBudget + 1 },
			"nodeAgent.maxReportBytes: must be in [1 MiB, 192 MiB], the most the controller reads of reports at once"},
		"too much work":         {func(n *NodeAgentConfig) { n.WorkPerReport = 11 }, "nodeAgent.workPerReport"},
		"negative work":         {func(n *NodeAgentConfig) { n.WorkPerReport = -1 }, "nodeAgent.workPerReport"},
		"bad selector":          {func(n *NodeAgentConfig) { n.ExposedNodes = "zone in (dmz" }, "nodeAgent.exposedNodes: "},
		"empty namespace":       {func(n *NodeAgentConfig) { n.Namespace = "" }, "nodeAgent.namespace"},
		"empty service account": {func(n *NodeAgentConfig) { n.ServiceAccount = "" }, "nodeAgent.serviceAccount"},
		"empty cert dir":        {func(n *NodeAgentConfig) { n.CertDir = "" }, "nodeAgent.certDir"},
		"empty architecture":    {func(n *NodeAgentConfig) { n.Architectures = []string{"amd64", " "} }, "nodeAgent.architectures"},
	} {
		c := Default()
		tc.mut(&c.NodeAgent)
		require.ErrorContains(t, c.Validate(), tc.want, name)
	}
	require.Equal(t, int64(192<<20), int64(NodeAgentReportBudget))
	c := Default()
	c.NodeAgent.MaxReportBytes = NodeAgentReportBudget // a report of the whole report budget
	require.NoError(t, c.Validate())
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

func TestNodeAgent_ScheduledOn(t *testing.T) {
	linuxAMD := map[string]string{"kubernetes.io/os": "linux", "kubernetes.io/arch": "amd64"}
	ok, why := NodeAgentConfig{}.ScheduledOn(map[string]string{"kubernetes.io/os": "windows"}, "arm64")
	require.True(t, ok, "nothing configured: every node")
	require.Empty(t, why)

	n := NodeAgentConfig{Architectures: []string{"amd64"}, NodeSelector: map[string]string{"kubernetes.io/os": "linux"}}
	ok, _ = n.ScheduledOn(linuxAMD, "")
	require.True(t, ok)
	ok, why = n.ScheduledOn(map[string]string{"kubernetes.io/os": "linux", "kubernetes.io/arch": "arm64"}, "amd64")
	require.False(t, ok, "the label wins over the reported architecture")
	require.Equal(t, "architecture arm64 is not in nodeAgent.architectures", why)
	ok, _ = n.ScheduledOn(map[string]string{"kubernetes.io/os": "linux"}, "amd64")
	require.True(t, ok, "without the label, the node's reported architecture")
	ok, why = n.ScheduledOn(map[string]string{"kubernetes.io/os": "windows", "kubernetes.io/arch": "amd64"}, "amd64")
	require.False(t, ok)
	require.Equal(t, "node labels do not match nodeAgent.nodeSelector", why)
}

// TestNodeAgent_Tolerations (#11): the default is the chart's, tolerate everything; a value in the file
// replaces it, an explicitly empty or null one means none, and every field of a toleration is read.
func TestNodeAgent_Tolerations(t *testing.T) {
	require.Equal(t, []Toleration{{Operator: "Exists"}}, Default().NodeAgent.Tolerations)
	secs := int64(300)
	for name, tc := range map[string]struct {
		yaml string
		want []Toleration
	}{
		"absent keeps the default": {"nodeAgent:\n  staleAfter: 1h\n", []Toleration{{Operator: "Exists"}}},
		"empty":                    {"nodeAgent:\n  tolerations: []\n", []Toleration{}},
		"null":                     {"nodeAgent:\n  tolerations:\n", nil},
		"set replaces": {"nodeAgent:\n  tolerations:\n    - key: dedicated\n      operator: Equal\n      value: gpu\n" +
			"      effect: NoExecute\n      tolerationSeconds: 300\n",
			[]Toleration{{Key: "dedicated", Operator: "Equal", Value: "gpu", Effect: "NoExecute", TolerationSeconds: &secs}}},
	} {
		c, err := Load(writeFile(t, tc.yaml))
		require.NoError(t, err, name)
		require.Equal(t, tc.want, c.NodeAgent.Tolerations, name)
	}
	require.Equal(t, []Toleration{{Operator: "Exists"}}, Default().NodeAgent.Tolerations, "loading never changes the default")
}
