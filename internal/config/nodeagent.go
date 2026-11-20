package config

import (
	"net"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/labels"
)

// NodeAgentConfig configures the node agent and the controller's agent API. The chart sets these keys
// from the top-level nodeAgent Helm values.
type NodeAgentConfig struct {
	Enabled           bool          `yaml:"enabled"`
	Listen            string        `yaml:"listen"`
	CertDir           string        `yaml:"certDir"` // holds tls.crt and tls.key
	Namespace         string        `yaml:"namespace"`
	ServiceAccount    string        `yaml:"serviceAccount"`
	MaxReportBytes    int64         `yaml:"maxReportBytes"`
	ReportInterval    time.Duration `yaml:"reportInterval"`
	ImageListInterval time.Duration `yaml:"imageListInterval"`
	StaleAfter        time.Duration `yaml:"staleAfter"`
	RuntimeGrace      time.Duration `yaml:"runtimeGrace"`
	WorkPerReport     int           `yaml:"workPerReport"`
	WorkTimeout       time.Duration `yaml:"workTimeout"`
	ExposedNodes      string        `yaml:"exposedNodes"` // node label selector; "" exposes no node
}

func defaultNodeAgent() NodeAgentConfig {
	return NodeAgentConfig{
		Enabled: true, Listen: ":8444", CertDir: "/etc/ffs/agent-tls", Namespace: "ffs-agent", ServiceAccount: "ffs-agent",
		MaxReportBytes: 32 << 20, ReportInterval: 6 * time.Hour, ImageListInterval: 5 * time.Minute,
		StaleAfter: 30 * time.Minute, RuntimeGrace: 2 * time.Hour, WorkPerReport: 3, WorkTimeout: 30 * time.Minute,
	}
}

// ExposedSelector parses ExposedNodes. A blank or whitespace-only value returns labels.Nothing(),
// because labels.Parse("") selects every node.
func (n NodeAgentConfig) ExposedSelector() (labels.Selector, error) {
	if strings.TrimSpace(n.ExposedNodes) == "" {
		return labels.Nothing(), nil
	}
	return labels.Parse(n.ExposedNodes)
}

func (n NodeAgentConfig) validate(bad func(format string, a ...any)) {
	for _, s := range []struct{ key, val string }{
		{"namespace", n.Namespace}, {"serviceAccount", n.ServiceAccount}, {"certDir", n.CertDir},
	} {
		if s.val == "" {
			bad("nodeAgent.%s: must not be empty", s.key)
		}
	}
	if _, _, err := net.SplitHostPort(n.Listen); err != nil {
		bad("nodeAgent.listen: %v", err)
	}
	if n.MaxReportBytes < 1<<20 || n.MaxReportBytes > 256<<20 {
		bad("nodeAgent.maxReportBytes: must be in [1 MiB, 256 MiB]")
	}
	for _, d := range []struct {
		key string
		val time.Duration
	}{
		{"reportInterval", n.ReportInterval}, {"imageListInterval", n.ImageListInterval},
		{"staleAfter", n.StaleAfter}, {"runtimeGrace", n.RuntimeGrace}, {"workTimeout", n.WorkTimeout},
	} {
		if d.val <= 0 {
			bad("nodeAgent.%s: must be > 0", d.key)
		}
	}
	if n.ImageListInterval > 0 && n.ReportInterval > 0 && n.ImageListInterval >= n.ReportInterval {
		bad("nodeAgent.imageListInterval: must be shorter than reportInterval")
	}
	if n.ImageListInterval > 0 && n.StaleAfter > 0 && n.StaleAfter < 2*n.ImageListInterval {
		bad("nodeAgent.staleAfter: must be at least twice imageListInterval")
	}
	if n.WorkPerReport < 0 || n.WorkPerReport > 10 {
		bad("nodeAgent.workPerReport: must be in 0..10")
	}
	if _, err := n.ExposedSelector(); err != nil {
		bad("nodeAgent.exposedNodes: %v", err)
	}
}
