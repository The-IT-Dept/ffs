package model

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNodeGroup_JSONKeys(t *testing.T) {
	b, err := json.Marshal(NodeGroup{ID: "abc", Kind: NodeGroupAgent, Members: []string{"worker-1"}})
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	for _, k := range []string{"id", "kind", "name", "label", "digest", "osImage", "kernelRelease", "containerRuntimeVersion",
		"kubeletVersion", "arch", "packageDB", "packageCount", "members"} {
		require.Contains(t, m, k)
	}
	for _, k := range []string{"distro", "kernel", "binaries", "exposedNodes"} {
		require.NotContains(t, m, k) // omitempty
	}
}
