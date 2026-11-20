package apiserver

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/nodegroup"
)

// testGroup is a node group named name: an agent group unless nodeinfo, with a fingerprint-like ID
// that starts with idPrefix.
func testGroup(idPrefix, name, arch string, nodeinfo bool, members ...string) model.NodeGroup {
	id := idPrefix + strings.Repeat("0", 64-len(idPrefix))
	kind := model.NodeGroupAgent
	if nodeinfo {
		kind = model.NodeGroupNodeInfo
	}
	return model.NodeGroup{ID: id, Kind: kind, Name: name, Label: nodegroup.GroupLabel(name, id), Arch: arch,
		Members: members, LastSeen: time.Unix(0, 0)}
}

// keysOf is every group's key, in group order, after checking that the keys are distinct and that
// each resolves to its own group.
func keysOf(t *testing.T, gs *groupSet) []string {
	t.Helper()
	keys := make([]string, 0, len(gs.groups))
	for _, g := range gs.groups {
		k := gs.key(g)
		require.NotContains(t, keys, k, "keys are distinct")
		got, ok := gs.find(k)
		require.True(t, ok, k)
		require.Equal(t, g.ID, got.ID, "%s resolves to its own group", k)
		keys = append(keys, k)
	}
	return keys
}

// findID is the ID of the group ref resolves to, "" when none.
func findID(gs *groupSet, ref string) string {
	g, ok := gs.find(ref)
	if !ok {
		return ""
	}
	return g.ID
}

// V6: a group is linked by its stable name; groups sharing it are told apart by what survives
// package updates (architecture, kind, then a member node), never by a fingerprint.
func TestGroupSet_KeysSurvivePackageUpdates(t *testing.T) {
	const name = "debian-12-k6.1.0-28"

	t.Run("unique names", func(t *testing.T) {
		a, b := testGroup("a1", name, "amd64", false, "w-1"), testGroup("b1", "debian-12-k6.1.0-27", "amd64", true, "w-2")
		require.Equal(t, []string{name, "debian-12-k6.1.0-27"}, keysOf(t, newGroupSet([]model.NodeGroup{a, b})))
	})

	t.Run("multi-arch pools and an agentless node", func(t *testing.T) {
		amd := testGroup("a1", name, "amd64", false, "w-1", "w-2", "w-3")
		arm := testGroup("b1", name, "arm64", false, "a-1")
		fresh := testGroup("c1", name, "amd64", true, "w-9")
		gs := newGroupSet([]model.NodeGroup{amd, arm, fresh})
		require.Equal(t, []string{name + "-amd64", name + "-arm64", name + "-amd64-nodeinfo"}, keysOf(t, gs))
		require.Equal(t, amd.ID, findID(gs, name), "the bare name opens the preferred group: an agent group, then the largest")

		// Package updates re-key both agent pools; the agentless node gets its agent and joins amd64.
		amd2 := testGroup("a2", name, "amd64", false, "w-1", "w-2", "w-3", "w-9")
		arm2 := testGroup("b2", name, "arm64", false, "a-1")
		gs = newGroupSet([]model.NodeGroup{amd2, arm2})
		require.Equal(t, amd2.ID, findID(gs, name+"-amd64"))
		require.Equal(t, arm2.ID, findID(gs, name+"-arm64"))
		require.Equal(t, amd2.ID, findID(gs, name+"-amd64-nodeinfo"), "the agentless node's link follows it into its agent group")
		require.Empty(t, findID(gs, amd.ID), "a fingerprint does not survive")

		// The arm64 pool leaves: the amd64 pool is its bare name again, and its qualified key still opens it.
		gs = newGroupSet([]model.NodeGroup{amd2})
		require.Equal(t, []string{name}, keysOf(t, gs))
		require.Equal(t, amd2.ID, findID(gs, name+"-amd64"))
		require.Empty(t, findID(gs, name+"-arm64"))
	})

	t.Run("agent and nodeinfo groups of one architecture", func(t *testing.T) {
		agent, fresh := testGroup("a1", name, "amd64", false, "w-1"), testGroup("c1", name, "amd64", true, "w-8", "w-9")
		gs := newGroupSet([]model.NodeGroup{agent, fresh})
		require.Equal(t, []string{name, name + "-nodeinfo"}, keysOf(t, gs))
		require.Equal(t, agent.ID, findID(gs, name+"-amd64"), "an agent group is preferred over a larger nodeinfo group")
	})

	t.Run("pools of one OS, kernel and architecture", func(t *testing.T) {
		cpu := testGroup("a1", name, "amd64", false, "cpu-1", "cpu-2", "cpu-3")
		gpu := testGroup("b1", name, "amd64", false, "gpu-1")
		gs := newGroupSet([]model.NodeGroup{cpu, gpu})
		require.Equal(t, []string{name + "@cpu-1", name + "@gpu-1"}, keysOf(t, gs))

		// Package updates re-key both pools: each link follows its node.
		cpu2 := testGroup("a2", name, "amd64", false, "cpu-1", "cpu-2", "cpu-3")
		gpu2 := testGroup("b2", name, "amd64", false, "gpu-1")
		gs = newGroupSet([]model.NodeGroup{gpu2, cpu2})
		require.Equal(t, gpu2.ID, findID(gs, name+"@gpu-1"))
		require.Equal(t, cpu2.ID, findID(gs, name+"@cpu-1"))
		require.Equal(t, cpu2.ID, findID(gs, name+"@cpu-gone"), "without its node, an anchored link opens the preferred group")
		require.Empty(t, findID(gs, "ubuntu-24.04-k6.8.0-88@gpu-1"), "the stable part must still match")
	})

	t.Run("rollout of package updates", func(t *testing.T) {
		old, next := testGroup("a1", name, "amd64", false, "w-1", "w-2"), testGroup("a2", name, "amd64", false, "w-3")
		gs := newGroupSet([]model.NodeGroup{old, next})
		require.Equal(t, []string{name + "@w-1", name + "@w-3"}, keysOf(t, gs))
		require.Equal(t, old.ID, findID(gs, name))

		done := testGroup("a2", name, "amd64", false, "w-1", "w-2", "w-3")
		gs = newGroupSet([]model.NodeGroup{done})
		require.Equal(t, []string{name}, keysOf(t, gs))
		for _, ref := range []string{name, name + "@w-1", name + "@w-3"} {
			require.Equal(t, done.ID, findID(gs, ref), ref)
		}
	})

	t.Run("a key another group answers to is its ID", func(t *testing.T) {
		amd, arm := testGroup("a1", "foo", "amd64", false, "w-1"), testGroup("b1", "foo", "arm64", false, "a-1")
		odd := testGroup("c1", "foo-amd64", "amd64", false, "x-1")
		named := testGroup("d1", odd.ID, "amd64", false, "y-1")
		labelled := testGroup("e1", amd.Label, "amd64", false, "z-1")
		gs := newGroupSet([]model.NodeGroup{amd, arm, odd, named, labelled})
		require.Equal(t, []string{amd.ID, "foo-arm64", odd.ID, named.ID, labelled.ID}, keysOf(t, gs))
	})
}
