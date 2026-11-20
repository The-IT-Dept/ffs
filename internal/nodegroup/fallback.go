package nodegroup

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"time"

	"github.com/the-it-dept/ffs/internal/model"
)

// FallbackID identifies a node by its node.status.nodeInfo tuple, before any agent report: the
// sha256 hex of "nodeinfo", OSImage, KernelVersion, ContainerRuntimeVersion, KubeletVersion and
// Arch, joined by NUL bytes.
func FallbackID(n model.Node) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{"nodeinfo", n.OSImage, n.KernelVersion,
		n.ContainerRuntimeVersion, n.KubeletVersion, n.Arch}, "\x00")))
	return hex.EncodeToString(sum[:])
}

// FallbackGroups groups nodes by FallbackID: one NodeGroupNodeInfo group per distinct ID, with
// sorted Members and no Distro, ordered by Label and then ID. FirstSeen and LastSeen are now.
func FallbackGroups(nodes []model.Node, now time.Time) []model.NodeGroup {
	byID := map[string]*model.NodeGroup{}
	for _, n := range nodes {
		id := FallbackID(n)
		g, ok := byID[id]
		if !ok {
			name := GroupName(nil, n.OSImage, n.KernelVersion)
			g = &model.NodeGroup{ID: id, Kind: model.NodeGroupNodeInfo, Name: name, Label: GroupLabel(name, id),
				OSImage: n.OSImage, KernelRelease: n.KernelVersion, ContainerRuntimeVersion: n.ContainerRuntimeVersion,
				KubeletVersion: n.KubeletVersion, Arch: n.Arch, FirstSeen: now, LastSeen: now}
			byID[id] = g
		}
		g.Members = append(g.Members, n.Name)
	}
	groups := make([]model.NodeGroup, 0, len(byID))
	for _, g := range byID {
		slices.Sort(g.Members)
		g.Members = slices.Compact(g.Members)
		groups = append(groups, *g)
	}
	slices.SortFunc(groups, func(a, b model.NodeGroup) int {
		return cmp.Or(strings.Compare(a.Label, b.Label), strings.Compare(a.ID, b.ID))
	})
	return groups
}
