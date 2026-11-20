package inventory

import "maps"

// PodCounts returns the live pods of every owner, by owner key, as of the last Flush. The map is a
// copy the caller may change. It is nil before the first Flush and for a nil Inventory, so a
// reader can tell "not known yet" from "no pods".
func (inv *Inventory) PodCounts() map[string]int {
	if inv == nil {
		return nil
	}
	p := inv.podCounts.Load()
	if p == nil {
		return nil
	}
	return maps.Clone(*p)
}

// snapshotPodCounts replaces the PodCounts snapshot from ownerPods. Flush calls it with flushMu held.
func (inv *Inventory) snapshotPodCounts() {
	m := make(map[string]int, len(inv.ownerPods))
	for key, pods := range inv.ownerPods {
		m[key] = len(pods)
	}
	inv.podCounts.Store(&m)
}
