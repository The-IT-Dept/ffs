package notify

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"time"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

// maxNodeGroupNames is how many node groups an item names before "+N more".
const maxNodeGroupNames = 3

// isNodes reports whether o is the Nodes owner, which holds every host finding.
func isNodes(o model.OwnerRef) bool { return o.ClusterLevel() && o.Kind == model.OwnerKindNodes }

// nodesBaseline sends the target one summary of the open node findings, the node inventory
// baseline, instead of an alert for each, and records them in its ledger (spec §9.9). Node findings
// are held from the target's alerts and digests until then. It moves no cursor: the immediate pass
// that follows classifies the held transitions against the new ledger, so nothing summarised is
// sent again, and the message ID is stable, so a repeated pass queues nothing twice. A target
// limited to some namespaces never covers cluster-level subjects: it only records the baseline.
func (e *Engine) nodesBaseline(ctx context.Context, t *target, now time.Time) error {
	uid := t.cfg.UID
	maxID, err := e.st.MaxTransitionID(ctx)
	if err != nil {
		return err
	}
	if !t.cfg.allows("") {
		return e.st.CommitNotify(ctx, store.NotifyCommit{Target: uid, NodesBaselineAt: now})
	}
	all, err := e.st.ListFindings(ctx, store.FindingFilter{States: []model.FindingState{model.StateOpen}})
	if err != nil {
		return err
	}
	var open []model.Finding
	var ledger []store.LedgerEntry
	counts := map[model.Priority]int{}
	ids := map[string]bool{}
	for _, f := range all {
		if !isNodes(f.Owner) {
			continue
		}
		open = append(open, f)
		counts[f.Priority]++
		ids[f.AdvisoryID] = true
		ledger = append(ledger, store.LedgerEntry{Target: uid, Fingerprint: f.Fingerprint, MaxPriority: f.Priority,
			LastState: model.StateOpen, UpdatedAt: now})
	}
	labels, groups, err := e.groupLabels(ctx)
	if err != nil {
		return err
	}
	advs, err := e.st.Advisories(ctx, slices.Sorted(maps.Keys(ids)))
	if err != nil {
		return err
	}
	b := itemBuilder{advisories: advs, dashboardURL: e.o.DashboardURL, nodeGroups: labels}
	m := e.message(t, KindBaseline, "nodes-"+strconv.FormatInt(maxID, 10),
		nodesBaselineTitle(len(open), groups, counts[model.PriorityUrgent], counts[model.PriorityHigh]), now)
	m.Items = b.baselineItems(open)
	d, err := delivery(m, now)
	if err != nil {
		return err
	}
	return e.st.CommitNotify(ctx, store.NotifyCommit{Target: uid, Ledger: ledger, Deliveries: []store.Delivery{d},
		NodesBaselineAt: now})
}

// groupLabels returns the labels of the agent node groups with members, keyed by their group
// digest, and how many such groups there are. A group just left by its last node drops out of the
// names items carry.
func (e *Engine) groupLabels(ctx context.Context) (labels map[string]string, groups int, err error) {
	gs, err := e.st.NodeGroups(ctx)
	if err != nil {
		return nil, 0, err
	}
	labels = map[string]string{}
	for _, g := range gs {
		if g.Kind != model.NodeGroupAgent {
			continue
		}
		groups++
		if g.Digest != "" {
			labels[g.Digest] = g.Label
		}
	}
	return labels, groups, nil
}

// nodeGroupNames returns the sorted labels of the node groups the Nodes findings among fs affect
// (their group digests), at most maxNodeGroupNames followed by "+N more", and how many there are
// in all. It returns nil when no finding in fs is a Nodes finding; unknown digests are dropped.
func nodeGroupNames(fs []model.Finding, labels map[string]string) (names []string, count int) {
	seen := map[string]bool{}
	for _, f := range fs {
		if !isNodes(f.Owner) {
			continue
		}
		for _, d := range f.Digests {
			if l, ok := labels[d]; ok {
				seen[l] = true
			}
		}
	}
	all := slices.Sorted(maps.Keys(seen))
	if len(all) <= maxNodeGroupNames {
		return all, len(all)
	}
	return append(all[:maxNodeGroupNames:maxNodeGroupNames], fmt.Sprintf("+%d more", len(all)-maxNodeGroupNames)), len(all)
}

// nodesBaselineTitle titles the node inventory baseline.
func nodesBaselineTitle(n, groups, urgent, high int) string {
	return "Node inventory baseline: " + plural(n, "finding", "findings") + " on " +
		plural(groups, "node group", "node groups") + fmt.Sprintf(" (%d urgent, %d high)", urgent, high)
}
