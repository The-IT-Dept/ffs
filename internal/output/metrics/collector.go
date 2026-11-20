package metrics

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

// defaultInterval is how often Start refreshes the snapshot.
const defaultInterval = 60 * time.Second

var (
	findingsOpenDesc = prometheus.NewDesc("ffs_findings_open",
		"Open vulnerability findings by owner and priority.",
		[]string{"namespace", "owner_kind", "owner_name", "priority", "fixable", "kev"}, nil)
	feedSuccessDesc = prometheus.NewDesc("ffs_feed_last_success_timestamp_seconds",
		"Unix time of the last successful sync of a feed, or 0 if it has never succeeded.", []string{"feed"}, nil)
	feedLagDesc = prometheus.NewDesc("ffs_feed_lag_seconds",
		"Seconds since a feed last synced successfully, or since ffs started if it never has.", []string{"feed"}, nil)
	feedStaleDesc = prometheus.NewDesc("ffs_feed_stale_after_seconds",
		"Seconds after which a feed counts as stale.", []string{"feed"}, nil)
	nodeAgentNodesDesc = prometheus.NewDesc("ffs_node_agent_nodes",
		"Nodes by node agent state.", []string{"state"}, nil)
	nodeGroupsDesc = prometheus.NewDesc("ffs_node_groups",
		"Node groups by kind.", []string{"kind"}, nil)
)

// agentStates and groupKinds are every value of the node-agent gauges' labels, each exported even at 0.
var (
	agentStates = []model.AgentState{model.AgentReporting, model.AgentReportingWithoutInventory, model.AgentStale, model.AgentNever,
		model.AgentDisabled, model.AgentUnsupported}
	groupKinds = []model.NodeGroupKind{model.NodeGroupAgent, model.NodeGroupNodeInfo}
)

// CollectorOptions configures a Collector.
type CollectorOptions struct {
	FeedStaleAfter map[string]time.Duration // feed name to staleness threshold
	// NodeAgentStaleAfter is when a node agent's last report counts as stale; 0 exports no node-agent gauges.
	NodeAgentStaleAfter time.Duration
	Interval            time.Duration    // refresh period; default 60s
	Now                 func() time.Time // default time.Now
}

// Collector exports findings and feed freshness from the store. It reads the store on Refresh only
// and serves the last snapshot from Collect.
type Collector struct {
	st      *store.Store
	o       CollectorOptions
	started time.Time

	mu   sync.Mutex
	snap []prometheus.Metric
}

// NewCollector returns a Collector over st. Call Refresh or Start to fill it.
func NewCollector(st *store.Store, o CollectorOptions) *Collector {
	if o.Interval <= 0 {
		o.Interval = defaultInterval
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Collector{st: st, o: o, started: o.Now()}
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- findingsOpenDesc
	ch <- feedSuccessDesc
	ch <- feedLagDesc
	ch <- feedStaleDesc
	ch <- nodeAgentNodesDesc
	ch <- nodeGroupsDesc
}

// Collect implements prometheus.Collector. It emits the last snapshot and never touches the store.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	snap := c.snap
	c.mu.Unlock()
	for _, m := range snap {
		ch <- m
	}
}

type findingKey struct{ namespace, kind, name, priority, fixable, kev string }

// Refresh rebuilds the snapshot from the store.
func (c *Collector) Refresh(ctx context.Context) error {
	fs, err := c.st.ListFindings(ctx, store.FindingFilter{States: []model.FindingState{model.StateOpen}})
	if err != nil {
		return fmt.Errorf("metrics: list findings: %w", err)
	}
	ids := make([]string, 0, len(fs))
	seen := map[string]bool{}
	for _, f := range fs {
		if !seen[f.AdvisoryID] {
			seen[f.AdvisoryID] = true
			ids = append(ids, f.AdvisoryID)
		}
	}
	advs, err := c.st.Advisories(ctx, ids)
	if err != nil {
		return fmt.Errorf("metrics: advisories: %w", err)
	}
	counts := map[findingKey]int{}
	for _, f := range fs {
		a, ok := advs[f.AdvisoryID]
		counts[findingKey{f.Owner.Namespace, f.Owner.Kind, f.Owner.Name, f.Priority.String(),
			strconv.FormatBool(f.FixAvailable), strconv.FormatBool(ok && a.KEVAdded != nil)}]++
	}

	snap := make([]prometheus.Metric, 0, len(counts)+3*len(c.o.FeedStaleAfter))
	for k, n := range counts {
		snap = append(snap, prometheus.MustNewConstMetric(findingsOpenDesc, prometheus.GaugeValue, float64(n),
			k.namespace, k.kind, k.name, k.priority, k.fixable, k.kev))
	}
	now := c.o.Now()
	for _, feed := range slices.Sorted(maps.Keys(c.o.FeedStaleAfter)) {
		fstate, err := c.st.FeedState(ctx, feed)
		if err != nil {
			return fmt.Errorf("metrics: feed state %s: %w", feed, err)
		}
		var last float64
		lag := now.Sub(c.started)
		if !fstate.LastSuccess.IsZero() {
			last, lag = float64(fstate.LastSuccess.Unix()), now.Sub(fstate.LastSuccess)
		}
		snap = append(snap,
			prometheus.MustNewConstMetric(feedSuccessDesc, prometheus.GaugeValue, last, feed),
			prometheus.MustNewConstMetric(feedLagDesc, prometheus.GaugeValue, lag.Seconds(), feed),
			prometheus.MustNewConstMetric(feedStaleDesc, prometheus.GaugeValue, c.o.FeedStaleAfter[feed].Seconds(), feed))
	}
	if c.o.NodeAgentStaleAfter > 0 {
		nodes, err := c.nodeAgentMetrics(ctx, now)
		if err != nil {
			return err
		}
		snap = append(snap, nodes...)
	}
	c.mu.Lock()
	c.snap = snap
	c.mu.Unlock()
	return nil
}

// nodeAgentMetrics counts the nodes by node agent state and the node groups with members by kind. A node is
// counted in its CountState: a reporting node without a current host inventory, and a node the agent does not
// schedule on, each have their own state rather than reporting, never or stale.
func (c *Collector) nodeAgentMetrics(ctx context.Context, now time.Time) ([]prometheus.Metric, error) {
	statuses, err := c.st.AgentStatus(ctx, now, c.o.NodeAgentStaleAfter)
	if err != nil {
		return nil, fmt.Errorf("metrics: node agent status: %w", err)
	}
	groups, err := c.st.NodeGroups(ctx)
	if err != nil {
		return nil, fmt.Errorf("metrics: node groups: %w", err)
	}
	states := map[model.AgentState]int{}
	for _, s := range statuses {
		states[s.CountState()]++
	}
	kinds := map[model.NodeGroupKind]int{}
	for _, g := range groups {
		kinds[g.Kind]++
	}
	out := make([]prometheus.Metric, 0, len(agentStates)+len(groupKinds))
	for _, s := range agentStates {
		out = append(out, prometheus.MustNewConstMetric(nodeAgentNodesDesc, prometheus.GaugeValue, float64(states[s]), string(s)))
	}
	for _, k := range groupKinds {
		out = append(out, prometheus.MustNewConstMetric(nodeGroupsDesc, prometheus.GaugeValue, float64(kinds[k]), string(k)))
	}
	return out, nil
}

// Start refreshes now and then every Interval until ctx ends. A failed refresh keeps the previous
// snapshot and is tried again at the next tick.
func (c *Collector) Start(ctx context.Context) error {
	c.refreshLogged(ctx)
	t := time.NewTicker(c.o.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			c.refreshLogged(ctx)
		}
	}
}

// refreshLogged runs Refresh and logs a failure, so a failing store is visible while the old snapshot is served.
func (c *Collector) refreshLogged(ctx context.Context) {
	if err := c.Refresh(ctx); err != nil && ctx.Err() == nil {
		logr.FromContextOrDiscard(ctx).Error(err, "metrics refresh failed; serving previous snapshot")
	}
}

// NeedLeaderElection reports false: every replica serves its own metrics.
func (c *Collector) NeedLeaderElection() bool { return false }
