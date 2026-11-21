package metrics_test

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/feeds"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/nodegroup"
	"github.com/the-it-dept/ffs/internal/output/metrics"
	"github.com/the-it-dept/ffs/internal/store"
)

var (
	ctx = context.Background()
	t0  = time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
)

func newStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "ffs.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	return st
}

func finding(fp, adv, owner string, p model.Priority, state model.FindingState, fix bool) model.Finding {
	return model.Finding{Fingerprint: fp, AdvisoryID: adv, ImageRepo: "docker.io/library/nginx",
		Owner:   model.OwnerRef{Kind: "Deployment", Namespace: "shop", Name: owner, UID: "uid-" + owner},
		Digests: []string{"sha256:" + strings.Repeat("a", 64)}, Priority: p, State: state, FixAvailable: fix,
		Packages: []model.FindingPackage{{Name: "openssl"}}}
}

func apply(t *testing.T, st *store.Store, fs ...model.Finding) {
	t.Helper()
	require.NoError(t, st.ApplyFindings(ctx, fs, nil))
}

func seed(t *testing.T, st *store.Store) {
	t.Helper()
	kev := t0
	require.NoError(t, st.UpsertAdvisory(ctx, model.Advisory{ID: "CVE-2026-41873", Aliases: []string{"GHSA-xxxx-yyyy-zzzz"}, KEVAdded: &kev}))
	require.NoError(t, st.UpsertAdvisory(ctx, model.Advisory{ID: "CVE-2026-1"}))
	apply(t, st,
		finding("f1", "CVE-2026-41873", "web", model.PriorityUrgent, model.StateOpen, true),
		finding("f2", "CVE-2026-41873", "web", model.PriorityUrgent, model.StateOpen, true),
		finding("f3", "CVE-2026-1", "web", model.PriorityHigh, model.StateOpen, false),
		finding("f4", "CVE-2026-41873", "web", model.PriorityUrgent, model.StateExcepted, true),
		finding("f5", "CVE-2026-41873", "web", model.PriorityUrgent, model.StateResolved, true))
}

func gather(t *testing.T, reg *prometheus.Registry) []*dto.MetricFamily {
	t.Helper()
	mfs, err := reg.Gather()
	require.NoError(t, err)
	return mfs
}

func TestCollector_FindingsOpen(t *testing.T) {
	st := newStore(t)
	seed(t, st)
	c := metrics.NewCollector(st, metrics.CollectorOptions{Now: func() time.Time { return t0 }})
	require.NoError(t, c.Refresh(ctx))
	require.NoError(t, testutil.CollectAndCompare(c, strings.NewReader(`
# HELP ffs_findings_open Open vulnerability findings by owner and priority.
# TYPE ffs_findings_open gauge
ffs_findings_open{fixable="false",kev="false",namespace="shop",owner_kind="Deployment",owner_name="web",priority="high"} 1
ffs_findings_open{fixable="true",kev="true",namespace="shop",owner_kind="Deployment",owner_name="web",priority="urgent"} 2
`), "ffs_findings_open"))
}

func TestCollector_NoHighCardinalityLabels(t *testing.T) {
	st := newStore(t)
	seed(t, st)
	c := metrics.NewCollector(st, metrics.CollectorOptions{FeedStaleAfter: map[string]time.Duration{"osv": time.Hour},
		NodeAgentStaleAfter: time.Hour, Now: func() time.Time { return t0 }})
	reg := prometheus.NewRegistry()
	require.NoError(t, metrics.Register(reg, c))
	require.NoError(t, c.Refresh(ctx))
	metrics.NotifyDeliveries.WithLabelValues("ops", "success").Inc()
	metrics.RegistryBudgetRemaining.WithLabelValues("docker.io").Set(90)
	metrics.RematchDuration.WithLabelValues("osv").Observe(1)
	metrics.CatalogQueueDepth.Set(1)
	metrics.CatalogFailures.Inc()

	allowed := map[string]bool{}
	for _, l := range []string{"namespace", "owner_kind", "owner_name", "priority", "fixable", "kev", "feed", "registry", "target",
		"result", "reason", "source", "le", "state", "kind"} {
		allowed[l] = true
	}
	var n int
	for _, mf := range gather(t, reg) {
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				n++
				assert.True(t, allowed[lp.GetName()], "label %s on %s", lp.GetName(), mf.GetName())
				for _, bad := range []string{"CVE-", "GHSA-", "openssl", "sha256:", "nginx"} {
					assert.NotContains(t, lp.GetValue(), bad)
				}
			}
		}
	}
	assert.NotZero(t, n)
}

func TestCollector_FeedFreshness(t *testing.T) {
	st := newStore(t)
	now := t0
	c := metrics.NewCollector(st, metrics.CollectorOptions{
		FeedStaleAfter: map[string]time.Duration{"osv": 2 * time.Hour, "kev": 24 * time.Hour},
		Now:            func() time.Time { return now },
	})
	now = t0.Add(25 * time.Hour) // the collector started 25h ago
	osvLast := now.Add(-30 * time.Minute)
	require.NoError(t, st.PutFeedState(ctx, store.FeedState{Name: "osv", LastSuccess: osvLast}))
	require.NoError(t, c.Refresh(ctx))
	require.NoError(t, testutil.CollectAndCompare(c, strings.NewReader(fmt.Sprintf(`
# HELP ffs_feed_last_success_timestamp_seconds Unix time of the last successful sync of a feed, or 0 if it has never succeeded.
# TYPE ffs_feed_last_success_timestamp_seconds gauge
ffs_feed_last_success_timestamp_seconds{feed="kev"} 0
ffs_feed_last_success_timestamp_seconds{feed="osv"} %d
# HELP ffs_feed_lag_seconds Seconds since a feed last synced successfully, or if it never has, since its first attempt or since ffs started, whichever is earlier.
# TYPE ffs_feed_lag_seconds gauge
ffs_feed_lag_seconds{feed="kev"} 90000
ffs_feed_lag_seconds{feed="osv"} 1800
# HELP ffs_feed_stale_after_seconds Seconds after which a feed counts as stale.
# TYPE ffs_feed_stale_after_seconds gauge
ffs_feed_stale_after_seconds{feed="kev"} 86400
ffs_feed_stale_after_seconds{feed="osv"} 7200
`, osvLast.Unix()))))
}

// TestCollector_NeverSyncedLagsFromFirstAttempt (F67, W53): a feed that never succeeded lags from
// its stored first attempt when that is before the collector started, so a restart does not reset
// it; a state v0.0.1 wrote, with no first attempt, lags from its last attempt; a first attempt
// after the start counts from the start. This is store.FeedState.StaleFrom, the feed runner's rule.
func TestCollector_NeverSyncedLagsFromFirstAttempt(t *testing.T) {
	st := newStore(t)
	now := t0
	c := metrics.NewCollector(st, metrics.CollectorOptions{
		FeedStaleAfter: map[string]time.Duration{"grypedb": 48 * time.Hour, "kev": 24 * time.Hour, "epss": 72 * time.Hour},
		Now:            func() time.Time { return now },
	})
	now = t0.Add(time.Hour) // the collector started an hour ago
	require.NoError(t, st.PutFeedState(ctx, store.FeedState{Name: "grypedb", FirstAttempt: t0.Add(-71 * time.Hour),
		LastAttempt: t0, LastError: "connection refused"}))
	require.NoError(t, st.PutFeedState(ctx, store.FeedState{Name: "kev", FirstAttempt: t0.Add(30 * time.Minute)}))
	require.NoError(t, st.PutFeedState(ctx, store.FeedState{Name: "epss", LastAttempt: t0.Add(-5 * time.Hour),
		LastError: "connection refused"})) // as v0.0.1 left it: no first attempt
	require.NoError(t, c.Refresh(ctx))
	require.NoError(t, testutil.CollectAndCompare(c, strings.NewReader(`
# HELP ffs_feed_lag_seconds Seconds since a feed last synced successfully, or if it never has, since its first attempt or since ffs started, whichever is earlier.
# TYPE ffs_feed_lag_seconds gauge
ffs_feed_lag_seconds{feed="epss"} 21600
ffs_feed_lag_seconds{feed="grypedb"} 259200
ffs_feed_lag_seconds{feed="kev"} 3600
`), "ffs_feed_lag_seconds"))
}

// TestMetrics_NamesListsFeedSkipped (F66): the counter the feeds package registers itself is an
// exported family, so the shipped alerts and dashboards may use it.
func TestMetrics_NamesListsFeedSkipped(t *testing.T) {
	feeds.Skipped.WithLabelValues("test", feeds.SkipTooLarge)
	t.Cleanup(func() { feeds.Skipped.DeleteLabelValues("test", feeds.SkipTooLarge) })
	reg := prometheus.NewRegistry()
	require.NoError(t, reg.Register(feeds.Skipped))
	mfs, err := reg.Gather()
	require.NoError(t, err)
	require.Len(t, mfs, 1)
	assert.Equal(t, "ffs_feed_skipped_total", mfs[0].GetName())
	assert.Contains(t, metrics.Names(), mfs[0].GetName())
}

func TestCollector_ServesSnapshotBetweenRefreshes(t *testing.T) {
	st := newStore(t)
	seed(t, st)
	c := metrics.NewCollector(st, metrics.CollectorOptions{})
	require.NoError(t, c.Refresh(ctx))
	before := testutil.CollectAndCount(c, "ffs_findings_open")
	assert.Equal(t, 2, before)

	apply(t, st, finding("f6", "CVE-2026-1", "api", model.PriorityLow, model.StateOpen, false))
	assert.Equal(t, before, testutil.CollectAndCount(c, "ffs_findings_open"))
	require.NoError(t, c.Refresh(ctx))
	assert.Equal(t, before+1, testutil.CollectAndCount(c, "ffs_findings_open"))
}

func TestCollector_NodeAgentGauges(t *testing.T) {
	st := newStore(t)
	node := func(name string) model.Node {
		return model.Node{Name: name, OS: "linux", Arch: "amd64", OSImage: "Ubuntu 26.04 LTS", KernelVersion: "7.0.0-34-generic",
			KubeletVersion: "v1.37.1", ContainerRuntimeVersion: "containerd://2.2.1", Ready: true, UpdatedAt: t0}
	}
	cp1 := node("cp-1")
	require.NoError(t, st.ReplaceNodes(ctx, []model.Node{node("worker-1"), node("worker-2"), node("worker-3"), node("win-1"), cp1}))
	require.NoError(t, st.PutNodesState(ctx, store.NodesState{AgentEnabled: true,
		Unsupported: map[string]string{"win-1": "node labels do not match nodeAgent.nodeSelector"}}))
	// worker-3 reports but is in no agent group: reporting without inventory.
	for name, at := range map[string]time.Time{"worker-1": t0.Add(-time.Minute), "worker-2": t0.Add(-2 * time.Hour),
		"worker-3": t0.Add(-time.Minute)} {
		_, err := st.AcceptAgentReport(ctx, store.AgentReport{Node: name, BootID: "boot", StartedAt: t0.Add(-3 * time.Hour), Seq: 1,
			At: at, Full: true})
		require.NoError(t, err)
	}
	grpA := strings.Repeat("a", 64)
	require.NoError(t, st.PutNodeGroup(ctx, model.NodeGroup{ID: grpA, Kind: model.NodeGroupAgent, Name: "ubuntu-26.04-k7.0.0-34",
		Label: nodegroup.GroupLabel("ubuntu-26.04-k7.0.0-34", grpA), Digest: nodegroup.GroupDigest(grpA), Arch: "amd64"}, t0))
	fb := nodegroup.FallbackGroups([]model.Node{cp1}, t0)
	require.NoError(t, st.ApplyNodeGrouping(ctx, store.NodeGrouping{
		Members:  map[string]string{"worker-1": grpA, "worker-2": grpA, "cp-1": fb[0].ID, "worker-3": fb[0].ID, "win-1": fb[0].ID},
		Fallback: fb, Now: t0}))

	c := metrics.NewCollector(st, metrics.CollectorOptions{NodeAgentStaleAfter: 30 * time.Minute, Now: func() time.Time { return t0 }})
	require.NoError(t, c.Refresh(ctx))
	require.NoError(t, testutil.CollectAndCompare(c, strings.NewReader(`
# HELP ffs_node_agent_nodes Nodes by node agent state.
# TYPE ffs_node_agent_nodes gauge
ffs_node_agent_nodes{state="disabled"} 0
ffs_node_agent_nodes{state="never"} 1
ffs_node_agent_nodes{state="reporting"} 1
ffs_node_agent_nodes{state="reporting_without_inventory"} 1
ffs_node_agent_nodes{state="stale"} 1
ffs_node_agent_nodes{state="unsupported"} 1
# HELP ffs_node_groups Node groups by kind.
# TYPE ffs_node_groups gauge
ffs_node_groups{kind="agent"} 1
ffs_node_groups{kind="nodeinfo"} 1
`), "ffs_node_agent_nodes", "ffs_node_groups"))

	c = metrics.NewCollector(st, metrics.CollectorOptions{Now: func() time.Time { return t0 }})
	require.NoError(t, c.Refresh(ctx))
	assert.Zero(t, testutil.CollectAndCount(c, "ffs_node_agent_nodes"), "no node-agent gauges without NodeAgentStaleAfter")
	assert.Zero(t, testutil.CollectAndCount(c, "ffs_node_groups"))
}

func TestMetrics_NamesAndAgentReportsRegistered(t *testing.T) {
	assert.Subset(t, metrics.Names(), []string{"ffs_node_agent_nodes", "ffs_node_groups", "ffs_agent_reports_total"})
	reg := prometheus.NewRegistry()
	require.NoError(t, metrics.Register(reg, metrics.NewCollector(newStore(t), metrics.CollectorOptions{})))
	require.NoError(t, testutil.GatherAndCompare(reg, strings.NewReader(`
# HELP ffs_agent_reports_total Node agent reports received, by result; rejected reports and SBOM results also by reason.
# TYPE ffs_agent_reports_total counter
ffs_agent_reports_total{reason="",result="applied"} 0
ffs_agent_reports_total{reason="",result="deferred"} 0
ffs_agent_reports_total{reason="",result="duplicate"} 0
ffs_agent_reports_total{reason="bad_request",result="rejected"} 0
ffs_agent_reports_total{reason="forbidden",result="rejected"} 0
ffs_agent_reports_total{reason="rate_limited",result="rejected"} 0
ffs_agent_reports_total{reason="too_large",result="rejected"} 0
ffs_agent_reports_total{reason="unauthenticated",result="rejected"} 0
`), "ffs_agent_reports_total"))
}
