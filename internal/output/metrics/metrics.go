// Package metrics defines ffs's bounded Prometheus metrics. Labels are limited to namespace, owner,
// priority, feed, registry, target, state and kind: never advisory IDs, package names, digests, image
// names or node names.
//
// It imports only store, model and prometheus, because the engine, registry, sbom and notify
// packages import it. The controller wires it directly.
package metrics

import (
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
)

// Operational metrics, updated by the packages that own the work.
var (
	// RematchDuration times one re-match run per source: "grypedb", "osv" or "cna".
	RematchDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "ffs_rematch_duration_seconds",
		Help:    "Time taken to re-match findings after a feed update, by source.",
		Buckets: prometheus.ExponentialBuckets(0.05, 2, 16),
	}, []string{"source"})

	// CatalogQueueDepth is the number of images waiting to be catalogued.
	CatalogQueueDepth = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ffs_catalog_queue_depth",
		Help: "Number of images waiting to be catalogued.",
	})

	// CatalogFailures counts failed cataloguing attempts.
	CatalogFailures = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "ffs_catalog_failures_total",
		Help: "Total number of failed cataloguing attempts.",
	})

	// RegistryBudgetRemaining is the request budget left per registry host, such as "docker.io".
	RegistryBudgetRemaining = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ffs_registry_budget_remaining",
		Help: "Registry requests remaining in the current rate-limit window, by registry.",
	}, []string{"registry"})

	// NotifyDeliveries counts delivery attempts by AlertTarget name and result: "success", "retry"
	// or "failed".
	NotifyDeliveries = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ffs_notify_deliveries_total",
		Help: "Total notification delivery attempts, by alert target and result.",
	}, []string{"target", "result"})

	// AgentReports counts node agent reports by result: "applied", "duplicate" or "rejected".
	AgentReports = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ffs_agent_reports_total",
		Help: "Node agent reports received, by result.",
	}, []string{"result"})
)

// AgentReports results.
const (
	AgentReportApplied   = "applied"
	AgentReportDuplicate = "duplicate"
	AgentReportRejected  = "rejected"
)

// crsDropped is the name of the gauge the crds package defines and registers itself.
const crsDropped = "ffs_finding_crs_dropped"

// Register registers c and every metric variable of this package on reg. The crds package registers
// its own gauge.
func Register(reg prometheus.Registerer, c *Collector) error {
	for _, col := range []prometheus.Collector{c, RematchDuration, CatalogQueueDepth, CatalogFailures, RegistryBudgetRemaining,
		NotifyDeliveries, AgentReports} {
		if err := reg.Register(col); err != nil {
			return fmt.Errorf("metrics: register: %w", err)
		}
	}
	// Every result is exported from the start, so a rate over it never starts from a missing series.
	for _, r := range []string{AgentReportApplied, AgentReportDuplicate, AgentReportRejected} {
		AgentReports.WithLabelValues(r)
	}
	return nil
}

// Names returns every metric family name ffs exports.
func Names() []string {
	return []string{
		"ffs_findings_open",
		"ffs_feed_last_success_timestamp_seconds",
		"ffs_feed_lag_seconds",
		"ffs_feed_stale_after_seconds",
		"ffs_rematch_duration_seconds",
		"ffs_catalog_queue_depth",
		"ffs_catalog_failures_total",
		"ffs_registry_budget_remaining",
		"ffs_notify_deliveries_total",
		"ffs_node_agent_nodes",
		"ffs_node_groups",
		"ffs_agent_reports_total",
		crsDropped,
	}
}
