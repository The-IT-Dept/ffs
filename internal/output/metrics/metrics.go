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

	// NotifyDeliveries counts delivery attempts by AlertTarget name and result: "success", "retry",
	// "failed", or "dropped" (the oldest pending delivery of a target over its outbox cap).
	NotifyDeliveries = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ffs_notify_deliveries_total",
		Help: "Total notification deliveries by alert target and result: success, retry, failed, or dropped over the outbox cap.",
	}, []string{"target", "result"})

	// AgentReports counts node agent reports by result, "applied", "duplicate", "deferred" or "rejected",
	// and by reason for rejected ones. Rejected SBOM results are counted too.
	AgentReports = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ffs_agent_reports_total",
		Help: "Node agent reports received, by result; rejected reports and SBOM results also by reason.",
	}, []string{"result", "reason"})

	// AgentIngestBytesInFlight is the bytes of node agent report and SBOM result bodies being read and
	// handled now, out of the agent API's ingest budgets.
	AgentIngestBytesInFlight = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ffs_agent_ingest_bytes_in_flight",
		Help: "Bytes of node agent report and SBOM result bodies being read and handled.",
	})
)

// AgentReports results. Deferred is a report answered 429 because the controller's ingest budget was spent.
const (
	AgentReportApplied   = "applied"
	AgentReportDuplicate = "duplicate"
	AgentReportDeferred  = "deferred"
	AgentReportRejected  = "rejected"
)

// AgentReports rejection reasons; every other result has the reason "".
const (
	AgentRejectUnauthenticated = "unauthenticated"
	AgentRejectRateLimited     = "rate_limited"
	AgentRejectForbidden       = "forbidden"
	AgentRejectBadRequest      = "bad_request"
	AgentRejectTooLarge        = "too_large"
)

// AgentRejectReasons lists every rejection reason.
var AgentRejectReasons = []string{AgentRejectUnauthenticated, AgentRejectRateLimited, AgentRejectForbidden, AgentRejectBadRequest,
	AgentRejectTooLarge}

// crsDropped and crNameCollisions are the names of the gauges the crds package defines and registers
// itself, and feedSkipped the counter the feeds package does.
const (
	crsDropped       = "ffs_finding_crs_dropped"
	crNameCollisions = "ffs_finding_cr_name_collisions"
	feedSkipped      = "ffs_feed_skipped_total"
)

// Register registers c and every metric variable of this package on reg. The crds and feeds packages
// register their own.
func Register(reg prometheus.Registerer, c *Collector) error {
	for _, col := range []prometheus.Collector{c, RematchDuration, CatalogQueueDepth, CatalogFailures, RegistryBudgetRemaining,
		NotifyDeliveries, AgentReports, AgentIngestBytesInFlight} {
		if err := reg.Register(col); err != nil {
			return fmt.Errorf("metrics: register: %w", err)
		}
	}
	// Every result is exported from the start, so a rate over it never starts from a missing series.
	for _, r := range []string{AgentReportApplied, AgentReportDuplicate, AgentReportDeferred} {
		AgentReports.WithLabelValues(r, "")
	}
	for _, reason := range AgentRejectReasons {
		AgentReports.WithLabelValues(AgentReportRejected, reason)
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
		feedSkipped,
		"ffs_rematch_duration_seconds",
		"ffs_catalog_queue_depth",
		"ffs_catalog_failures_total",
		"ffs_registry_budget_remaining",
		"ffs_notify_deliveries_total",
		"ffs_node_agent_nodes",
		"ffs_node_groups",
		"ffs_agent_reports_total",
		"ffs_agent_ingest_bytes_in_flight",
		crsDropped,
		crNameCollisions,
	}
}
