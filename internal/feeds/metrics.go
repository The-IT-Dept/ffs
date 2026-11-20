package feeds

import (
	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// SkipTooLarge is the Skipped reason for a download over its size limit.
const SkipTooLarge = "too_large"

// Skipped counts the downloads a feed gave up on and moved past, by feed and reason: data ffs will
// not have unless it is published again. The package registers it itself.
var Skipped = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "ffs_feed_skipped_total",
	Help: "Feed downloads skipped and moved past, by feed and reason.",
}, []string{"feed", "reason"})

func init() { ctrlmetrics.Registry.MustRegister(Skipped) }
