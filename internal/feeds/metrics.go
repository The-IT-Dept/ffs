package feeds

import (
	"github.com/prometheus/client_golang/prometheus"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// Skipped reasons.
const (
	// SkipTooLarge is a download over its size limit.
	SkipTooLarge = "too_large"
	// SkipNotFound is a record the feed's listing names that the source still answered 404 for
	// after a day of asking.
	SkipNotFound = "not_found"
	// SkipMissingOverflow is a record the listing names and the source answered 404 for, beyond
	// the number the feed asks for again.
	SkipMissingOverflow = "missing_overflow"
)

// Skipped counts the downloads a feed gave up on and moved past, by feed and reason: data ffs will
// not have unless it is published again. The package registers it itself, with a zero series for
// each feed and reason in skippedSeries, so increase() sees 0 before the first skip.
var Skipped = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "ffs_feed_skipped_total",
	Help: "Feed downloads skipped and moved past, by feed and reason.",
}, []string{"feed", "reason"})

// skippedSeries are the feed and reason pairs Skipped counts.
var skippedSeries = [][2]string{
	{NameCVEList, SkipTooLarge},
	{NameOSV, SkipNotFound},
	{NameOSV, SkipMissingOverflow},
}

func init() {
	ctrlmetrics.Registry.MustRegister(Skipped)
	for _, s := range skippedSeries {
		Skipped.WithLabelValues(s[0], s[1])
	}
}
