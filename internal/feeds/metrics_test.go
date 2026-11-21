package feeds_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	ctrlmetrics "sigs.k8s.io/controller-runtime/pkg/metrics"
)

// TestSkipped_InitialSeries (W41): ffs_feed_skipped_total is registered with a zero series for every
// feed and reason it counts, so increase() over it reads 0 before the first skip instead of nothing.
func TestSkipped_InitialSeries(t *testing.T) {
	mfs, err := ctrlmetrics.Registry.Gather()
	require.NoError(t, err)
	got := map[string]float64{}
	for _, mf := range mfs {
		if mf.GetName() != "ffs_feed_skipped_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			got[labels["feed"]+"/"+labels["reason"]] = m.GetCounter().GetValue()
		}
	}
	require.Equal(t, map[string]float64{"cvelist/too_large": 0, "osv/too_large": 0, "osv/not_found": 0, "osv/missing_overflow": 0}, got)
}
