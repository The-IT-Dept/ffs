package engine_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/engine"
	"github.com/the-it-dept/ffs/internal/match/upstream"
	"github.com/the-it-dept/ffs/internal/model"
)

// The first cvelistV5 backfill hands every CVE record to the upstream matcher. Most name no mapped
// product: they produce no match transaction at all, and only the CVE that matches a stored php does
// (F70). Each ReplaceMatches call is one write transaction.
func TestEngine_CNABackfillRunsNoEmptyMatchTransactions(t *testing.T) {
	h := newHarness(t)
	cfg := config.Default()
	cfg.ClusterName = "prod"
	e := engine.New(engine.Options{Config: cfg, Store: h.st, Grype: h.grype, CNA: upstream.New(h.st.Store), Now: h.clock.Now})

	const d3, matched = "sha256:d3", "CVE-2026-1000"
	php := model.Package{ImageDigest: d3, Ecosystem: "binary", Classifier: "php-cli-binary", Name: "php-cli", Version: "8.3.13",
		Path: "/usr/local/bin/php"}
	require.NoError(t, h.st.PutSBOM(ctx, d3, []byte("{}"), []model.Package{php}))
	require.NoError(t, h.st.PutUpstreamRanges(ctx, matched, "php",
		[]byte(`{"defaultStatus":"unaffected","versions":[{"version":"8.3.*","lessThan":"8.3.15","status":"affected"}]}`)))

	backfill := make([]string, 0, 2001)
	for i := range 2000 {
		backfill = append(backfill, fmt.Sprintf("CVE-2025-%05d", i))
	}
	require.NoError(t, e.OnCNARecords(ctx, backfill))
	require.Empty(t, h.st.replacedFor(model.SourceUpstream), "no empty transactions")

	require.NoError(t, e.OnCNARecords(ctx, append(backfill, matched)))
	replaced := h.st.replacedFor(model.SourceUpstream)
	require.Len(t, replaced, 1, "one transaction, for the CVE that matches")
	require.Equal(t, []string{matched}, replaced[0].AdvisoryIDs)
}
