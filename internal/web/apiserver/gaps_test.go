package apiserver_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/web/apiserver"
	"github.com/the-it-dept/ffs/internal/web/webtest"
)

// V27: the rail and the summary count a scope's gaps from the store's tally instead of listing every
// image; the count is exactly the number of gaps /coverage lists, in every scope and coverage state.
func TestGaps_CountMatchesList(t *testing.T) {
	f := webtest.Open(t)
	ctx := t.Context()
	// Every kind of image gap: a full image with a classifier-found package matched by CPE only, an
	// image not matched yet, and the fixture's pending, unresolvable, failed and partial images.
	require.NoError(t, f.Store.PutSBOM(ctx, webtest.DigestCoreDNS, nil, []model.Package{
		{Ecosystem: "binary", Name: "redis-server", Version: "7.4.1", Classifier: "redis-binary", Path: "/usr/local/bin/redis-server"},
	}))
	require.NoError(t, f.Store.MarkUnmatched(ctx, webtest.DigestPayments, webtest.Now))
	agentReport(t, f, "worker-1", time.Minute, model.GapNodeAgentBlocked)
	srv := apiserver.New(f.Options())

	for _, sc := range []model.Scope{
		{Kind: model.ScopeCluster},
		{Kind: model.ScopeNamespace, Value: "shop"}, {Kind: model.ScopeNamespace, Value: "payments"},
		{Kind: model.ScopeNamespace, Value: "ops"}, {Kind: model.ScopeNamespace, Value: "kube-system"},
		{Kind: model.ScopeWorkload, Value: webtest.Worker.Key()}, {Kind: model.ScopeWorkload, Value: webtest.Payments.Key()},
		{Kind: model.ScopeImage, Value: webtest.DigestWorker}, {Kind: model.ScopeImage, Value: webtest.DigestWeb},
		{Kind: model.ScopeImage, Value: webtest.DigestFailed}, {Kind: model.ScopeImage, Value: webtest.DigestCoreDNS},
		{Kind: model.ScopeNodeGroup, Value: webtest.AgentGroupKey}, {Kind: model.ScopeNode, Value: "worker-1"},
		{Kind: model.ScopeControlPlane},
	} {
		gaps, n, err := srv.ScopeGapsAndCount(ctx, sc)
		require.NoError(t, err, sc.String())
		require.Len(t, gaps, n, sc.String())
	}
	gaps, _, err := srv.ScopeGapsAndCount(ctx, model.Scope{Kind: model.ScopeCluster})
	require.NoError(t, err)
	require.Greater(t, len(gaps), 6, "the fixture covers several gap kinds")
}
