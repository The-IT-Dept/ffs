package apiserver_test

import (
	"encoding/json"
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/web/apigen"
	"github.com/the-it-dept/ffs/internal/web/apiserver"
)

func TestFeeds_ListsFreshnessAndSources(t *testing.T) {
	_, h := newAPI(t)
	got := ok[apigen.FeedsList](t, get(t, h, "/api/v1/feeds"))
	var names []string
	byName := map[string]apigen.Feed{}
	for _, f := range got.Feeds {
		names = append(names, f.Name)
		byName[f.Name] = f
	}
	require.Equal(t, []string{"eol", "kev", "osv"}, names)
	require.True(t, byName["kev"].Stale)
	require.Equal(t, "24h0m0s", byName["kev"].StaleAfter)
	require.False(t, byName["osv"].Stale)
	require.NotNil(t, byName["osv"].LastSuccess)

	want := make([]apigen.Source, 0, len(apiserver.Sources))
	for _, s := range apiserver.Sources {
		want = append(want, apigen.Source{Name: s.Name, Feed: s.Feed, Licence: s.Licence, Attribution: s.Attribution, Url: s.URL})
	}
	require.Len(t, got.Sources, 7)
	require.Equal(t, "OSV.dev", got.Sources[0].Name)
	require.Equal(t, want, got.Sources)
}

func TestExceptions_ListsCRs(t *testing.T) {
	f, h := newAPI(t)
	got := ok[apigen.ExceptionsList](t, get(t, h, "/api/v1/exceptions"))
	require.Len(t, got.Exceptions, 1)
	e := got.Exceptions[0]
	require.Equal(t, "shop/accept-risk", e.Id)
	require.Equal(t, []string{"CVE-2026-0005"}, e.Advisories)
	require.Equal(t, 1, e.MatchedFindings)
	require.False(t, e.Expired)
	require.Equal(t, "Not reachable in our configuration", e.Reason)

	f.Kube = nil
	got = ok[apigen.ExceptionsList](t, get(t, handlerOf(f), "/api/v1/exceptions"))
	require.NotNil(t, got.Exceptions)
	require.Empty(t, got.Exceptions, "no Kubernetes client lists no exceptions")
}

func TestSettings_OmitsDeploymentDetails(t *testing.T) {
	_, h := newAPI(t)
	rec := get(t, h, "/api/v1/settings")
	typed := ok[apigen.Settings](t, rec)
	require.Equal(t, "test", typed.ClusterName)

	var got map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.ElementsMatch(t, []string{"cluster", "generatedAt", "version", "clusterName", "feeds", "priority", "exposure", "crd", "events",
		"openReports", "exceptions", "retention", "upgrades", "nodeAgent"}, slices.Collect(maps.Keys(got)))
	for _, k := range []string{"registry", "listen", "allowedHosts", "storePath", "dataDir", "catalog"} {
		require.NotContains(t, got, k)
	}
	// The node agent's listen address, TLS directory and namespace are deployment details too.
	require.ElementsMatch(t, []string{"enabled", "staleAfter"}, slices.Collect(maps.Keys(got["nodeAgent"].(map[string]any))))
	require.InDelta(t, 0.1, got["priority"].(map[string]any)["epssBump"], 1e-9)

	var feeds []string
	for _, f := range typed.Feeds {
		feeds = append(feeds, f.Name)
	}
	require.True(t, slices.IsSorted(feeds), "%v", feeds)
	require.Contains(t, feeds, "chainguard-osv")
}
