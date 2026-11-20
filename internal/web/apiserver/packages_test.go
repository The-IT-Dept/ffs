package apiserver_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/web/apigen"
)

func TestPackages_ListAndFacets(t *testing.T) {
	_, h := newAPI(t)
	got := ok[apigen.PackagesPage](t, get(t, h, "/api/v1/packages?facets=ecosystem,priority"))
	require.NotEmpty(t, got.Rows)
	first := got.Rows[0]
	require.Equal(t, apigen.PackageRow{Ecosystem: "deb", Name: "openssl", Version: "3.0.15-1~deb12u1", Images: 2, Workloads: 2,
		Counts: apigen.PriorityCounts{Urgent: 1, High: 1}, Worst: apigen.PriorityUrgent}, first)
	require.Len(t, got.Facets, 2)
	require.NotEmpty(t, got.Facets["ecosystem"])
	require.NotEmpty(t, got.Facets["priority"])

	gomod := ok[apigen.PackagesPage](t, get(t, h, "/api/v1/packages?ecosystem=go-module&facets=ecosystem"))
	var versions []string
	for _, r := range gomod.Rows {
		require.Equal(t, "stdlib", r.Name)
		versions = append(versions, r.Version)
	}
	require.ElementsMatch(t, []string{"go1.24.1", "go1.25.3"}, versions)
	for _, v := range gomod.Facets["ecosystem"] {
		require.Equal(t, v.Value == "go-module", v.Selected, v.Value)
	}

	worker := ok[apigen.PackagesPage](t, get(t, h, "/api/v1/packages?scope=workload:Deployment/shop/worker"))
	require.Len(t, worker.Rows, 1)
	require.Equal(t, "traefik", worker.Rows[0].Name)
	require.NotNil(t, worker.Rows[0].Classifier)
	require.Equal(t, "traefik-binary", *worker.Rows[0].Classifier)

	wantProblem(t, get(t, h, "/api/v1/packages?scope=controlplane"), 400, apigen.ProblemCodeInvalidScope)
}
