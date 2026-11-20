package apigen_test

import (
	"reflect"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/web/apigen"
)

func TestOpenAPI_StreamExcludedFromStrictServer(t *testing.T) {
	typ := reflect.TypeFor[apigen.StrictServerInterface]()
	var got []string
	for i := range typ.NumMethod() {
		got = append(got, typ.Method(i).Name)
	}
	want := []string{"GetSummary", "GetScope", "GetExposure", "ListFindings", "ListTransitions", "GetAdvisory", "ListWorkloads",
		"GetWorkload", "ListImages", "GetImage", "ListImagePackages", "ListPackages", "ListNodeGroups", "GetNodeGroup", "GetNode",
		"GetCoverage", "ListFeeds", "ListExceptions", "GetSettings", "Search"}
	slices.Sort(got)
	slices.Sort(want)
	require.Equal(t, want, got)
	require.NotContains(t, got, "StreamChanges") // the stream is hand-written in internal/web/live
}
