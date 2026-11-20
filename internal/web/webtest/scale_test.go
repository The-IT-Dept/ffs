package webtest_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
	"github.com/the-it-dept/ffs/internal/web/webtest"
)

// scale builds a Scale fixture of size n in a temporary directory, closed when the test ends.
func scale(t *testing.T, n webtest.ScaleSize) *webtest.Fixture {
	t.Helper()
	f, err := webtest.Scale(t.Context(), t.TempDir()+"/ffs.db", n)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, f.Close()) })
	return f
}

// containerImage reports whether digest names a container image rather than a cluster-level
// owner's synthetic image or a node group's host image (the read model's image_kind container).
func containerImage(digest string) bool {
	for _, p := range []string{"k8s:", "runtime:", model.NodeGroupDigestPrefix} {
		if strings.HasPrefix(digest, p) {
			return false
		}
	}
	return true
}

// TestScale_DeterministicAndSized: two fixtures of one size write the same rows, in the numbers asked for.
// Images 14 makes 6 catalogued, 5 pending and 3 unresolvable images, so some workloads run no catalogued image
// and one runs its catalogued image second.
func TestScale_DeterministicAndSized(t *testing.T) {
	n := webtest.ScaleSize{Namespaces: 2, Workloads: 19, Images: 14, PackagesPerImage: 20, OpenFindings: 200, Excepted: 20,
		Resolved: 30, Suggestions: 2, ExposedWorkloads: 3}
	a, b := scale(t, n), scale(t, n)
	states := map[model.FindingState]int{model.StateOpen: 200, model.StateExcepted: 20, model.StateResolved: 30}

	for _, f := range []*webtest.Fixture{a, b} {
		for state, want := range states {
			got, err := f.Store.CountFindings(t.Context(), store.FindingFilter{States: []model.FindingState{state}})
			require.NoError(t, err)
			require.Equal(t, want, got, state)
		}

		owners, err := f.Store.ListOwners(t.Context())
		require.NoError(t, err)
		kinds := map[string]int{}
		for _, o := range owners {
			kinds[o.Ref.Kind]++
		}
		require.Equal(t, map[string]int{"Deployment": 19, model.OwnerKindCluster: 1, model.OwnerKindContainerRuntime: 1}, kinds)

		images, err := f.Store.ListImages(t.Context(), store.ImageFilter{})
		require.NoError(t, err)
		var containers int
		for _, img := range images {
			if containerImage(img.Digest) {
				containers++
			}
		}
		require.Equal(t, 14, containers)

		workloads, err := f.Store.OwnerEntities(t.Context(), model.Scope{Kind: model.ScopeCluster})
		require.NoError(t, err)
		require.Len(t, workloads, 19)
		var exposed int
		for _, w := range workloads {
			if w.Exposed {
				exposed++
			}
		}
		require.Equal(t, 3, exposed)
	}

	fingerprints := func(f *webtest.Fixture, state model.FindingState) []string {
		fs, err := f.Store.ListFindings(t.Context(), store.FindingFilter{States: []model.FindingState{state}})
		require.NoError(t, err)
		out := make([]string, len(fs))
		for i, x := range fs {
			out[i] = x.Fingerprint
		}
		slices.Sort(out)
		return out
	}
	for state, want := range states {
		fa := fingerprints(a, state)
		require.Len(t, fa, want)
		require.Equal(t, fa, fingerprints(b, state), state)
	}

	first := func(f *webtest.Fixture) []model.Finding {
		fs, err := f.Store.ListFindings(t.Context(), store.FindingFilter{Limit: 20})
		require.NoError(t, err)
		require.Len(t, fs, 20)
		return fs
	}
	require.Equal(t, first(a), first(b))
}

// TestScale_FindingsOnCataloguedImages: every workload finding is on the first catalogued image its workload
// runs, never on a pending or unresolvable one, and a workload that runs no catalogued image has none.
func TestScale_FindingsOnCataloguedImages(t *testing.T) {
	f := scale(t, webtest.ScaleSize{Namespaces: 2, Workloads: 19, Images: 14, PackagesPerImage: 20, OpenFindings: 200,
		Excepted: 20, Resolved: 30, Suggestions: 2, ExposedWorkloads: 3})
	images, err := f.Store.ListImages(t.Context(), store.ImageFilter{})
	require.NoError(t, err)
	status := map[string]model.ImageStatus{}
	for _, img := range images {
		status[img.Digest] = img.Status
	}
	owners, err := f.Store.ListOwners(t.Context())
	require.NoError(t, err)
	want := map[string]string{} // workload key -> the digest its findings are on, "" for none
	var none, second int
	for _, o := range owners {
		if o.Ref.Kind != "Deployment" {
			continue
		}
		want[o.Ref.Key()] = ""
		for c, use := range o.Containers {
			if status[use.Digest] == model.ImageCatalogued {
				want[o.Ref.Key()] = use.Digest
				if c > 0 {
					second++
				}
				break
			}
		}
		if want[o.Ref.Key()] == "" {
			none++
		}
	}
	require.Positive(t, none, "some workloads run no catalogued image")
	require.Positive(t, second, "some workload runs its catalogued image second")

	fs, err := f.Store.ListFindings(t.Context(), store.FindingFilter{States: []model.FindingState{model.StateOpen,
		model.StateExcepted, model.StateResolved}})
	require.NoError(t, err)
	require.Len(t, fs, 250)
	carried := map[string]int{}
	for _, x := range fs {
		if x.Owner.Kind != "Deployment" {
			continue
		}
		carried[x.Owner.Key()]++
		require.Equal(t, []string{want[x.Owner.Key()]}, x.Digests, "%s %s", x.Owner.Key(), x.AdvisoryID)
		require.Equal(t, model.ImageCatalogued, status[x.Digests[0]], x.Owner.Key())
	}
	for key, digest := range want {
		if digest == "" {
			require.Zero(t, carried[key], "%s runs no catalogued image", key)
		} else {
			require.Positive(t, carried[key], key)
		}
	}
}
