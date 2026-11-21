package openreports

import (
	"testing"

	orv1alpha1 "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// TestStub_KeepsOnlyWhatSyncReads (W56): the writer's view holds each report's kind, namespace,
// name, resourceVersion and content hash, not its results.
func TestStub_KeepsOnlyWhatSyncReads(t *testing.T) {
	meta := metav1.ObjectMeta{Namespace: "shop", Name: "ffs-deployment-web", ResourceVersion: "42",
		Labels:      map[string]string{LabelManagedBy: "ffs"},
		Annotations: map[string]string{AnnotationContentHash: "abc", "other": "x"}}
	rep := &orv1alpha1.Report{ObjectMeta: meta, Summary: orv1alpha1.ReportSummary{Fail: 2},
		Results: []orv1alpha1.ReportResult{{Policy: "CVE-2026-0001"}, {Policy: "CVE-2026-0002"}}}
	got, ok := stub(rep).(*orv1alpha1.Report)
	require.True(t, ok)
	require.Equal(t, &orv1alpha1.Report{ObjectMeta: metav1.ObjectMeta{Namespace: "shop", Name: "ffs-deployment-web",
		ResourceVersion: "42", Annotations: map[string]string{AnnotationContentHash: "abc"}}}, got)

	u := &unstructured.Unstructured{Object: map[string]any{"results": []any{map[string]any{"policy": "CVE-2026-0001"}}}}
	u.SetAPIVersion(wgGroupVersion)
	u.SetKind("PolicyReport")
	u.SetNamespace("shop")
	u.SetName("ffs-deployment-web")
	u.SetResourceVersion("7")
	u.SetAnnotations(map[string]string{AnnotationContentHash: "def"})
	us, ok := stub(u).(*unstructured.Unstructured)
	require.True(t, ok)
	require.Equal(t, wgGroupVersion, us.GetAPIVersion())
	require.Equal(t, "PolicyReport", us.GetKind())
	require.Equal(t, "shop/ffs-deployment-web", us.GetNamespace()+"/"+us.GetName())
	require.Equal(t, "7", us.GetResourceVersion())
	require.Equal(t, map[string]string{AnnotationContentHash: "def"}, us.GetAnnotations())
	require.NotContains(t, us.Object, "results")

	require.Empty(t, stub(&orv1alpha1.Report{ObjectMeta: metav1.ObjectMeta{Name: "x"}}).GetAnnotations(), "no hash, no annotations")
}
