package openreports_test

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	fakedisc "k8s.io/client-go/discovery/fake"
	clienttesting "k8s.io/client-go/testing"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	orv1alpha1 "github.com/openreports/reports-api/apis/openreports.io/v1alpha1"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/output/openreports"
	"github.com/the-it-dept/ffs/internal/store"
)

var wgGV = schema.GroupVersion{Group: "wgpolicyk8s.io", Version: "v1alpha2"}

type harness struct {
	st      *store.Store
	c       client.Client
	w       *openreports.Writer
	creates atomic.Int32
	updates atomic.Int32
}

func newHarness(t *testing.T, cfg config.OpenReportsConfig, served ...string) *harness {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "ffs.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })

	s := runtime.NewScheme()
	require.NoError(t, orv1alpha1.Install(s))
	s.AddKnownTypeWithName(wgGV.WithKind("PolicyReport"), &unstructured.Unstructured{})
	s.AddKnownTypeWithName(wgGV.WithKind("PolicyReportList"), &unstructured.UnstructuredList{})

	h := &harness{st: st}
	h.c = fake.NewClientBuilder().WithScheme(s).WithInterceptorFuncs(interceptor.Funcs{
		Create: func(ctx context.Context, c client.WithWatch, o client.Object, opts ...client.CreateOption) error {
			h.creates.Add(1)
			return c.Create(ctx, o, opts...)
		},
		Update: func(ctx context.Context, c client.WithWatch, o client.Object, opts ...client.UpdateOption) error {
			h.updates.Add(1)
			return c.Update(ctx, o, opts...)
		},
	}).Build()

	fd := &fakedisc.FakeDiscovery{Fake: &clienttesting.Fake{}}
	for _, gv := range served {
		kind := "Report"
		if gv == wgGV.String() {
			kind = "PolicyReport"
		}
		fd.Resources = append(fd.Resources, &metav1.APIResourceList{GroupVersion: gv, APIResources: []metav1.APIResource{{Kind: kind}}})
	}
	var d discovery.ServerResourcesInterfaceWithContext = fd
	h.w = openreports.New(h.c, h.c, d, st, cfg, openreports.Options{Namespace: "ffs"})
	return h
}

func (h *harness) seed(t *testing.T, ref model.OwnerRef, id string, p model.Priority) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, h.st.UpsertOwner(ctx, model.Owner{Ref: ref}))
	require.NoError(t, h.st.UpsertAdvisory(ctx, model.Advisory{ID: id, Title: "t " + id}))
	f := model.Finding{Fingerprint: model.FindingFingerprint("c", ref, "docker.io/library/nginx", id), Owner: ref,
		ImageRepo: "docker.io/library/nginx", AdvisoryID: id, Priority: p, Severity: model.SeverityHigh,
		State: model.StateOpen, Matched: t0, LastSeen: t0, Observed: t0, Published: t0}
	require.NoError(t, h.st.ApplyFindings(ctx, []model.Finding{f}, nil))
}

func (h *harness) reports(t *testing.T) []orv1alpha1.Report {
	t.Helper()
	var l orv1alpha1.ReportList
	require.NoError(t, h.c.List(context.Background(), &l))
	return l.Items
}

func (h *harness) policyReports(t *testing.T) []unstructured.Unstructured {
	t.Helper()
	var l unstructured.UnstructuredList
	l.SetGroupVersionKind(wgGV.WithKind("PolicyReportList"))
	require.NoError(t, h.c.List(context.Background(), &l))
	return l.Items
}

const orGV = "openreports.io/v1alpha1"

func TestWriter_AutoModeSkipsWithoutCRD(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, config.OpenReportsConfig{Mode: "auto", MaxResults: 100})
	h.seed(t, dref, "CVE-2026-0001", model.PriorityHigh)
	require.NoError(t, h.w.ReconcileOnce(ctx))
	assert.Zero(t, h.creates.Load())

	h = newHarness(t, config.OpenReportsConfig{Mode: "on", MaxResults: 100})
	h.seed(t, dref, "CVE-2026-0001", model.PriorityHigh)
	require.NoError(t, h.w.ReconcileOnce(ctx))
	assert.EqualValues(t, 1, h.creates.Load())

	h = newHarness(t, config.OpenReportsConfig{Mode: "auto", MaxResults: 100}, orGV)
	h.seed(t, dref, "CVE-2026-0001", model.PriorityHigh)
	require.NoError(t, h.w.ReconcileOnce(ctx))
	assert.EqualValues(t, 1, h.creates.Load())
}

func TestWriter_ModeOffWritesNothing(t *testing.T) {
	h := newHarness(t, config.OpenReportsConfig{Mode: "off", MaxResults: 100}, orGV)
	h.seed(t, dref, "CVE-2026-0001", model.PriorityHigh)
	require.NoError(t, h.w.ReconcileOnce(context.Background()))
	assert.Zero(t, h.creates.Load())
}

func TestWriter_HashGatedWrites(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, config.OpenReportsConfig{Mode: "auto", MaxResults: 100}, orGV)
	h.seed(t, dref, "CVE-2026-0001", model.PriorityHigh)
	require.NoError(t, h.w.ReconcileOnce(ctx))
	require.NoError(t, h.w.ReconcileOnce(ctx))
	assert.EqualValues(t, 1, h.creates.Load())
	assert.Zero(t, h.updates.Load())

	h.seed(t, dref, "CVE-2026-0002", model.PriorityUrgent)
	require.NoError(t, h.w.ReconcileOnce(ctx))
	assert.EqualValues(t, 1, h.updates.Load())
	rs := h.reports(t)
	require.Len(t, rs, 1)
	assert.Equal(t, orv1alpha1.ReportSummary{Fail: 2}, rs[0].Summary)
}

func TestWriter_DeletesWhenOwnerHasNone(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, config.OpenReportsConfig{Mode: "auto", MaxResults: 100}, orGV)
	h.seed(t, dref, "CVE-2026-0001", model.PriorityHigh)
	foreign := &orv1alpha1.Report{ObjectMeta: metav1.ObjectMeta{Name: "other", Namespace: "shop"}, Source: "trivy"}
	require.NoError(t, h.c.Create(ctx, foreign))
	require.NoError(t, h.w.ReconcileOnce(ctx))
	require.Len(t, h.reports(t), 2)

	h.seed(t, dref, "CVE-2026-0001", model.PriorityLow) // now below medium
	require.NoError(t, h.w.ReconcileOnce(ctx))
	rs := h.reports(t)
	require.Len(t, rs, 1)
	assert.Equal(t, "other", rs[0].Name)
}

func TestWriter_ClusterSubjectsInInstallNamespace(t *testing.T) {
	h := newHarness(t, config.OpenReportsConfig{Mode: "on", MaxResults: 100})
	h.seed(t, model.OwnerRef{Kind: "Cluster", Name: "test"}, "CVE-2026-0001", model.PriorityHigh)
	require.NoError(t, h.w.ReconcileOnce(context.Background()))
	rs := h.reports(t)
	require.Len(t, rs, 1)
	assert.Equal(t, "ffs-cluster-test", rs[0].Name)
	assert.Equal(t, "ffs", rs[0].Namespace)
	assert.Nil(t, rs[0].Scope)
}

func TestWriter_WGPolicyMirrorsMapping(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, config.OpenReportsConfig{Mode: "auto", MaxResults: 100, WGPolicy: true}, orGV, wgGV.String())
	h.seed(t, dref, "CVE-2026-0001", model.PriorityHigh)
	require.NoError(t, h.w.ReconcileOnce(ctx))
	prs := h.policyReports(t)
	require.Len(t, prs, 1)
	rs := h.reports(t)
	require.Len(t, rs, 1)
	assert.Equal(t, "ffs-deployment-web", prs[0].GetName())
	assert.NotContains(t, prs[0].Object, "source")
	assert.NotContains(t, prs[0].Object, "configuration")
	res, _, err := unstructured.NestedSlice(prs[0].Object, "results")
	require.NoError(t, err)
	want, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&rs[0])
	require.NoError(t, err)
	assert.Equal(t, want["results"], any(res))
	assert.Equal(t, want["summary"], prs[0].Object["summary"])

	h = newHarness(t, config.OpenReportsConfig{Mode: "auto", MaxResults: 100}, orGV, wgGV.String())
	h.seed(t, dref, "CVE-2026-0001", model.PriorityHigh)
	require.NoError(t, h.w.ReconcileOnce(ctx))
	assert.Empty(t, h.policyReports(t))
}
