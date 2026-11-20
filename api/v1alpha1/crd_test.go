package v1alpha1_test

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/the-it-dept/ffs/api/v1alpha1"
	"github.com/the-it-dept/ffs/internal/testenv"
)

var cfg *rest.Config

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}
	env, c, err := testenv.Start()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	cfg = c
	code := m.Run()
	_ = env.Stop()
	os.Exit(code)
}

func newClient(t *testing.T) client.Client {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, scheme.AddToScheme(s))
	require.NoError(t, apiextensionsv1.AddToScheme(s))
	require.NoError(t, v1alpha1.AddToScheme(s))
	c, err := client.New(cfg, client.Options{Scheme: s})
	require.NoError(t, err)
	return c
}

func TestCRDCategories(t *testing.T) {
	if testing.Short() {
		t.Skip("envtest")
	}
	c, ctx := newClient(t), context.Background()
	hidden := "anx" + "iety"
	for name, w := range map[string]struct {
		scope apiextensionsv1.ResourceScope
		cats  []string
		cols  []string
	}{
		"findings.ffs.theitdept.au":        {apiextensionsv1.NamespaceScoped, []string{"ffs", hidden}, []string{"ADVISORY", "SEVERITY", "PRIORITY", "PACKAGE", "INSTALLED", "FIX", "SUGGESTED", "AGE"}},
		"vulnerabilities.ffs.theitdept.au": {apiextensionsv1.ClusterScoped, []string{"ffs", hidden}, []string{"SEVERITY", "PRIORITY", "KEV", "EPSS", "WORKLOADS", "FIX", "AGE"}},
		"alerttargets.ffs.theitdept.au":    {apiextensionsv1.ClusterScoped, []string{"ffs"}, nil},
		"exceptions.ffs.theitdept.au":      {apiextensionsv1.NamespaceScoped, []string{"ffs"}, nil},
	} {
		var crd apiextensionsv1.CustomResourceDefinition
		require.NoError(t, c.Get(ctx, client.ObjectKey{Name: name}, &crd))
		require.Equal(t, w.scope, crd.Spec.Scope, name)
		require.ElementsMatch(t, w.cats, crd.Spec.Names.Categories, name)
		require.NotNil(t, crd.Spec.Versions[0].Subresources.Status, name)
		if w.cols != nil {
			var got []string
			for _, col := range crd.Spec.Versions[0].AdditionalPrinterColumns {
				got = append(got, strings.ToUpper(col.Name))
			}
			require.Equal(t, w.cols, got, name)
		}
	}
}

func TestAlertTargetDefaults(t *testing.T) {
	if testing.Short() {
		t.Skip("envtest")
	}
	c, ctx := newClient(t), context.Background()
	at := &v1alpha1.AlertTarget{ObjectMeta: metav1.ObjectMeta{Name: "ops"},
		Spec: v1alpha1.AlertTargetSpec{Type: "slack", SecretRef: v1alpha1.SecretReference{Name: "slack-ops"},
			QuietHours: &v1alpha1.QuietHours{Intervals: []v1alpha1.TimeInterval{{Weekdays: []string{"saturday:sunday"}}}}}}
	require.NoError(t, c.Create(ctx, at))
	require.NoError(t, c.Get(ctx, client.ObjectKeyFromObject(at), at))
	s := at.Spec
	require.Equal(t, "urgent", s.Immediate.MinPriority)
	require.Equal(t, "0 9 * * *", s.Digest.Schedule)
	require.Equal(t, "UTC", s.Digest.TimeZone)
	require.Equal(t, "medium", s.Digest.MinPriority)
	require.True(t, *s.Digest.IncludeResolved)
	require.True(t, *s.QuietHours.AllowUrgent)
	require.False(t, s.NotifyOnFeedStale || s.Paused || s.AllowPrivate)
	require.Equal(t, "url", s.SecretRef.URLKey)
	require.Equal(t, "signingSecret", s.SecretRef.SigningSecretKey)

	off := &v1alpha1.AlertTarget{ObjectMeta: metav1.ObjectMeta{Name: "quiet"},
		Spec: v1alpha1.AlertTargetSpec{Type: "webhook", SecretRef: v1alpha1.SecretReference{Name: "hook"},
			Digest: v1alpha1.DigestSpec{IncludeResolved: ptr.To(false)}}}
	require.NoError(t, c.Create(ctx, off))
	require.NoError(t, c.Get(ctx, client.ObjectKeyFromObject(off), off))
	require.False(t, *off.Spec.Digest.IncludeResolved) // explicit false is not defaulted back to true

	bad := &v1alpha1.AlertTarget{ObjectMeta: metav1.ObjectMeta{Name: "email"},
		Spec: v1alpha1.AlertTargetSpec{Type: "email", SecretRef: v1alpha1.SecretReference{Name: "x"}}}
	requireInvalid(t, c.Create(ctx, bad), "type", `spec.type: Unsupported value: "email": supported values: "slack", "discord", "teams", "webhook"`)
}

// requireInvalid checks err is the API server's Invalid error naming the expected field error, not just any
// rejection (F55).
func requireInvalid(t *testing.T, err error, name, want string) {
	t.Helper()
	require.True(t, apierrors.IsInvalid(err), "%s: %v", name, err)
	require.ErrorContains(t, err, want, name)
}

func TestExceptionValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("envtest")
	}
	c, ctx := newClient(t), context.Background()
	valid := func() *v1alpha1.Exception {
		return &v1alpha1.Exception{ObjectMeta: metav1.ObjectMeta{GenerateName: "ex-", Namespace: "default"},
			Spec: v1alpha1.ExceptionSpec{Advisories: []string{"CVE-2026-0001"}, Reason: "Not reachable in this build",
				Expires: metav1.NewTime(time.Now().Add(30 * 24 * time.Hour))}}
	}
	require.NoError(t, c.Create(ctx, valid()))
	for name, tc := range map[string]struct {
		mut  func(*v1alpha1.Exception)
		want string
	}{
		"empty reason":    {func(e *v1alpha1.Exception) { e.Spec.Reason = "" }, "spec.reason: Invalid value: \"\": spec.reason in body should be at least 1 chars long"},
		"missing expires": {func(e *v1alpha1.Exception) { e.Spec.Expires = metav1.Time{} }, "spec.expires: Required value"},
		"no selector": {func(e *v1alpha1.Exception) { e.Spec.Advisories = nil },
			"spec: Invalid value: at least one of advisories, packages, imageRepositories or owners is required"},
		"bad vexStatus": {func(e *v1alpha1.Exception) { e.Spec.VEXStatus = "maybe" },
			`spec.vexStatus: Unsupported value: "maybe": supported values: "not_affected", "affected", "fixed", "under_investigation"`},
		"bad justification": {func(e *v1alpha1.Exception) { e.Spec.Justification = "trust me" },
			`spec.justification: Unsupported value: "trust me": supported values: "component_not_present"`},
	} {
		e := valid()
		tc.mut(e)
		requireInvalid(t, c.Create(ctx, e), name, tc.want)
	}
}
