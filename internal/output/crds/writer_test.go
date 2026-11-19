package crds

import (
	"fmt"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/the-it-dept/ffs/api/v1alpha1"
	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
	"github.com/the-it-dept/ffs/internal/testenv"
)

var self = &corev1.ObjectReference{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "ffs", Name: "ffs", UID: "uid-ffs"}

// newWriter clears every managed resource left by earlier tests and returns a writer over st.
func newWriter(t *testing.T, st *store.Store, cfg func(*config.Config)) (*Writer, *testenv.Recorder) {
	t.Helper()
	needEnv(t)
	var fl v1alpha1.FindingList
	require.NoError(t, env.Client.List(ctx, &fl, client.MatchingLabels{LabelManagedBy: "ffs"}))
	for i := range fl.Items {
		require.NoError(t, client.IgnoreNotFound(env.Client.Delete(ctx, &fl.Items[i])))
	}
	var vl v1alpha1.VulnerabilityList
	require.NoError(t, env.Client.List(ctx, &vl, client.MatchingLabels{LabelManagedBy: "ffs"}))
	for i := range vl.Items {
		require.NoError(t, client.IgnoreNotFound(env.Client.Delete(ctx, &vl.Items[i])))
	}
	c := config.Default()
	if cfg != nil {
		cfg(&c)
	}
	rec := &testenv.Recorder{}
	return NewWriter(WriterOptions{Client: env.Client, Store: st, Config: c, Namespace: "ffs", Self: self, Recorder: rec}), rec
}

// findingCRs returns the managed Findings keyed by "namespace/name".
func findingCRs(t *testing.T) map[string]v1alpha1.Finding {
	t.Helper()
	var l v1alpha1.FindingList
	require.NoError(t, env.Client.List(ctx, &l, client.MatchingLabels{LabelManagedBy: "ffs"}))
	out := map[string]v1alpha1.Finding{}
	for _, f := range l.Items {
		out[f.Namespace+"/"+f.Name] = f
	}
	return out
}

// vulnerabilityCRs returns the managed Vulnerabilities keyed by name.
func vulnerabilityCRs(t *testing.T) map[string]v1alpha1.Vulnerability {
	t.Helper()
	var l v1alpha1.VulnerabilityList
	require.NoError(t, env.Client.List(ctx, &l, client.MatchingLabels{LabelManagedBy: "ffs"}))
	out := map[string]v1alpha1.Vulnerability{}
	for _, v := range l.Items {
		out[v.Name] = v
	}
	return out
}

func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestCRWriter_CapDropsLowestFirst(t *testing.T) {
	needEnv(t)
	st := newStore(t)
	seedAdvisory(t, st)
	a, b, c, d, e := deployment("web", "a"), deployment("web", "b"), deployment("web", "c"), deployment("web", "d"), deployment("web", "e")
	t1, t2, t3, t4 := t0, t0.Add(time.Minute), t0.Add(2*time.Minute), t0.Add(3*time.Minute)
	apply(t, st,
		openFinding(a, debianRepo, cve, model.PriorityUrgent, t1),
		openFinding(b, debianRepo, cve, model.PriorityHigh, t1),
		openFinding(c, debianRepo, cve, model.PriorityHigh, t2),
		openFinding(d, debianRepo, cve, model.PriorityHigh, t3),
		openFinding(e, debianRepo, cve, model.PriorityUrgent, t4))
	w, rec := newWriter(t, st, func(c *config.Config) { c.CRD.MaxFindings, c.CRD.MinPriority = 3, "high" })

	require.NoError(t, w.Sync(ctx))
	name := func(o model.OwnerRef) string { return "web/" + FindingName(o, cve) }
	require.ElementsMatch(t, []string{name(a), name(e), name(b)}, keysOf(findingCRs(t)))
	require.InDelta(t, 2.0, testutil.ToFloat64(FindingCRsDropped), 0)

	events := rec.Snapshot()
	require.Len(t, events, 1)
	require.Equal(t, testenv.RecordedEvent{Regarding: self, Type: corev1.EventTypeWarning, Reason: "FindingCapReached",
		Action: capAction,
		Note:   "Finding resources are capped at 3 (crd.maxFindings); 2 lower-priority findings are not written as resources and remain available in the API."},
		events[0])

	vulns := vulnerabilityCRs(t)
	require.Equal(t, []string{"cve-2026-41873"}, keysOf(vulns))
	require.Equal(t, int32(5), vulns["cve-2026-41873"].Status.AffectedOwners)

	require.NoError(t, w.Sync(ctx))
	require.Len(t, rec.Snapshot(), 1, "the same overflow raises no second Event")
}

func TestCRWriter_HashGatedWrites(t *testing.T) {
	needEnv(t)
	st := newStore(t)
	seedAdvisory(t, st)
	f := openFinding(deployment("web", "api"), debianRepo, cve, model.PriorityUrgent, t0)
	apply(t, st, f)
	w, _ := newWriter(t, st, nil)
	key := "web/deployment-api-cve-2026-41873"

	require.NoError(t, w.Sync(ctx))
	first := findingCRs(t)[key]
	require.NotEmpty(t, first.Annotations[AnnotationContentHash])
	require.Equal(t, f.Fingerprint, first.Annotations[AnnotationFingerprint])
	require.Equal(t, "urgent", first.Labels[LabelPriority])
	require.Equal(t, "urgent", first.Status.Priority)
	require.NoError(t, w.Sync(ctx))
	require.Equal(t, first.ResourceVersion, findingCRs(t)[key].ResourceVersion, "an unchanged finding is not rewritten")

	f.Priority = model.PriorityHigh
	apply(t, st, f)
	require.NoError(t, w.Sync(ctx))
	second := findingCRs(t)[key]
	require.NotEqual(t, first.ResourceVersion, second.ResourceVersion)
	require.NotEqual(t, first.Annotations[AnnotationContentHash], second.Annotations[AnnotationContentHash])
	require.Equal(t, "high", second.Status.Priority)
	require.Equal(t, "high", second.Labels[LabelPriority])

	f.LastSeen = f.LastSeen.Add(time.Hour) // same UTC day
	apply(t, st, f)
	require.NoError(t, w.Sync(ctx))
	require.Equal(t, second.ResourceVersion, findingCRs(t)[key].ResourceVersion, "liveness within the day is not rewritten")
}

func TestCRWriter_DeletesStale(t *testing.T) {
	needEnv(t)
	st := newStore(t)
	seedAdvisory(t, st)
	const other = "CVE-2026-2222"
	a := openFinding(deployment("web", "a"), debianRepo, cve, model.PriorityUrgent, t0)
	b := openFinding(deployment("web", "b"), debianRepo, other, model.PriorityUrgent, t0)
	c := openFinding(deployment("web", "c"), debianRepo, cve, model.PriorityHigh, t0)
	apply(t, st, a, b, c)
	w, _ := newWriter(t, st, func(c *config.Config) { c.CRD.MinPriority = "high" })
	name := func(f model.Finding) string { return "web/" + FindingName(f.Owner, f.AdvisoryID) }

	require.NoError(t, w.Sync(ctx))
	require.ElementsMatch(t, []string{name(a), name(b), name(c)}, keysOf(findingCRs(t)))
	require.ElementsMatch(t, []string{"cve-2026-41873", "cve-2026-2222"}, keysOf(vulnerabilityCRs(t)))

	resolved := t0.Add(time.Hour)
	b.State, b.ResolvedAt = model.StateResolved, &resolved
	apply(t, st, b)
	require.NoError(t, w.Sync(ctx))
	require.ElementsMatch(t, []string{name(a), name(c)}, keysOf(findingCRs(t)), "a resolved finding's resource is deleted")
	require.Equal(t, []string{"cve-2026-41873"}, keysOf(vulnerabilityCRs(t)), "a Vulnerability without Findings is deleted")

	a.State, a.ExceptedBy = model.StateExcepted, "web/accept"
	apply(t, st, a)
	require.NoError(t, w.Sync(ctx))
	require.Equal(t, []string{name(c)}, keysOf(findingCRs(t)), "an excepted finding's resource is deleted")

	c.Priority = model.PriorityMedium
	apply(t, st, c)
	require.NoError(t, w.Sync(ctx))
	require.Empty(t, findingCRs(t), "a finding below crd.minPriority has no resource")
	require.Empty(t, vulnerabilityCRs(t))
}

func TestCRWriter_ClusterLevelInFFSNamespace(t *testing.T) {
	needEnv(t)
	st := newStore(t)
	prod := model.OwnerRef{Kind: "Cluster", Name: "prod"}
	apply(t, st, openFinding(prod, "kubernetes", "CVE-2026-1111", model.PriorityUrgent, t0))
	w, _ := newWriter(t, st, nil)

	require.NoError(t, w.Sync(ctx))
	crs := findingCRs(t)
	require.Equal(t, []string{"ffs/cluster-prod-cve-2026-1111"}, keysOf(crs))
	require.Equal(t, v1alpha1.OwnerReference{Kind: "Cluster", Name: "prod"}, crs["ffs/cluster-prod-cve-2026-1111"].Status.Subject.Owner)
}

func TestCRWriter_VulnerabilityTopFiftyOwners(t *testing.T) {
	needEnv(t)
	st := newStore(t)
	seedAdvisory(t, st)
	var fs []model.Finding
	for i := range 60 {
		p := model.PriorityHigh
		if i == 37 {
			p = model.PriorityUrgent
		}
		fs = append(fs, openFinding(deployment("web", fmt.Sprintf("w%02d", i)), debianRepo, cve, p, t0))
	}
	apply(t, st, fs...)
	w, _ := newWriter(t, st, nil)
	w.limiter = rate.NewLimiter(rate.Inf, 1) // 180 writes; the throttle is not under test here

	require.NoError(t, w.Sync(ctx))
	v := vulnerabilityCRs(t)["cve-2026-41873"].Status
	require.Equal(t, int32(60), v.AffectedOwners)
	require.Len(t, v.TopOwners, 50)
	require.Equal(t, v1alpha1.AffectedOwner{Kind: "Deployment", Namespace: "web", Name: "w37", Priority: "urgent"}, v.TopOwners[0])
	require.Equal(t, "w00", v.TopOwners[1].Name, "equal priorities are ordered by owner key")
	require.Equal(t, "urgent", v.HighestPriority)
	require.Equal(t, "9.8", v.CVSS)
	require.Equal(t, []string{ghsa}, v.Aliases)
	require.True(t, v.FixAvailable)
}

func TestFindingStatus_Suggestion(t *testing.T) {
	f := openFinding(deployment("web", "api"), "docker.io/library/nginx", cve, model.PriorityUrgent, t0)
	f.Suggestion = &model.Suggestion{Repo: "docker.io/library/nginx", FromTag: "1.30.6", ToTag: "1.30.7", ToDigest: "sha256:d2",
		Tier: model.TierPatch, Fixes: map[model.Priority]int{model.PriorityUrgent: 1}}
	st := findingStatus("default", f, model.Owner{}, model.Advisory{})
	require.Equal(t, &v1alpha1.SuggestionSummary{Target: "docker.io/library/nginx:1.30.7", Digest: "sha256:d2", Tier: "patch",
		Fixes: map[string]int32{"urgent": 1}}, st.Suggestion)

	f.Suggestion.Tier = model.TierNone
	require.Nil(t, findingStatus("default", f, model.Owner{}, model.Advisory{}).Suggestion)
	f.Suggestion = nil
	require.Nil(t, findingStatus("default", f, model.Owner{}, model.Advisory{}).Suggestion)
}

func TestFindingStatus_Content(t *testing.T) {
	api := deployment("web", "api")
	f := openFinding(api, debianRepo, cve, model.PriorityUrgent, t0)
	f.Provisional = true
	owner := model.Owner{Ref: api, ManagedBy: &model.ManagedBy{Tool: "flux-helmrelease", Name: "api", Namespace: "flux-system"},
		Containers: []model.ContainerUse{{Name: "app", Repo: debianRepo}, {Name: "proxy", Repo: "docker.io/library/nginx"},
			{Name: "migrate", Kind: model.ContainerInit, Repo: debianRepo}},
		Context: model.WorkloadContext{Exposed: true, ExposurePaths: []string{"Service web/api (LoadBalancer)"},
			PowerfulSA: true, SAReasons: []string{"service account can read secrets cluster-wide"}}}
	adv := model.Advisory{ID: cve, Aliases: []string{ghsa}, Title: "openssl: buffer overflow", Links: []string{"https://example.com/" + cve}}

	st := findingStatus("prod", f, owner, adv)
	require.Equal(t, "prod", st.Cluster)
	require.Equal(t, f.Fingerprint, st.Fingerprint)
	require.Equal(t, v1alpha1.FindingSubject{Owner: v1alpha1.OwnerReference{Kind: "Deployment", Namespace: "web", Name: "api", UID: "uid-api"},
		Containers: []string{"app", "migrate"}, ImageRepository: debianRepo, Digests: []string{"sha256:d1"},
		ManagedBy: &v1alpha1.ManagedBy{Tool: "flux-helmrelease", Name: "api", Namespace: "flux-system"}}, st.Subject)
	require.Equal(t, v1alpha1.AdvisorySummary{ID: cve, Aliases: []string{ghsa}, Title: "openssl: buffer overflow", Severity: "critical",
		SeveritySource: "debian", Links: []string{"https://example.com/" + cve}}, st.Advisory)
	require.Equal(t, []v1alpha1.AffectedPackage{{Name: "openssl", Type: "deb", Installed: "3.0.15-1~deb12u1",
		Fixed: []string{"3.0.17-1~deb12u1"}, Path: "/var/lib/dpkg/status.d/openssl"}}, st.Packages)
	require.Equal(t, "3.0.17-1~deb12u1", st.Fix)
	require.Equal(t, "urgent", st.Priority)
	require.Equal(t, f.Reasons, st.Reasons)
	require.Equal(t, v1alpha1.ExposureSummary{Exposed: true, ExposurePaths: []string{"Service web/api (LoadBalancer)"},
		PowerfulServiceAccount: true, ServiceAccountReasons: []string{"service account can read secrets cluster-wide"}}, st.Exposure)
	require.Equal(t, "open", st.State)
	require.True(t, st.Provisional)
	require.Equal(t, t0, st.Matched.Time)
	require.Equal(t, t0.Add(-48*time.Hour), st.Published.Time)

	f.Packages[0].Fixed, f.FixState, f.FixAvailable = nil, model.FixWontFix, false
	require.Equal(t, "wont-fix", findingStatus("prod", f, owner, adv).Fix, "without a fixed version Fix is the fix state")
}
