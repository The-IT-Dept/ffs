package inventory

import (
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/the-it-dept/ffs/internal/model"
)

// TestFlush_FinishedJobWithoutPodsIdle (F77): a standalone Job that completed or failed and whose pods
// are gone runs nothing, so it is not running; a Job just created, with no pods yet, still counts as
// running, as does a Job whose failure condition is not true.
func TestFlush_FinishedJobWithoutPodsIdle(t *testing.T) {
	job := func(name string, conds ...batchv1.JobCondition) *batchv1.Job {
		return &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: name},
			Spec:   batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: podSpec("nginx:1.27")}},
			Status: batchv1.JobStatus{Conditions: conds}}
	}
	cond := func(typ batchv1.JobConditionType, st corev1.ConditionStatus) batchv1.JobCondition {
		return batchv1.JobCondition{Type: typ, Status: st}
	}
	h := newHarness(t, newNode("n1", "amd64"),
		job("done", cond(batchv1.JobComplete, corev1.ConditionTrue)), job("failed", cond(batchv1.JobFailed, corev1.ConditionTrue)),
		job("new"), job("retrying", cond(batchv1.JobFailed, corev1.ConditionFalse)))
	h.res.tags[nginx+":1.27"] = idx
	h.res.platforms[idx+"|linux/amd64"] = registryManifest(mA, idx, "linux/amd64")

	require.NoError(t, h.inv.SyncAll(ctx))
	for name, idle := range map[string]bool{"done": true, "failed": true, "new": false, "retrying": false} {
		o := h.owner(t, "Job/apps/"+name)
		require.Equal(t, idle, o.NotRunning, name)
		require.Equal(t, []string{mA}, digestsOf(o.Containers), name)
	}
}

// TestTemplatePlatform (F84): an owner with no running pods is resolved at the platform its template
// pins, preferring the majority platform when the pins allow it.
func TestTemplatePlatform(t *testing.T) {
	amd, arm := NodePlatform{OS: "linux", Arch: "amd64"}, NodePlatform{OS: "linux", Arch: "arm64"}
	nodes := []model.Node{{Name: "n1", OS: "linux", Arch: "amd64", Ready: true}, {Name: "n2", OS: "linux", Arch: "amd64", Ready: true},
		{Name: "n3", OS: "linux", Arch: "arm64", Ready: true}, {Name: "n4", OS: "linux", Arch: "arm64", Ready: false},
		{Name: "n5", OS: "linux", Arch: "ppc64le", Ready: true}, {Name: "n6", OS: "linux", Arch: "ppc64le", Ready: true}}
	terms := func(exprs ...corev1.NodeSelectorRequirement) *corev1.Affinity {
		return &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
			NodeSelectorTerms: []corev1.NodeSelectorTerm{{MatchExpressions: exprs}}}}}
	}
	arch := func(op corev1.NodeSelectorOperator, values ...string) corev1.NodeSelectorRequirement {
		return corev1.NodeSelectorRequirement{Key: corev1.LabelArchStable, Operator: op, Values: values}
	}
	for name, tc := range map[string]struct {
		spec corev1.PodSpec
		want NodePlatform
	}{
		"no pins":                     {corev1.PodSpec{}, amd},
		"other labels only":           {corev1.PodSpec{NodeSelector: map[string]string{"pool": "general"}}, amd},
		"nodeSelector arm64":          {corev1.PodSpec{NodeSelector: map[string]string{corev1.LabelArchStable: "arm64"}}, arm},
		"nodeSelector majority":       {corev1.PodSpec{NodeSelector: map[string]string{corev1.LabelArchStable: "amd64"}}, amd},
		"affinity In allows majority": {corev1.PodSpec{Affinity: terms(arch(corev1.NodeSelectorOpIn, "arm64", "amd64"))}, amd},
		"affinity NotIn amd64, most Ready nodes": {corev1.PodSpec{Affinity: terms(arch(corev1.NodeSelectorOpNotIn, "amd64"))},
			NodePlatform{OS: "linux", Arch: "ppc64le"}},
		"affinity In arm64 and ppc64le": {corev1.PodSpec{Affinity: terms(arch(corev1.NodeSelectorOpIn, "arm64", "ppc64le"))},
			NodePlatform{OS: "linux", Arch: "ppc64le"}},
		"pinned where no node is": {corev1.PodSpec{NodeSelector: map[string]string{corev1.LabelArchStable: "s390x"}},
			NodePlatform{OS: "linux", Arch: "s390x"}},
		"windows": {corev1.PodSpec{NodeSelector: map[string]string{corev1.LabelOSStable: "windows"}},
			NodePlatform{OS: "windows", Arch: "amd64"}},
		"affinity term with other labels only": {corev1.PodSpec{Affinity: terms(corev1.NodeSelectorRequirement{Key: "zone",
			Operator: corev1.NodeSelectorOpIn, Values: []string{"a"}})}, amd},
	} {
		require.Equal(t, tc.want, templatePlatform(&tc.spec, nodes, amd), name)
	}
}

// TestSyncAll_TemplatePlatformPins (F84): a workload scaled to zero whose template pins arm64 is
// resolved at the arm64 manifest on a cluster whose majority is amd64; through the cache transform,
// the pins are kept.
func TestSyncAll_TemplatePlatformPins(t *testing.T) {
	pinned := newDeployment("arm", 0, "nginx:1.27")
	pinned.Spec.Template.Spec.NodeSelector = map[string]string{corev1.LabelArchStable: "arm64", "pool": "general"}
	out, err := transformWorkload(pinned)
	require.NoError(t, err)
	pinned = out.(*appsv1.Deployment)
	require.Equal(t, map[string]string{corev1.LabelArchStable: "arm64"}, pinned.Spec.Template.Spec.NodeSelector)

	h := newHarness(t, newNode("n1", "amd64"), newNode("n2", "amd64"), newNode("n3", "arm64"), pinned,
		newDeployment("free", 0, "nginx:1.27"))
	h.res.tags[nginx+":1.27"] = idx
	h.res.platforms[idx+"|linux/amd64"] = registryManifest(mA, idx, "linux/amd64")
	h.res.platforms[idx+"|linux/arm64"] = registryManifest(mB, idx, "linux/arm64")
	require.NoError(t, h.inv.SyncAll(ctx))

	arm := h.owner(t, "Deployment/apps/arm")
	require.Equal(t, []string{"arm64"}, arm.Arch)
	require.Equal(t, []string{mB}, digestsOf(arm.Containers))
	free := h.owner(t, "Deployment/apps/free")
	require.Equal(t, []string{"amd64"}, free.Arch)
	require.Equal(t, []string{mA}, digestsOf(free.Containers))
}

// TestPruneHandedOff_DepartedDigests (F54): digests handed to the acquirer are forgotten once no owner
// uses them, and handed off again if an owner uses them later. A prune while a flush runs skips
// rather than wait for it.
func TestPruneHandedOff_DepartedDigests(t *testing.T) {
	web, api := newPod("web", "n1", nil, "nginx:1.27", nginx+"@"+mA), newPod("api", "n1", nil, "nginx:1.27", nginx+"@"+mB)
	h := newHarness(t, newNode("n1", "amd64"), web, api)
	h.res.platforms[mA+"|linux/amd64"] = registryManifest(mA, "", "linux/amd64")
	h.res.platforms[mB+"|linux/amd64"] = registryManifest(mB, "", "linux/amd64")
	require.NoError(t, h.inv.SyncAll(ctx))
	require.ElementsMatch(t, []string{mA, mB}, h.acq.digests())
	handedOff := func() []string {
		h.inv.flushMu.Lock()
		defer h.inv.flushMu.Unlock()
		return sortedKeys(h.inv.enqueued)
	}
	require.Equal(t, []string{mA, mB}, handedOff())

	require.NoError(t, h.c.Delete(ctx, web.DeepCopy()))
	require.NoError(t, h.inv.Flush(ctx, []string{"Pod/apps/web"}))
	require.Equal(t, []string{mA, mB}, handedOff(), "kept until a prune")
	h.inv.flushMu.Lock() // a flush is running
	require.NoError(t, h.inv.pruneHandedOff(ctx), "returns at once")
	h.inv.flushMu.Unlock()
	require.Equal(t, []string{mA, mB}, handedOff(), "skipped while the flush ran")
	require.NoError(t, h.inv.pruneHandedOff(ctx))
	require.Equal(t, []string{mB}, handedOff())

	again := newPod("web", "n1", nil, "nginx:1.27", nginx+"@"+mA)
	require.NoError(t, h.c.Create(ctx, again))
	require.NoError(t, h.inv.Flush(ctx, []string{"Pod/apps/web"}))
	require.Len(t, h.acq.reqs, 3, "handed off again")
	require.Equal(t, mA, h.acq.digests()[2])
	require.Equal(t, []string{mA, mB}, handedOff())
}

// TestCommonestPlatform (W55): majorityPlatform and templatePlatform count Ready nodes the same way, and
// ties prefer linux/amd64, then the lowest key.
func TestCommonestPlatform(t *testing.T) {
	amd, arm := NodePlatform{OS: "linux", Arch: "amd64"}, NodePlatform{OS: "linux", Arch: "arm64"}
	node := func(arch string, ready bool) model.Node { return model.Node{OS: "linux", Arch: arch, Ready: ready} }
	all := func(NodePlatform) bool { return true }
	for name, tc := range map[string]struct {
		nodes []model.Node
		want  NodePlatform
		ok    bool
	}{
		"no nodes":                       {nil, NodePlatform{}, false},
		"none ready":                     {[]model.Node{node("arm64", false)}, NodePlatform{}, false},
		"the most":                       {[]model.Node{node("arm64", true), node("arm64", true), node("amd64", true)}, arm, true},
		"a tie prefers amd64":            {[]model.Node{node("386", true), node("amd64", true)}, amd, true},
		"other ties take the lowest key": {[]model.Node{node("s390x", true), node("arm64", true)}, arm, true},
	} {
		got, ok := commonestPlatform(tc.nodes, all)
		require.Equal(t, tc.ok, ok, name)
		require.Equal(t, tc.want, got, name)
	}
	require.Equal(t, amd, majorityPlatform(nil), "a cluster with no Ready nodes")
	got, ok := commonestPlatform([]model.Node{node("arm64", true), node("amd64", true), node("amd64", true)},
		func(np NodePlatform) bool { return np != amd })
	require.True(t, ok)
	require.Equal(t, arm, got, "only the platforms allow accepts are counted")
}
