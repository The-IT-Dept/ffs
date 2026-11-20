package inventory

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/registry"
)

func cronJob(ns, name, image string) *batchv1.CronJob {
	return &batchv1.CronJob{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: batchv1.CronJobSpec{Schedule: "@daily", JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{Spec: podSpec(image)}}}}}
}

// TestResolveRef_UnresolvedTagBacksOff (F53): a tag that never resolves is not looked up on every
// flush of its owner: the miss holds an hour, then two, four, and at most six, per credentials. Other
// credentials are looked up at once, and once the tag resolves it is used.
func TestResolveRef_UnresolvedTagBacksOff(t *testing.T) {
	h := newHarness(t, newNode("n1", "amd64"), cronJob("apps", "nightly", "nginx:9.9"))
	const key = "CronJob/apps/nightly"
	require.NoError(t, h.inv.SyncAll(ctx))
	require.Equal(t, 1, h.res.resolveTagCalls)
	placeholder := "unknown:" + nginx + ":9.9"
	require.Equal(t, []string{placeholder}, digestsOf(h.owner(t, key).Containers))
	img, ok, err := h.st.GetImage(ctx, placeholder)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, model.ImageUnresolvable, img.Status)
	require.Equal(t, fmt.Sprintf(registry.ReasonNotFound, nginx+":9.9"), img.StatusReason)

	flushAt := func(d time.Duration) int {
		t.Helper()
		h.now = t0.Add(d)
		require.NoError(t, h.inv.Flush(ctx, []string{key}))
		return h.res.resolveTagCalls
	}
	for _, step := range []struct {
		at    time.Duration
		calls int
	}{
		{time.Minute, 1}, {time.Hour - time.Second, 1}, // the first miss holds an hour
		{time.Hour, 2}, {3*time.Hour - time.Second, 2}, // then two
		{3 * time.Hour, 3}, {7*time.Hour - time.Second, 3}, // then four
		{7 * time.Hour, 4}, {13*time.Hour - time.Second, 4}, // then six, at most
		{13 * time.Hour, 5}, {19*time.Hour - time.Second, 5},
	} {
		require.Equal(t, step.calls, flushAt(step.at), "flush at %s", step.at)
	}
	require.Equal(t, []string{placeholder}, digestsOf(h.owner(t, key).Containers))

	// Another namespace's credentials are not covered by the miss.
	require.NoError(t, h.c.Create(ctx, cronJob("team-b", "nightly", "nginx:9.9")))
	require.NoError(t, h.inv.Flush(ctx, []string{"CronJob/team-b/nightly"}))
	require.Equal(t, 6, h.res.resolveTagCalls)

	// The tag is pushed: the next lookup, when the miss ends, resolves it.
	h.res.tags[nginx+":9.9"] = idx
	h.res.platforms[idx+"|linux/amd64"] = registryManifest(mA, idx, "linux/amd64")
	require.Equal(t, 7, flushAt(19*time.Hour))
	require.Equal(t, []string{mA}, digestsOf(h.owner(t, key).Containers))
	require.Equal(t, 7, flushAt(20*time.Hour), "a resolved tag uses its record")
}

// TestRefreshTemplates_TagsAtMostTagTTLOld (F53): the TagTTL refresh looks every tag of the owners that
// are not running up again, however young its record, so a tag recorded just after one refresh is
// replaced at the next rather than surviving until the one after (up to twice TagTTL).
func TestRefreshTemplates_TagsAtMostTagTTLOld(t *testing.T) {
	h := newHarness(t, newNode("n1", "amd64"), newDeployment("idle", 0, "nginx:1.27"))
	const key = "Deployment/apps/idle"
	h.res.tags[nginx+":1.27"] = idx
	h.res.platforms[idx+"|linux/amd64"] = registryManifest(mA, idx, "linux/amd64")
	h.now = t0.Add(time.Minute) // just after a refresh at t0
	require.NoError(t, h.inv.SyncAll(ctx))
	require.Equal(t, 1, h.res.resolveTagCalls)

	// The tag moves. The next refresh, one TagTTL after the last, finds a record younger than TagTTL
	// and looks the tag up anyway.
	idx2 := "sha256:" + "2222222222222222222222222222222222222222222222222222222222222222"
	h.res.tags[nginx+":1.27"] = idx2
	h.res.platforms[idx2+"|linux/amd64"] = registryManifest(mB, idx2, "linux/amd64")
	h.now = t0.Add(6 * time.Hour)
	require.NoError(t, h.inv.refreshTemplates(ctx))
	require.Equal(t, 2, h.res.resolveTagCalls)
	require.Equal(t, []string{mB}, digestsOf(h.owner(t, key).Containers))

	// Other flushes between refreshes use the record.
	h.now = t0.Add(7 * time.Hour)
	require.NoError(t, h.inv.Flush(ctx, []string{key}))
	require.Equal(t, 2, h.res.resolveTagCalls)
	require.False(t, h.inv.forceTags)
}
