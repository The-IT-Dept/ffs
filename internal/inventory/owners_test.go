package inventory

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/the-it-dept/ffs/internal/model"
)

func TestOwnerOf(t *testing.T) {
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web-5d9",
		OwnerReferences: ctrl("apps/v1", "Deployment", "web")}}
	job := &batchv1.Job{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "backup-29",
		OwnerReferences: ctrl("batch/v1", "CronJob", "backup")}}
	c := fake.NewClientBuilder().WithObjects(rs, job).Build()

	for _, tc := range []struct {
		name   string
		owners []metav1.OwnerReference
		want   model.OwnerRef
	}{
		{"deployment via replicaset", ctrl("apps/v1", "ReplicaSet", "web-5d9"),
			model.OwnerRef{Kind: "Deployment", Namespace: "apps", Name: "web", UID: "web-uid"}},
		{"cronjob via job", ctrl("batch/v1", "Job", "backup-29"),
			model.OwnerRef{Kind: "CronJob", Namespace: "apps", Name: "backup", UID: "backup-uid"}},
		{"statefulset", ctrl("apps/v1", "StatefulSet", "db"),
			model.OwnerRef{Kind: "StatefulSet", Namespace: "apps", Name: "db", UID: "db-uid"}},
		{"unknown kind", ctrl("argoproj.io/v1alpha1", "Rollout", "r"),
			model.OwnerRef{Kind: "Rollout", Namespace: "apps", Name: "r", UID: "r-uid"}},
		{"static pod", ctrl("v1", "Node", "n1"), model.OwnerRef{Kind: "Pod", Namespace: "apps", Name: "p", UID: "p-uid"}},
		{"no controller", []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "ReplicaSet", Name: "x", UID: "x-uid"}},
			model.OwnerRef{Kind: "Pod", Namespace: "apps", Name: "p", UID: "p-uid"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "p", UID: "p-uid", OwnerReferences: tc.owners}}
			got, err := ownerOf(ctx, c, pod)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}

	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "p",
		OwnerReferences: ctrl("apps/v1", "ReplicaSet", "web-6f1")}}
	_, err := ownerOf(ctx, c, pod)
	require.True(t, errors.Is(err, errOwnerPending), "got %v", err)
}

func TestManagedByFrom(t *testing.T) {
	helmAnn := map[string]string{"meta.helm.sh/release-name": "web", "meta.helm.sh/release-namespace": "apps"}
	for _, tc := range []struct {
		name                string
		labels, annotations map[string]string
		want                *model.ManagedBy
	}{
		{"flux helmrelease wins over helm",
			map[string]string{"helm.toolkit.fluxcd.io/name": "web", "helm.toolkit.fluxcd.io/namespace": "flux-system"}, helmAnn,
			&model.ManagedBy{Tool: "flux-helmrelease", Name: "web", Namespace: "flux-system"}},
		{"helm", nil, helmAnn, &model.ManagedBy{Tool: "helm", Name: "web", Namespace: "apps"}},
		{"flux kustomization",
			map[string]string{"kustomize.toolkit.fluxcd.io/name": "apps", "kustomize.toolkit.fluxcd.io/namespace": "flux-system"}, nil,
			&model.ManagedBy{Tool: "flux-kustomization", Name: "apps", Namespace: "flux-system"}},
		{"argocd", nil, map[string]string{"argocd.argoproj.io/tracking-id": "guestbook:apps/Deployment:default/guestbook"},
			&model.ManagedBy{Tool: "argocd", Name: "guestbook"}},
		{"argocd namespaced app", nil,
			map[string]string{"argocd.argoproj.io/tracking-id": "argocd_guestbook:apps/Deployment:default/guestbook"},
			&model.ManagedBy{Tool: "argocd", Name: "guestbook", Namespace: "argocd"}},
		{"nothing", map[string]string{"app": "web"}, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, ManagedByFrom(tc.labels, tc.annotations))
		})
	}
}

func TestContainerUses_AllKinds(t *testing.T) {
	const nginx = "docker.io/library/nginx"
	always := corev1.ContainerRestartPolicyAlways
	h := newHarness(t)
	h.res.platforms[idx+"|linux/amd64"] = registryManifest(mA, idx, "linux/amd64")
	h.res.platforms[mB+"|linux/amd64"] = registryManifest(mB, "", "linux/amd64")
	h.res.tags["ghcr.io/acme/models:v3"] = mB
	amd64 := NodePlatform{OS: "linux", Arch: "amd64"}

	id := nginx + "@" + idx
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "apps", Name: "web-x"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Image: "nginx:1.27"}, {Name: "late", Image: "busybox:1"}},
			InitContainers: []corev1.Container{
				{Name: "migrate", Image: "nginx:1.27", SecurityContext: &corev1.SecurityContext{RunAsUser: ptr.To[int64](1000)}},
				{Name: "proxy", Image: "nginx:1.27", RestartPolicy: &always,
					SecurityContext: &corev1.SecurityContext{RunAsUser: ptr.To[int64](0)}},
			},
			EphemeralContainers: []corev1.EphemeralContainer{{EphemeralContainerCommon: corev1.EphemeralContainerCommon{
				Name: "debug", Image: "nginx:1.27"}}},
			Volumes: []corev1.Volume{{Name: "models", VolumeSource: corev1.VolumeSource{
				Image: &corev1.ImageVolumeSource{Reference: "ghcr.io/acme/models:v3"}}}},
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "app", Image: "nginx:1.27", ImageID: id, VolumeMounts: []corev1.VolumeMountStatus{{Name: "models",
					MountPath: "/models", VolumeStatus: &corev1.VolumeStatus{Image: &corev1.ImageVolumeStatus{
						ImageRef: "ghcr.io/acme/models@" + mB}}}}},
				{Name: "late", Image: "busybox:1"},
			},
			InitContainerStatuses: []corev1.ContainerStatus{
				{Name: "migrate", Image: "nginx:1.27", ImageID: id},
				{Name: "proxy", Image: "nginx:1.27", ImageID: id},
			},
			EphemeralContainerStatuses: []corev1.ContainerStatus{{Name: "debug", Image: "nginx:1.27", ImageID: id}},
		},
	}

	type got struct {
		kind   model.ContainerKind
		digest string
		root   bool
	}
	summarise := func(us []use) map[string]got {
		out := map[string]got{}
		for _, u := range us {
			out[u.Name] = got{u.Kind, u.Digest, u.RootUnlessImageUser}
		}
		return out
	}

	uses, err := h.inv.containerUses(ctx, pod, amd64, nil)
	require.NoError(t, err)
	require.Equal(t, map[string]got{
		"app":     {model.ContainerRegular, mA, true},
		"migrate": {model.ContainerInit, mA, false},
		"proxy":   {model.ContainerSidecar, mA, false},
		"debug":   {model.ContainerEphemeral, mA, true},
		"models":  {model.ContainerImageVolume, mB, false},
	}, summarise(uses))
	require.Zero(t, h.res.resolveTagCalls)
	for _, u := range uses {
		require.Equal(t, "linux/amd64", u.Platform, u.Name)
		require.Equal(t, "apps", u.Creds.Namespace)
		require.Equal(t, "default", u.Creds.ServiceAccount)
	}

	noStatus := pod.DeepCopy()
	noStatus.Status.ContainerStatuses[0].VolumeMounts = nil
	uses, err = h.inv.containerUses(ctx, noStatus, amd64, nil)
	require.NoError(t, err)
	require.Equal(t, got{model.ContainerImageVolume, mB, false}, summarise(uses)["models"])
	require.Equal(t, 1, h.res.resolveTagCalls)
	d, _, ok, err := h.st.TagDigest(ctx, "ghcr.io/acme/models", "v3")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, mB, d)

	nonRoot := pod.DeepCopy()
	nonRoot.Spec.SecurityContext = &corev1.PodSecurityContext{RunAsNonRoot: ptr.To(true)}
	uses, err = h.inv.containerUses(ctx, nonRoot, amd64, nil)
	require.NoError(t, err)
	for _, u := range uses {
		require.False(t, u.RootUnlessImageUser, u.Name)
	}
}
