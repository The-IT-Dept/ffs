package inventory

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

func TestTransformPod_KeepsNeededFields(t *testing.T) {
	podSC := &corev1.PodSecurityContext{RunAsNonRoot: ptr.To(true)}
	containerSC := &corev1.SecurityContext{Privileged: ptr.To(true)}
	hostPath := &corev1.HostPathVolumeSource{Path: "/var/run/docker.sock"}
	imageVol := &corev1.ImageVolumeSource{Reference: "ghcr.io/acme/models:v3"}
	volStatus := &corev1.VolumeStatus{Image: &corev1.ImageVolumeStatus{ImageRef: "ghcr.io/acme/models@" + mB}}
	owners := ctrl("apps/v1", "ReplicaSet", "web-5d9")
	in := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "apps", Name: "web-x", Labels: map[string]string{"app": "web"},
			Annotations:     map[string]string{lastApplied: `{"big":"json"}`, "meta.helm.sh/release-name": "web"},
			ManagedFields:   []metav1.ManagedFieldsEntry{{Manager: "kubectl"}},
			OwnerReferences: owners,
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: "web",
			ImagePullSecrets:   []corev1.LocalObjectReference{{Name: "regcred"}},
			NodeName:           "n1",
			HostPID:            true,
			SecurityContext:    podSC,
			RestartPolicy:      corev1.RestartPolicyAlways,
			Volumes: []corev1.Volume{
				{Name: "sock", VolumeSource: corev1.VolumeSource{HostPath: hostPath}},
				{Name: "models", VolumeSource: corev1.VolumeSource{Image: imageVol}},
				{Name: "cfg", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{Name: "cfg"}}}},
			},
			Containers: []corev1.Container{{
				Name: "app", Image: "nginx:1.27",
				Env:     []corev1.EnvVar{{Name: "SECRET", Value: "x"}},
				Command: []string{"nginx"},
				Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{
					corev1.ResourceCPU: resource.MustParse("1")}},
				LivenessProbe:   &corev1.Probe{InitialDelaySeconds: 5},
				Ports:           []corev1.ContainerPort{{ContainerPort: 80, HostPort: 8080, Protocol: corev1.ProtocolTCP}},
				SecurityContext: containerSC,
				VolumeMounts:    []corev1.VolumeMount{{Name: "models", MountPath: "/models"}},
			}},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
			ContainerStatuses: []corev1.ContainerStatus{{
				Name: "app", Image: "docker.io/library/nginx:1.27", ImageID: "docker.io/library/nginx@" + idx,
				VolumeMounts: []corev1.VolumeMountStatus{{Name: "models", MountPath: "/models", VolumeStatus: volStatus}},
			}},
		},
	}

	out, err := transformPod(in)
	require.NoError(t, err)
	p := out.(*corev1.Pod)
	require.Nil(t, p.ManagedFields)
	require.NotContains(t, p.Annotations, lastApplied)
	require.Equal(t, "web", p.Annotations["meta.helm.sh/release-name"])
	require.Equal(t, map[string]string{"app": "web"}, p.Labels)
	require.Equal(t, owners, p.OwnerReferences)
	require.Equal(t, "web", p.Spec.ServiceAccountName)
	require.Equal(t, []corev1.LocalObjectReference{{Name: "regcred"}}, p.Spec.ImagePullSecrets)
	require.Equal(t, "n1", p.Spec.NodeName)
	require.True(t, p.Spec.HostPID)
	require.Equal(t, podSC, p.Spec.SecurityContext)
	require.Equal(t, corev1.RestartPolicyAlways, p.Spec.RestartPolicy)
	require.Equal(t, []corev1.Volume{
		{Name: "sock", VolumeSource: corev1.VolumeSource{HostPath: hostPath}},
		{Name: "models", VolumeSource: corev1.VolumeSource{Image: imageVol}},
	}, p.Spec.Volumes)

	c := p.Spec.Containers[0]
	require.Equal(t, "app", c.Name)
	require.Equal(t, "nginx:1.27", c.Image)
	require.Nil(t, c.Env)
	require.Nil(t, c.Command)
	require.Zero(t, c.Resources)
	require.Nil(t, c.LivenessProbe)
	require.Nil(t, c.VolumeMounts)
	require.Equal(t, int32(8080), c.Ports[0].HostPort)
	require.Equal(t, containerSC, c.SecurityContext)

	st := p.Status.ContainerStatuses[0]
	require.Equal(t, "docker.io/library/nginx@"+idx, st.ImageID)
	require.Equal(t, volStatus, st.VolumeMounts[0].VolumeStatus)
	require.Equal(t, corev1.PodRunning, p.Status.Phase)

	t.Run("workload", func(t *testing.T) {
		d := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "web", Annotations: map[string]string{lastApplied: "{}"},
				ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "helm"}}},
			Spec: appsv1.DeploymentSpec{Replicas: ptr.To[int32](0), Selector: &metav1.LabelSelector{},
				Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "web"}}, Spec: in.Spec}},
			Status: appsv1.DeploymentStatus{Replicas: 2, ReadyReplicas: 2},
		}
		out, err := transformWorkload(d)
		require.NoError(t, err)
		got := out.(*appsv1.Deployment)
		require.Nil(t, got.ManagedFields)
		require.NotContains(t, got.Annotations, lastApplied)
		require.Equal(t, ptr.To[int32](0), got.Spec.Replicas)
		require.Nil(t, got.Spec.Selector)
		require.Equal(t, map[string]string{"app": "web"}, got.Spec.Template.Labels)
		require.Nil(t, got.Spec.Template.Spec.Containers[0].Env)
		require.Len(t, got.Spec.Template.Spec.Volumes, 2)
		require.Equal(t, appsv1.DeploymentStatus{Replicas: 2}, got.Status)

		cj := &batchv1.CronJob{Spec: batchv1.CronJobSpec{Schedule: "@daily", JobTemplate: batchv1.JobTemplateSpec{
			Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: in.Spec}}}}}
		out, err = transformWorkload(cj)
		require.NoError(t, err)
		require.Equal(t, "nginx:1.27", out.(*batchv1.CronJob).Spec.JobTemplate.Spec.Template.Spec.Containers[0].Image)
	})

	t.Run("node", func(t *testing.T) {
		n := &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "n1", Annotations: map[string]string{"flannel": "x"},
				ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "kubelet"}}},
			Status: corev1.NodeStatus{
				NodeInfo: corev1.NodeSystemInfo{Architecture: "arm64", KubeletVersion: "v1.35.2+k3s1"},
				Images: []corev1.ContainerImage{{Names: []string{"docker.io/library/nginx@sha256:" + strings.Repeat("e", 64),
					"docker.io/library/nginx:1.27"}, SizeBytes: 1234}},
				Conditions: []corev1.NodeCondition{{Type: corev1.NodeMemoryPressure, Status: corev1.ConditionFalse},
					{Type: corev1.NodeReady, Status: corev1.ConditionTrue, Message: "kubelet is posting ready status"}},
			},
		}
		out, err := transformNode(n)
		require.NoError(t, err)
		got := out.(*corev1.Node)
		require.Nil(t, got.ManagedFields)
		require.Equal(t, n.Status.Images, got.Status.Images)
		require.Equal(t, n.Status.NodeInfo, got.Status.NodeInfo)
		require.Equal(t, []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}}, got.Status.Conditions)
	})
}
