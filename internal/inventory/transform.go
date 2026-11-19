package inventory

import (
	"maps"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const lastApplied = "kubectl.kubernetes.io/last-applied-configuration"

// CacheOptions returns the manager cache options: per-kind transforms that keep only the fields
// inventory and exposure read, and managed-field stripping for every other kind.
func CacheOptions() cache.Options {
	return cache.Options{
		DefaultTransform: cache.TransformStripManagedFields(),
		ByObject: map[client.Object]cache.ByObject{
			&corev1.Pod{}:         {Transform: transformPod},
			&corev1.Node{}:        {Transform: transformNode},
			&appsv1.Deployment{}:  {Transform: transformWorkload},
			&appsv1.StatefulSet{}: {Transform: transformWorkload},
			&appsv1.DaemonSet{}:   {Transform: transformWorkload},
			&batchv1.Job{}:        {Transform: transformWorkload},
			&batchv1.CronJob{}:    {Transform: transformWorkload},
		},
	}
}

// trimMeta drops managed fields and the kubectl last-applied annotation.
func trimMeta(m metav1.ObjectMeta) metav1.ObjectMeta {
	m.ManagedFields = nil
	if _, ok := m.Annotations[lastApplied]; ok {
		m.Annotations = maps.Clone(m.Annotations)
		delete(m.Annotations, lastApplied)
	}
	return m
}

func transformPod(in any) (any, error) {
	p, ok := in.(*corev1.Pod)
	if !ok {
		return in, nil
	}
	return &corev1.Pod{
		TypeMeta:   p.TypeMeta,
		ObjectMeta: trimMeta(p.ObjectMeta),
		Spec:       trimPodSpec(p.Spec),
		Status: corev1.PodStatus{
			Phase:                      p.Status.Phase,
			ContainerStatuses:          trimStatuses(p.Status.ContainerStatuses),
			InitContainerStatuses:      trimStatuses(p.Status.InitContainerStatuses),
			EphemeralContainerStatuses: trimStatuses(p.Status.EphemeralContainerStatuses),
		},
	}, nil
}

// trimPodSpec keeps what inventory (images, pull secrets, node) and exposure (host namespaces,
// security contexts, host ports, hostPath volumes) read.
func trimPodSpec(s corev1.PodSpec) corev1.PodSpec {
	out := corev1.PodSpec{
		ServiceAccountName: s.ServiceAccountName,
		ImagePullSecrets:   s.ImagePullSecrets,
		NodeName:           s.NodeName,
		HostNetwork:        s.HostNetwork,
		HostPID:            s.HostPID,
		HostIPC:            s.HostIPC,
		SecurityContext:    s.SecurityContext,
		RestartPolicy:      s.RestartPolicy,
		Containers:         trimContainers(s.Containers),
		InitContainers:     trimContainers(s.InitContainers),
	}
	for _, v := range s.Volumes {
		if v.HostPath != nil || v.Image != nil {
			out.Volumes = append(out.Volumes, corev1.Volume{Name: v.Name,
				VolumeSource: corev1.VolumeSource{HostPath: v.HostPath, Image: v.Image}})
		}
	}
	for _, c := range s.EphemeralContainers {
		out.EphemeralContainers = append(out.EphemeralContainers, corev1.EphemeralContainer{
			EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: c.Name, Image: c.Image, Ports: c.Ports,
				SecurityContext: c.SecurityContext},
			TargetContainerName: c.TargetContainerName,
		})
	}
	return out
}

func trimContainers(cs []corev1.Container) []corev1.Container {
	if cs == nil {
		return nil
	}
	out := make([]corev1.Container, len(cs))
	for i, c := range cs {
		out[i] = corev1.Container{Name: c.Name, Image: c.Image, Ports: c.Ports, SecurityContext: c.SecurityContext,
			RestartPolicy: c.RestartPolicy}
	}
	return out
}

func trimStatuses(ss []corev1.ContainerStatus) []corev1.ContainerStatus {
	if ss == nil {
		return nil
	}
	out := make([]corev1.ContainerStatus, len(ss))
	for i, s := range ss {
		out[i] = corev1.ContainerStatus{Name: s.Name, Image: s.Image, ImageID: s.ImageID, Ready: s.Ready,
			RestartCount: s.RestartCount, Started: s.Started}
		for _, m := range s.VolumeMounts {
			if m.VolumeStatus != nil {
				out[i].VolumeMounts = append(out[i].VolumeMounts,
					corev1.VolumeMountStatus{Name: m.Name, MountPath: m.MountPath, VolumeStatus: m.VolumeStatus})
			}
		}
	}
	return out
}

func trimTemplate(t corev1.PodTemplateSpec) corev1.PodTemplateSpec {
	m := trimMeta(t.ObjectMeta)
	return corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{Labels: m.Labels, Annotations: m.Annotations},
		Spec:       trimPodSpec(t.Spec),
	}
}

// transformWorkload keeps metadata, the trimmed pod template, the scale and suspend fields, and
// status replicas, desiredNumberScheduled and active.
func transformWorkload(in any) (any, error) {
	switch w := in.(type) {
	case *appsv1.Deployment:
		return &appsv1.Deployment{TypeMeta: w.TypeMeta, ObjectMeta: trimMeta(w.ObjectMeta),
			Spec:   appsv1.DeploymentSpec{Replicas: w.Spec.Replicas, Template: trimTemplate(w.Spec.Template)},
			Status: appsv1.DeploymentStatus{Replicas: w.Status.Replicas}}, nil
	case *appsv1.StatefulSet:
		return &appsv1.StatefulSet{TypeMeta: w.TypeMeta, ObjectMeta: trimMeta(w.ObjectMeta),
			Spec:   appsv1.StatefulSetSpec{Replicas: w.Spec.Replicas, Template: trimTemplate(w.Spec.Template)},
			Status: appsv1.StatefulSetStatus{Replicas: w.Status.Replicas}}, nil
	case *appsv1.DaemonSet:
		return &appsv1.DaemonSet{TypeMeta: w.TypeMeta, ObjectMeta: trimMeta(w.ObjectMeta),
			Spec:   appsv1.DaemonSetSpec{Template: trimTemplate(w.Spec.Template)},
			Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: w.Status.DesiredNumberScheduled}}, nil
	case *batchv1.Job:
		return &batchv1.Job{TypeMeta: w.TypeMeta, ObjectMeta: trimMeta(w.ObjectMeta),
			Spec:   batchv1.JobSpec{Suspend: w.Spec.Suspend, Template: trimTemplate(w.Spec.Template)},
			Status: batchv1.JobStatus{Active: w.Status.Active}}, nil
	case *batchv1.CronJob:
		return &batchv1.CronJob{TypeMeta: w.TypeMeta, ObjectMeta: trimMeta(w.ObjectMeta),
			Spec: batchv1.CronJobSpec{Suspend: w.Spec.Suspend, JobTemplate: batchv1.JobTemplateSpec{
				Spec: batchv1.JobSpec{Template: trimTemplate(w.Spec.JobTemplate.Spec.Template)}}},
			Status: batchv1.CronJobStatus{Active: w.Status.Active}}, nil
	}
	return in, nil
}

// transformNode keeps name, labels, status.nodeInfo and the Ready condition's status.
func transformNode(in any) (any, error) {
	n, ok := in.(*corev1.Node)
	if !ok {
		return in, nil
	}
	out := &corev1.Node{
		TypeMeta: n.TypeMeta,
		ObjectMeta: metav1.ObjectMeta{Name: n.Name, UID: n.UID, ResourceVersion: n.ResourceVersion,
			Labels: n.Labels},
		Status: corev1.NodeStatus{NodeInfo: n.Status.NodeInfo},
	}
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady {
			out.Status.Conditions = []corev1.NodeCondition{{Type: c.Type, Status: c.Status}}
		}
	}
	return out, nil
}
