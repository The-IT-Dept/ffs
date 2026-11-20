package inventory

import (
	"maps"
	"slices"

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

// trimStatuses keeps what inventory and the node agent's pod index read of each container status:
// its name, image and image ID, and the image refs of its image volume mounts. Phase, readiness and
// restarts are not read: a pod counts as running once a container reports an image ID.
func trimStatuses(ss []corev1.ContainerStatus) []corev1.ContainerStatus {
	if ss == nil {
		return nil
	}
	out := make([]corev1.ContainerStatus, len(ss))
	for i, s := range ss {
		out[i] = corev1.ContainerStatus{Name: s.Name, Image: s.Image, ImageID: s.ImageID}
		for _, m := range s.VolumeMounts {
			if m.VolumeStatus != nil {
				out[i].VolumeMounts = append(out[i].VolumeMounts,
					corev1.VolumeMountStatus{Name: m.Name, MountPath: m.MountPath, VolumeStatus: m.VolumeStatus})
			}
		}
	}
	return out
}

// trimTemplate keeps a template's labels and annotations, its trimmed pod spec, and the scheduling
// constraints on the node platform (see trimPlatformPins), which pick the platform a workload that is
// not running is resolved at.
func trimTemplate(t corev1.PodTemplateSpec) corev1.PodTemplateSpec {
	m := trimMeta(t.ObjectMeta)
	spec := trimPodSpec(t.Spec)
	spec.NodeSelector, spec.Affinity = trimPlatformPins(t.Spec)
	return corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{Labels: m.Labels, Annotations: m.Annotations},
		Spec:       spec,
	}
}

// platformLabels are the node labels a pod spec can pin its platform with.
var platformLabels = []string{corev1.LabelArchStable, corev1.LabelOSStable}

// trimPlatformPins returns the part of s's nodeSelector, and of its required node affinity, on the
// kubernetes.io/arch and kubernetes.io/os labels; nil for each when there is none. Affinity terms keep
// their place, emptied of other expressions, so a term that does not constrain the platform still
// lets it be anything.
func trimPlatformPins(s corev1.PodSpec) (map[string]string, *corev1.Affinity) {
	var sel map[string]string
	for _, k := range platformLabels {
		if v, ok := s.NodeSelector[k]; ok {
			if sel == nil {
				sel = map[string]string{}
			}
			sel[k] = v
		}
	}
	if s.Affinity == nil || s.Affinity.NodeAffinity == nil || s.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution == nil {
		return sel, nil
	}
	pinned := false
	terms := s.Affinity.NodeAffinity.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms
	out := make([]corev1.NodeSelectorTerm, len(terms))
	for i, term := range terms {
		for _, e := range term.MatchExpressions {
			if slices.Contains(platformLabels, e.Key) {
				out[i].MatchExpressions = append(out[i].MatchExpressions,
					corev1.NodeSelectorRequirement{Key: e.Key, Operator: e.Operator, Values: slices.Clone(e.Values)})
				pinned = true
			}
		}
	}
	if !pinned {
		return sel, nil
	}
	return sel, &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{
		RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{NodeSelectorTerms: out}}}
}

// transformWorkload keeps metadata, the trimmed pod template, the scale and suspend fields, and
// status replicas, desiredNumberScheduled and active, and a Job's Complete and Failed conditions.
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
		var conds []batchv1.JobCondition
		for _, c := range w.Status.Conditions {
			if c.Type == batchv1.JobComplete || c.Type == batchv1.JobFailed {
				conds = append(conds, batchv1.JobCondition{Type: c.Type, Status: c.Status})
			}
		}
		return &batchv1.Job{TypeMeta: w.TypeMeta, ObjectMeta: trimMeta(w.ObjectMeta),
			Spec:   batchv1.JobSpec{Suspend: w.Spec.Suspend, Template: trimTemplate(w.Spec.Template)},
			Status: batchv1.JobStatus{Active: w.Status.Active, Conditions: conds}}, nil
	case *batchv1.CronJob:
		return &batchv1.CronJob{TypeMeta: w.TypeMeta, ObjectMeta: trimMeta(w.ObjectMeta),
			Spec: batchv1.CronJobSpec{Suspend: w.Spec.Suspend, JobTemplate: batchv1.JobTemplateSpec{
				Spec: batchv1.JobSpec{Template: trimTemplate(w.Spec.JobTemplate.Spec.Template)}}},
			Status: batchv1.CronJobStatus{Active: w.Status.Active}}, nil
	}
	return in, nil
}

// transformNode keeps name, labels, status.nodeInfo, the Ready condition's status and
// status.images (names and sizes), which the node agent's report merges with the cached images.
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
	if n.Status.Images != nil {
		out.Status.Images = make([]corev1.ContainerImage, len(n.Status.Images))
		for i, img := range n.Status.Images {
			out.Status.Images[i] = corev1.ContainerImage{Names: slices.Clone(img.Names), SizeBytes: img.SizeBytes}
		}
	}
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady {
			out.Status.Conditions = []corev1.NodeCondition{{Type: c.Type, Status: c.Status}}
		}
	}
	return out, nil
}
