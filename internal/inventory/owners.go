package inventory

import (
	"context"
	"errors"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/the-it-dept/ffs/internal/model"
)

// errOwnerPending means an intermediate owner (ReplicaSet, Job) is not in the cache yet; the pod
// key is retried in the next batch.
var errOwnerPending = errors.New("inventory: owner not in the cache yet")

// ownerOf follows the pod's controller reference to the top owner: ReplicaSet → its controller
// (Deployment), Job → its controller (CronJob). Pods with no controller, and static pods
// controlled by a Node, are their own owner.
func ownerOf(ctx context.Context, c client.Reader, pod *corev1.Pod) (model.OwnerRef, error) {
	ref := metav1.GetControllerOfNoCopy(pod)
	if ref == nil || ref.Kind == "Node" {
		return model.OwnerRef{Kind: "Pod", Namespace: pod.Namespace, Name: pod.Name, UID: string(pod.UID)}, nil
	}
	owner := model.OwnerRef{Kind: ref.Kind, Namespace: pod.Namespace, Name: ref.Name, UID: string(ref.UID)}
	gv, _ := schema.ParseGroupVersion(ref.APIVersion)
	switch {
	case gv.Group == appsv1.GroupName && ref.Kind == "ReplicaSet":
		rs := &metav1.PartialObjectMetadata{}
		rs.SetGroupVersionKind(appsv1.SchemeGroupVersion.WithKind("ReplicaSet"))
		return controllerOf(ctx, c, rs, owner)
	case gv.Group == batchv1.GroupName && ref.Kind == "Job":
		return controllerOf(ctx, c, &batchv1.Job{}, owner)
	}
	return owner, nil
}

// controllerOf reads the intermediate owner into obj and returns its controller, or the
// intermediate owner itself when it has none.
func controllerOf(ctx context.Context, c client.Reader, obj client.Object, owner model.OwnerRef) (model.OwnerRef, error) {
	if err := c.Get(ctx, client.ObjectKey{Namespace: owner.Namespace, Name: owner.Name}, obj); err != nil {
		if apierrors.IsNotFound(err) {
			return model.OwnerRef{}, errOwnerPending
		}
		return model.OwnerRef{}, err
	}
	if p := metav1.GetControllerOfNoCopy(obj); p != nil {
		return model.OwnerRef{Kind: p.Kind, Namespace: owner.Namespace, Name: p.Name, UID: string(p.UID)}, nil
	}
	return owner, nil
}

// ManagedByFrom reads the deployment tool from in-cluster metadata. Precedence: Flux HelmRelease
// labels, Helm release annotations, Flux Kustomization labels, then the Argo CD tracking id.
func ManagedByFrom(labels, annotations map[string]string) *model.ManagedBy {
	if n := labels["helm.toolkit.fluxcd.io/name"]; n != "" {
		return &model.ManagedBy{Tool: "flux-helmrelease", Name: n, Namespace: labels["helm.toolkit.fluxcd.io/namespace"]}
	}
	if n := annotations["meta.helm.sh/release-name"]; n != "" {
		return &model.ManagedBy{Tool: "helm", Name: n, Namespace: annotations["meta.helm.sh/release-namespace"]}
	}
	if n := labels["kustomize.toolkit.fluxcd.io/name"]; n != "" {
		return &model.ManagedBy{Tool: "flux-kustomization", Name: n, Namespace: labels["kustomize.toolkit.fluxcd.io/namespace"]}
	}
	// "<app>:<group>/<kind>:<namespace>/<name>", where <app> is "<namespace>_<name>" for apps outside
	// the Argo CD namespace.
	if app, _, _ := strings.Cut(annotations["argocd.argoproj.io/tracking-id"], ":"); app != "" {
		if ns, name, ok := strings.Cut(app, "_"); ok {
			return &model.ManagedBy{Tool: "argocd", Name: name, Namespace: ns}
		}
		return &model.ManagedBy{Tool: "argocd", Name: app}
	}
	return nil
}

// workloadOwner returns the owner key a workload event affects: a Job or ReplicaSet with a
// controller maps to that controller (CronJob, Deployment), anything else to itself.
func (inv *Inventory) workloadOwner(ctx context.Context, kind, ns, name string) (string, error) {
	var obj client.Object
	switch kind {
	case "Job":
		obj = &batchv1.Job{}
	case "ReplicaSet":
		rs := &metav1.PartialObjectMetadata{}
		rs.SetGroupVersionKind(appsv1.SchemeGroupVersion.WithKind("ReplicaSet"))
		obj = rs
	default:
		return ownerKey(kind, ns, name), nil
	}
	found, err := inv.get(ctx, ns, name, obj)
	if err != nil {
		return "", err
	}
	if p := metav1.GetControllerOfNoCopy(obj); found && p != nil {
		return ownerKey(p.Kind, ns, p.Name), nil
	}
	return ownerKey(kind, ns, name), nil
}

// workload is an owner's workload object as the inventory reads it.
type workload struct {
	meta metav1.Object
	tmpl *corev1.PodTemplateSpec
	idle bool // scaled to zero, a CronJob, a suspended Job, or a DaemonSet scheduled nowhere
}

func (inv *Inventory) getWorkload(ctx context.Context, kind, ns, name string) (*workload, error) {
	var (
		obj  client.Object
		read func() workload
	)
	switch kind {
	case "Deployment":
		d := &appsv1.Deployment{}
		obj, read = d, func() workload { return workload{d, &d.Spec.Template, ptr.Deref(d.Spec.Replicas, 1) == 0} }
	case "StatefulSet":
		s := &appsv1.StatefulSet{}
		obj, read = s, func() workload { return workload{s, &s.Spec.Template, ptr.Deref(s.Spec.Replicas, 1) == 0} }
	case "DaemonSet":
		d := &appsv1.DaemonSet{}
		obj, read = d, func() workload { return workload{d, &d.Spec.Template, d.Status.DesiredNumberScheduled == 0} }
	case "Job":
		j := &batchv1.Job{}
		obj, read = j, func() workload { return workload{j, &j.Spec.Template, ptr.Deref(j.Spec.Suspend, false)} }
	case "CronJob":
		c := &batchv1.CronJob{}
		obj, read = c, func() workload { return workload{c, &c.Spec.JobTemplate.Spec.Template, true} }
	default:
		return nil, nil
	}
	found, err := inv.get(ctx, ns, name, obj)
	if err != nil || !found {
		return nil, err
	}
	w := read()
	return &w, nil
}

func ownerServiceAccount(pods []*corev1.Pod, tmpl *corev1.PodTemplateSpec) string {
	for _, p := range pods {
		if p.Spec.ServiceAccountName != "" {
			return p.Spec.ServiceAccountName
		}
	}
	if tmpl != nil {
		return serviceAccount(&tmpl.Spec)
	}
	return "default"
}

// ownerPullSecrets is the sorted union of the pods' and the template's imagePullSecrets names.
func ownerPullSecrets(pods []*corev1.Pod, tmpl *corev1.PodTemplateSpec) []string {
	names := map[string]bool{}
	for _, p := range pods {
		for _, n := range pullSecretNames(&p.Spec) {
			names[n] = true
		}
	}
	if tmpl != nil {
		for _, n := range pullSecretNames(&tmpl.Spec) {
			names[n] = true
		}
	}
	return sortedKeys(names)
}
