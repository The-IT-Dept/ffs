package controller

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestFindSelf_GetsDeployment(t *testing.T) {
	needEnv(t)
	ctx := context.Background()
	labels := map[string]string{"app.kubernetes.io/name": "ffs"}
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default", Name: "ffs"},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "controller", Image: "ghcr.io/the-it-dept/ffs:dev"}}},
			},
		},
	}
	require.NoError(t, env.Client.Create(ctx, dep))
	t.Cleanup(func() { _ = env.Client.Delete(context.Background(), dep) })

	ref, err := FindSelf(ctx, env.Client, "default", "ffs")
	require.NoError(t, err)
	require.Equal(t, &corev1.ObjectReference{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "default", Name: "ffs", UID: dep.UID}, ref)

	_, err = FindSelf(ctx, env.Client, "default", "missing")
	require.Error(t, err)
}
