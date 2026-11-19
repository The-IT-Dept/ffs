package notify

import ffsv1alpha1 "github.com/the-it-dept/ffs/api/v1alpha1"

// NamespaceMatch exposes the namespace matcher the reconciler builds for at.
func (r *TargetReconciler) NamespaceMatch(at *ffsv1alpha1.AlertTarget) func(string) bool {
	return r.namespaceMatch(at)
}
