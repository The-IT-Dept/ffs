package notify

import (
	"context"

	ffsv1alpha1 "github.com/the-it-dept/ffs/api/v1alpha1"
)

// NamespaceMatch exposes the namespace matcher the reconciler builds for at.
func (r *TargetReconciler) NamespaceMatch(at *ffsv1alpha1.AlertTarget) func(string) bool {
	return r.namespaceMatch(at)
}

// StartDrains exposes startDrains: it starts the drains of the sendable targets without waiting.
func (e *Engine) StartDrains(ctx context.Context) (func() error, error) { return e.startDrains(ctx) }

// StartupRetain exposes the startup cleanup the reconciler adds to the manager.
func (r *TargetReconciler) StartupRetain(ctx context.Context) error { return r.startupRetain(ctx) }
