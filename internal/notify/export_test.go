package notify

import (
	"context"
	"net/netip"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"

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

// NamespaceGone exposes the deleted-namespace check the reconciler builds for at.
func (r *TargetReconciler) NamespaceGone(at *ffsv1alpha1.AlertTarget) func(string) bool {
	return r.namespaceGone(at)
}

// BlockedRanges exposes the guard's extra ranges: the configured ones and the nodes' pod CIDRs.
func BlockedRanges(c client.Reader, configured []netip.Prefix, log logr.Logger) func(context.Context) []netip.Prefix {
	return blockedRanges(c, configured, log)
}

// EncodePayload exposes the stored-payload encoder.
func EncodePayload(m Message) ([]byte, error) { return encodePayload(m) }
