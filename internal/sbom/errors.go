package sbom

import (
	"context"
	"errors"

	"github.com/the-it-dept/ffs/internal/registry"
)

// FailureKind says how a failed acquisition is treated.
type FailureKind int

const (
	// FailCounted is a crash, timeout or cataloguer error: it counts toward quarantine.
	FailCounted FailureKind = iota
	// FailTransient is a rate limit, a busy or unavailable cataloguer, or shutdown: requeue, not counted.
	FailTransient
	// FailUnresolvable is a credentials or not-found failure: the image is unresolvable, with Reason.
	FailUnresolvable
	// FailQuarantine is a deterministic refusal (such as too large): the image is catalogFailed immediately.
	FailQuarantine
)

// AcquireError is a classified acquisition failure.
type AcquireError struct {
	Kind   FailureKind
	Reason string
	Err    error
}

func (e *AcquireError) Error() string {
	switch {
	case e.Err != nil && e.Reason != "":
		return e.Reason + ": " + e.Err.Error()
	case e.Err != nil:
		return e.Err.Error()
	default:
		return e.Reason
	}
}

func (e *AcquireError) Unwrap() error { return e.Err }

// KindOf classifies err: an AcquireError carries its own kind, cancellation and registry rate
// limiting are transient, and anything else counts toward quarantine.
func KindOf(err error) FailureKind {
	var ae *AcquireError
	switch {
	case errors.As(err, &ae):
		return ae.Kind
	case errors.Is(err, context.Canceled), errors.Is(err, registry.ErrRateLimited):
		return FailTransient
	}
	return FailCounted
}
