package registry

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
)

// Classify wraps a registry transport error in the matching sentinel: ErrUnauthorized (401, 403),
// ErrNotFound (404, MANIFEST_UNKNOWN, NAME_UNKNOWN) or ErrRateLimited (429). Any other error,
// including one already classified, is returned unchanged.
func Classify(err error) error {
	if err == nil || errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrNotFound) || errors.Is(err, ErrRateLimited) {
		return err
	}
	var te *transport.Error
	if !errors.As(err, &te) {
		return err
	}
	switch {
	case te.StatusCode == http.StatusUnauthorized || te.StatusCode == http.StatusForbidden:
		return fmt.Errorf("%w: %w", ErrUnauthorized, err)
	case te.StatusCode == http.StatusTooManyRequests:
		return fmt.Errorf("%w: %w", ErrRateLimited, err)
	case te.StatusCode == http.StatusNotFound || hasCode(te, transport.ManifestUnknownErrorCode, transport.NameUnknownErrorCode):
		return fmt.Errorf("%w: %w", ErrNotFound, err)
	}
	return err
}

func hasCode(te *transport.Error, codes ...transport.ErrorCode) bool {
	for _, d := range te.Errors {
		for _, c := range codes {
			if d.Code == c {
				return true
			}
		}
	}
	return false
}
