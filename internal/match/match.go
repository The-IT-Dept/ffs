// Package match defines the matcher seam: a Matcher turns an image's packages into advisory
// matches, and a Delta carries a batch of matches with the scope they replace. The matchers live in
// the subpackages.
package match

import (
	"context"
	"errors"
	"strings"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

// ErrNotReady means the matcher has no vulnerability database loaded yet. The engine reads it as
// "no opinion from this matcher", never as a failure.
var ErrNotReady = errors.New("match: no vulnerability database loaded")

// ImageInput is one image to match.
type ImageInput struct {
	Digest   string
	SyftJSON []byte // nil for synthetic digests (k8s:, runtime:)
	Packages []model.Package
	// Hints are the image's current OSV matches. The grype matcher uses them to emit FixNotAffected
	// "opinion" matches when its DB has a record for the advisory but no match (spec §6.5 precedence).
	Hints []model.Match
}

// Matcher matches one image.
type Matcher interface {
	Source() model.MatchSource
	MatchImage(ctx context.Context, in ImageInput) ([]model.Match, error)
}

// Delta is a batch of matches and the scope of stored matches it replaces.
type Delta struct {
	Scope   store.MatchScope
	Matches []model.Match
}

// IsSynthetic reports whether digest names a synthetic cluster-level subject rather than an image.
func IsSynthetic(digest string) bool {
	return strings.HasPrefix(digest, "k8s:") || strings.HasPrefix(digest, "runtime:")
}
