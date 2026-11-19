// Package sbom acquires and normalises software bills of materials for platform manifests.
package sbom

import (
	"context"
	"errors"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/registry"
)

// Request asks for the SBOM of one platform manifest.
type Request struct {
	Repo, Digest, IndexDigest, Platform string
	Creds                               registry.CredSet
}

// Result is what a Source produced for a Request.
type Result struct {
	SyftJSON          []byte
	Packages          []model.Package
	Coverage          model.Coverage
	Source            string
	VersionAnnotation string
	ConfigUser        string // image config User; "" when the image sets none
}

// MaxSBOMBytes bounds an SBOM document the controller accepts, from the cataloguer or from an
// attestation. Decoding one takes several times its size in memory, and the controller's memory is
// small; an image whose SBOM is larger is quarantined instead.
const MaxSBOMBytes = 64 << 20

// ErrNotFound means a source has nothing for the digest; the next source is tried.
var ErrNotFound = errors.New("sbom: not found")

// Source produces SBOMs, e.g. from attestations or by cataloguing the image.
type Source interface {
	Name() string
	Acquire(ctx context.Context, r Request) (*Result, error)
}
