package sbom

import (
	"encoding/json"

	"github.com/the-it-dept/ffs/internal/model"
)

// CatalogRequest asks the cataloguer for the SBOM of one platform manifest. It is sent over the
// catalog container's unix socket and, from there, on the worker's stdin.
type CatalogRequest struct {
	Ref            string      `json:"ref"`      // pull location "repo@sha256:..." (mirror applied); must contain "@sha256:"
	Platform       string      `json:"platform"` // "linux/amd64"
	Auth           CatalogAuth `json:"auth"`
	MaxBytes       int64       `json:"maxBytes"`
	TimeoutSeconds int         `json:"timeoutSeconds"`
}

// CatalogAuth carries the pull credentials for one job. It is never logged.
type CatalogAuth struct {
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	RegistryToken string `json:"registryToken,omitempty"`
	IdentityToken string `json:"identityToken,omitempty"`
}

// CatalogResponse is a successful job: the syft-json document and its coverage.
type CatalogResponse struct {
	SyftJSON json.RawMessage `json:"syftJSON"`
	Coverage model.Coverage  `json:"coverage"`
}

// CatalogError is a failed job. Kind is one of the Kind* constants.
type CatalogError struct {
	Kind  string `json:"kind"`
	Error string `json:"error"`
}

// Catalog error kinds, each with the HTTP status the cataloguer answers with.
const (
	KindBadRequest   = "bad-request"  // 400
	KindUnauthorized = "unauthorized" // 401
	KindNotFound     = "not-found"    // 404
	KindTooLarge     = "too-large"    // 413
	KindRateLimited  = "rate-limited" // 429
	KindUnavailable  = "unavailable"  // 502: the registry could not be reached or answered with a server error
	KindFailed       = "failed"       // 500
	KindBusy         = "busy"         // 503
	KindTimeout      = "timeout"      // 504
	KindScratchFull  = "scratch-full" // 507
)

// UnknownRustNoAuditable is the unknowns entry the cataloguer adds to an unattributed ELF executable
// that was built by rustc but carries no cargo-auditable dependency metadata.
const UnknownRustNoAuditable = "ffs: rust binary without cargo-auditable metadata"
