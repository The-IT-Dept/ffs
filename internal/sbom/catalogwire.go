package sbom

import (
	"encoding/json"

	"github.com/the-it-dept/ffs/internal/model"
)

// CatalogRequest asks the cataloguer for the SBOM of one platform manifest, pulled from a registry
// or read from a local source. It is sent over the catalog container's unix socket and, from there,
// on the worker's stdin.
type CatalogRequest struct {
	Ref            string      `json:"ref"`      // pull location "repo@sha256:..." (mirror applied); must contain "@sha256:"
	Platform       string      `json:"platform"` // "linux/amd64"; host-dir takes none
	Auth           CatalogAuth `json:"auth"`
	MaxBytes       int64       `json:"maxBytes"`
	TimeoutSeconds int         `json:"timeoutSeconds"`
	Source         string      `json:"source,omitempty"` // "" or CatalogSourceRegistry: pull Ref; local sources read Path
	Path           string      `json:"path,omitempty"`   // local sources: absolute path inside the server's --local-root
}

// Catalog request sources.
const (
	CatalogSourceRegistry = "registry"
	CatalogSourceOCIDir   = "oci-dir"  // an OCI image layout with exactly one image in index.json
	CatalogSourceHostDir  = "host-dir" // a staged copy of host inputs (os-release, package DBs, binaries)
)

// CatalogAuth carries the pull credentials for one job. It is never logged.
type CatalogAuth struct {
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
	RegistryToken string `json:"registryToken,omitempty"`
	IdentityToken string `json:"identityToken,omitempty"`
}

// MaxCatalogResponseBytes bounds a cataloguer's successful response, read or written: the syft-json
// document (at most MaxSBOMBytes) plus its envelope.
const MaxCatalogResponseBytes = MaxSBOMBytes + 1<<20

// CatalogResponse is a successful job: the syft-json document and its coverage.
type CatalogResponse struct {
	SyftJSON json.RawMessage `json:"syftJSON"`
	Coverage model.Coverage  `json:"coverage"`
	// Encoded, when set, is the whole response already encoded (a worker's output), sent as it is in
	// place of SyftJSON and Coverage, so a large SBOM is not decoded and encoded again on its way.
	Encoded []byte `json:"-"`
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
