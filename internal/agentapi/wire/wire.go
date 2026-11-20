// Package wire holds the JSON types the node agent and the controller exchange over /agent/v1.
// It imports only the standard library and internal/model, so both sides can share it.
package wire

import (
	"encoding/json"
	"time"

	"github.com/the-it-dept/ffs/internal/model"
)

// Endpoint paths, the token audience and the report kinds.
const (
	PathReport = "/agent/v1/report"
	PathSBOM   = "/agent/v1/sbom"
	PathConfig = "/agent/v1/config"

	// Audience is the audience of the projected service-account token the agent presents.
	Audience = "ffs-agent"

	// KindFull is a report that carries the host inventory as well as the cached images.
	KindFull = "full"
	// KindImages is a lightweight report: a heartbeat that carries the cached images only when they changed.
	KindImages = "images"

	// HeaderWorkID carries an SBOMResult's ID on POST /agent/v1/sbom, so the controller knows which request
	// the result answers before it reads the body. Older agents send none.
	HeaderWorkID = "Ffs-Work-Id"
)

// Timing both sides rely on.
const (
	// ClientTimeout bounds one request of the agent. The controller answers an SBOM result within
	// ClientTimeout less a minute, however long the result waits to be read, so the agent sees the answer.
	ClientTimeout = 10 * time.Minute
	// ResultGrace is how long after its WorkRequest's Deadline the controller still takes a result: the
	// agent's job ends at the deadline and its result is sent after that, and sent again while the controller
	// does not take it (no answer, 429 or 5xx).
	ResultGrace = 2 * time.Minute
)

// Report is sent by the agent to POST /agent/v1/report.
// Reports are ordered by (BootID, Instance, Seq): within one agent process (Instance) Seq only grows,
// and a report from a different Instance of the same boot is a newer process (older ones have exited).
// The controller ignores a report it has already applied. StartedAt is informational only: wall
// clocks can step back, so it never orders reports.
type Report struct {
	Node          string    `json:"node"`
	AgentVersion  string    `json:"agentVersion"`
	BootID        string    `json:"bootID"`
	Instance      string    `json:"instance"` // random per agent process start (32 hex chars)
	StartedAt     time.Time `json:"startedAt"`
	Seq           uint64    `json:"seq"`
	Kind          string    `json:"kind"`               // KindFull | KindImages
	CollectedAt   time.Time `json:"collectedAt"`        // when the agent built the report
	KernelRelease string    `json:"kernelRelease"`      // /proc/sys/kernel/osrelease
	Arch          string    `json:"arch"`               // runtime.GOARCH
	Host          *Host     `json:"host,omitempty"`     // KindFull only
	Images        *Images   `json:"images,omitempty"`   // nil = unchanged since the last accepted report
	Problems      []Problem `json:"problems,omitempty"` // collection problems
}

// Host is the host inventory the agent sends inside a full Report.
type Host struct {
	PackageDB string          `json:"packageDB"` // "dpkg" | "rpm" | "apk" | ""
	Binaries  []Binary        `json:"binaries"`
	SyftJSON  json.RawMessage `json:"syftJSON"` // the cataloguer's syft-json document of the staged host inputs
}

// Binary is a known host binary the agent staged for cataloguing.
// Path is the resolved host path of the staged file, which is also Syft's location for its Go modules;
// k3s multi-call names share one Path.
type Binary struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Size int64  `json:"size"`
}

// Images is the agent's list of images in the node's containerd content store.
type Images struct {
	ContentStore bool          `json:"contentStore"` // false: no content store could be read
	Digests      []CachedImage `json:"digests"`
}

// CachedImage is one image manifest or index the agent found in the content store.
type CachedImage struct {
	Digest       string   `json:"digest"`
	MediaType    string   `json:"mediaType"`
	ConfigDigest string   `json:"configDigest"`
	Platform     string   `json:"platform"`
	Manifests    []string `json:"manifests,omitempty"` // index only: child digests in index order
	Size         int64    `json:"size"`
	Complete     bool     `json:"complete"`
}

// Problem is a collection problem the agent reports with a full Report.
type Problem struct {
	Code   string `json:"code"`
	Path   string `json:"path,omitempty"` // host path, when the problem concerns one
	Detail string `json:"detail"`
}

// Problem codes.
const (
	ProblemPermissionDenied = "permission_denied"
	ProblemNoPackageDB      = "no_package_db"
	ProblemContentStore     = "content_store"
	ProblemCatalog          = "catalog"
	ProblemScratch          = "scratch"
)

// ReportResponse is the controller's answer to a Report.
//
// Back-pressure: when the controller cannot take a full report now (its ingest budget is spent), it
// answers POST /agent/v1/report with 429 Too Many Requests and a Retry-After header in seconds. The
// agent waits at least that long and resends without re-cataloguing the host (it keeps the last host
// inventory it collected until the controller has stored one).
type ReportResponse struct {
	Applied bool `json:"applied"` // false: a duplicate or out-of-order report, nothing stored
	// HostRetry is true when the report was a full report but its host part was not stored (a
	// transient controller-side failure, or another node's identical host inventory is being stored).
	// The agent resends the host part on its full-report backoff, reusing the inventory it collected.
	HostRetry bool          `json:"hostRetry,omitempty"`
	Work      []WorkRequest `json:"work"`
	Config    AgentConfig   `json:"config"`
}

// WorkRequest is sent by the controller inside a ReportResponse: catalogue this image from the node's content store.
type WorkRequest struct {
	ID       string    `json:"id"`
	Digest   string    `json:"digest"`
	Platform string    `json:"platform"`
	Deadline time.Time `json:"deadline"`
}

// SBOMResult is sent by the agent to POST /agent/v1/sbom: the outcome of one WorkRequest.
type SBOMResult struct {
	ID           string          `json:"id"`
	Node         string          `json:"node"`
	AgentVersion string          `json:"agentVersion"`
	Digest       string          `json:"digest"`
	SyftJSON     json.RawMessage `json:"syftJSON,omitempty"`
	Coverage     model.Coverage  `json:"coverage"`
	Unavailable  string          `json:"unavailable,omitempty"` // UnavailableNotFound | UnavailableLayersDiscarded | UnavailableTooLarge | UnavailableSkipped
	Failure      string          `json:"failure,omitempty"`     // cataloguer crash, OOM or timeout: counts toward the poison pill
}

// SBOMResult.Unavailable values.
const (
	UnavailableNotFound        = "not_found"
	UnavailableLayersDiscarded = "layers_discarded"
	UnavailableTooLarge        = "too_large"
	// UnavailableSkipped: the agent did not attempt the request, for a reason that is not the image's (too
	// little of its time left, a busy cataloguer, a scratch volume that cannot take it, the agent stopping).
	// The controller releases the request without counting it, and offers the image again.
	UnavailableSkipped = "skipped"
)

// AgentConfig is sent by the controller from GET /agent/v1/config and inside every ReportResponse.
type AgentConfig struct {
	ReportIntervalSeconds    int64 `json:"reportIntervalSeconds"`
	ImageListIntervalSeconds int64 `json:"imageListIntervalSeconds"`
	JitterPercent            int   `json:"jitterPercent"`
	MaxImageBytes            int64 `json:"maxImageBytes"`  // 0: the agent keeps its --max-image-bytes
	MaxReportBytes           int64 `json:"maxReportBytes"` // 0: no report-size rule
}
