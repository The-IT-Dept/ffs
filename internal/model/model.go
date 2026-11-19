// Package model holds the shared domain types. It imports the standard library only.
package model

import "time"

type FixState string

const (
	FixFixed       FixState = "fixed"
	FixNotFixed    FixState = "not-fixed"
	FixWontFix     FixState = "wont-fix"
	FixNotAffected FixState = "not-affected"
	FixUnknown     FixState = "unknown"
)

type MatchSource string

const (
	SourceGrype    MatchSource = "grype"
	SourceOSV      MatchSource = "osv"
	SourceUpstream MatchSource = "upstream"
	SourceK8s      MatchSource = "k8s"
)

type FindingState string

const (
	StateOpen     FindingState = "open"
	StateExcepted FindingState = "excepted"
	StateResolved FindingState = "resolved"
)

type Trigger string

const (
	TriggerNewAdvisory      Trigger = "NewAdvisory"
	TriggerInventoryChange  Trigger = "InventoryChange"
	TriggerPriorityChange   Trigger = "PriorityChange"
	TriggerFixAvailable     Trigger = "FixAvailable"
	TriggerExceptionExpired Trigger = "ExceptionExpired"
	TriggerWithdrawn        Trigger = "Withdrawn"
	TriggerUpgradeAvailable Trigger = "UpgradeAvailable"
)

type Distro struct{ ID, VersionID, Codename string } // "debian","12","bookworm"

type Package struct {
	ID            string // PackageID(): sha256 hex of digest|ecosystem|distro|name|version|arch|path
	ImageDigest   string // platform manifest digest, or synthetic "k8s:<ver>" / "runtime:<name>@<ver>"
	Ecosystem     string // syft pkg.Type string: "deb","rpm","apk","npm","python","go-module", ...
	Distro        *Distro
	Name, Version string
	Epoch         string
	Arch          string
	SourceName    string // upstream/source/origin package (deb source, apk origin, rpm sourceRPM name)
	SourceVersion string
	PURL          string
	CPEs          []string
	Path, Layer   string
	Classifier    string // syft binary classifier class when found that way, e.g. "php-cli-binary"
	GoStdlib      bool   // Name=="stdlib" from a Go binary
	SyftID        string // syft artifact ID in its SBOM; "" for synthetic packages; not part of PackageID
}

type Coverage struct {
	UnattributedELF      int
	RustWithoutAuditable int
	Notes                []string
}

type ImageStatus string

const (
	ImagePending       ImageStatus = "pending"
	ImageCatalogued    ImageStatus = "catalogued"
	ImageUnresolvable  ImageStatus = "unresolvable"
	ImageCatalogFailed ImageStatus = "catalogFailed"
)

type Image struct {
	Digest, IndexDigest, Repo, Platform string // Repo normalised: "docker.io/library/nginx"; Platform "linux/amd64"
	Status                              ImageStatus
	StatusReason                        string
	Source                              string // "attestation" | "registry" | "agent"
	VersionAnnotation                   string // org.opencontainers.image.version if present
	ConfigUser                          string // image config User; "" when the image sets none
	Coverage                            Coverage
	CataloguedAt                        time.Time
	Attempts                            int
	QuarantinedUntil                    time.Time
}

// OwnerRef identifies a workload. Kind may be "Cluster" or "ContainerRuntime" for cluster-level subjects.
type OwnerRef struct{ Kind, Namespace, Name, UID string }

// ManagedBy names the deployment tool. Tool: "helm" | "flux-helmrelease" | "flux-kustomization" | "argocd".
type ManagedBy struct{ Tool, Name, Namespace string }

type ContainerKind string

const (
	ContainerRegular     ContainerKind = "container"
	ContainerInit        ContainerKind = "init"
	ContainerSidecar     ContainerKind = "sidecar"
	ContainerEphemeral   ContainerKind = "ephemeral"
	ContainerImageVolume ContainerKind = "imageVolume"
)

type ContainerUse struct {
	Name                string
	Kind                ContainerKind
	ImageRef            string
	Repo, Digest        string
	Platform            string
	RootUnlessImageUser bool // effective runAsUser unset and runAsNonRoot not true: runs as the image's user
}

type WorkloadContext struct {
	Exposed          bool
	ExposurePaths    []string // human strings: "HTTPRoute netbox/netbox on Gateway public/edge"
	Privileged       bool
	PrivilegeReasons []string
	PowerfulSA       bool
	SAReasons        []string
}

type Owner struct {
	Ref            OwnerRef
	ManagedBy      *ManagedBy
	NotRunning     bool
	ServiceAccount string
	Containers     []ContainerUse
	Context        WorkloadContext
	Arch           []string // node architectures its pods run on
	PullSecrets    []string // sorted spec.imagePullSecrets names; never served by the API
	UpdatedAt      time.Time
}

type Advisory struct {
	ID                            string // canonical: CVE if any alias is a CVE, else GHSA, else source ID
	Aliases                       []string
	Title                         string
	Published, Modified, Observed time.Time // Observed = first time ffs saw it
	Links                         []string
	CNASeverity                   Severity
	CNACVSS                       float64
	CNASource                     string
	KEVAdded                      *time.Time
	EPSS, EPSSPercentile          float64
	Malicious                     bool // OSV MAL- record
	Withdrawn                     bool
}

type Match struct {
	ImageDigest, PackageID string
	AdvisoryID             string // canonical (store resolves aliases on write)
	Source                 MatchSource
	FixState               FixState
	FixedVersions          []string
	VendorSeverity         Severity
	VendorSeveritySource   string    // "debian","ubuntu","ghsa","redhat", ...
	Namespace              string    // grype namespace, e.g. "debian:distro:debian:12"
	DBBuilt                time.Time // grype DB build time (zero for non-grype)
	ObservedAt             time.Time
}

type FindingPackage struct {
	Name, Ecosystem, Installed, Path string
	Fixed                            []string
}

type Finding struct {
	Fingerprint    string // FindingFingerprint(cluster, owner, repo, advisoryID)
	Owner          OwnerRef
	ImageRepo      string
	AdvisoryID     string
	Packages       []FindingPackage
	Digests        []string
	Severity       Severity
	SeveritySource string
	FixState       FixState
	FixAvailable   bool
	Priority       Priority
	Reasons        []string
	Provisional    bool
	GoStdlib       bool
	State          FindingState
	ExceptedBy     string // "namespace/name" of Exception
	Published      time.Time
	Observed       time.Time
	Matched        time.Time
	LastSeen       time.Time
	ResolvedAt     *time.Time
	Suggestion     *Suggestion
}

type Transition struct {
	ID                       int64
	Fingerprint              string
	Owner                    OwnerRef
	AdvisoryID               string
	FromState, ToState       FindingState // FromState "" for creation
	FromPriority, ToPriority Priority
	Trigger                  Trigger
	Provisional              bool
	At                       time.Time
}

type Tier string

const (
	TierRefresh Tier = "refresh"
	TierPatch   Tier = "patch"
	TierMinor   Tier = "minor"
	TierMajor   Tier = "major"
	TierNone    Tier = "none"
)

type Suggestion struct {
	Repo, FromTag, ToTag, ToDigest string
	Tier                           Tier
	Fixes, Remaining, Introduces   map[Priority]int
	Alternatives                   []Suggestion
	EOL                            string // e.g. "debian 10 reached end of life 2024-06-30"
	ComputedAt                     time.Time
}
