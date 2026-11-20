package model

import "time"

const (
	// HostRepo is the ImageRepo of every Nodes finding and the Repo of every node-group image.
	HostRepo = "host"
	// NodeGroupDigestPrefix starts the synthetic digest of a group's host SBOM: "nodegroup:<group ID>".
	NodeGroupDigestPrefix = "nodegroup:"
	// NodeExposurePathFmt formats a ContainerUse.ExposurePaths entry; a priority reason reads "exposed via node edge-1".
	NodeExposurePathFmt = "node %s"
)

// NodeGroupKind says where a node group's data came from.
type NodeGroupKind string

const (
	// NodeGroupAgent is a group of nodes with identical host fingerprints reported by the node agent.
	NodeGroupAgent NodeGroupKind = "agent"
	// NodeGroupNodeInfo is a fallback group built from node.status.nodeInfo.
	NodeGroupNodeInfo NodeGroupKind = "nodeinfo"
)

// NodeKernel is the running kernel: its osrelease and the distro package that provides it.
type NodeKernel struct{ Release, Package, Version, SourceName string }

// NodeBinary is a known host binary and its main Go module.
type NodeBinary struct{ Name, Path, Module, Version string }

// NodeGroup is a set of nodes sharing one host fingerprint, the display and drill-down unit for host findings.
type NodeGroup struct {
	ID     string        `json:"id"` // agent: host fingerprint (64 hex); nodeinfo: nodegroup.FallbackID
	Kind   NodeGroupKind `json:"kind"`
	Name   string        `json:"name"`             // stable part: "ubuntu-26.04-k7.0.0-34"
	Label  string        `json:"label"`            // Name + "-" + ID[:6]: "ubuntu-26.04-k7.0.0-34-3f9c1a"
	Digest string        `json:"digest"`           // "nodegroup:<ID>" (agent); "" (nodeinfo)
	Distro *Distro       `json:"distro,omitempty"` // agent only, from the host SBOM

	OSImage                 string `json:"osImage"`
	KernelRelease           string `json:"kernelRelease"` // running kernel: report osrelease (agent) / nodeInfo.kernelVersion
	ContainerRuntimeVersion string `json:"containerRuntimeVersion"`
	KubeletVersion          string `json:"kubeletVersion"`
	Arch                    string `json:"arch"`

	Kernel       *NodeKernel  `json:"kernel,omitempty"`   // agent only
	Binaries     []NodeBinary `json:"binaries,omitempty"` // agent only
	PackageDB    string       `json:"packageDB"`          // "dpkg" | "rpm" | "apk" | "" (agent); "" (nodeinfo)
	PackageCount int          `json:"packageCount"`       // agent: packages after kernel filtering
	Members      []string     `json:"members"`            // sorted node names
	ExposedNodes []string     `json:"exposedNodes,omitempty"`

	FirstSeen, LastSeen time.Time
}

// FieldDrift is one changed node field. Field is "kernel", "osImage", "containerRuntime", "kubelet" or "distro".
type FieldDrift struct{ Field, From, To string }

// DriftPackage is a package present in only one of two compared groups.
type DriftPackage struct{ Ecosystem, Name, Version, Arch string }

// VersionDrift is a package present in both groups at different versions.
// Newer is "from", "to" or "" when the versions are incomparable.
type VersionDrift struct {
	Ecosystem, Name, Arch, From, To string
	Newer                           string
}

// NodeDrift is the difference between two node groups; it reads "To compared with From".
type NodeDrift struct {
	From, To         string // group IDs
	Fields           []FieldDrift
	PackagesCompared bool // false unless both groups are agent groups with stored SBOMs
	OnlyFrom, OnlyTo []DriftPackage
	Changed          []VersionDrift
	NewerInTo        int
	NewerInFrom      int
}

// AgentState is the reporting state of one node's agent.
type AgentState string

const (
	// AgentReporting means the agent reported within the stale window.
	AgentReporting AgentState = "reporting"
	// AgentStale means the agent has reported before but not within the stale window.
	AgentStale AgentState = "stale"
	// AgentNever means the agent has never reported.
	AgentNever AgentState = "never"
	// AgentDisabled means the node agent is turned off.
	AgentDisabled AgentState = "disabled"
)

// NodeCoverageGap is a reason a node's host coverage is incomplete.
type NodeCoverageGap struct{ Code, Detail string }

// Coverage gap codes. They are untyped because NodeCoverageGap.Code is a string.
const (
	GapNodeAgentMissing       = "node_agent_missing"       // never reported, stale, or disabled
	GapNodeAgentBlocked       = "node_agent_blocked"       // permission denied reading a host path (SELinux, policy)
	GapNoPackageDatabase      = "no_package_database"      // Detail exactly "no package database (image-based OS)"
	GapContentStoreUnreadable = "content_store_unreadable" // no containerd content store (CRI-O, other layout)
)

// NodeAgentStatus is what ffs knows about one node's agent.
type NodeAgentStatus struct {
	Node                 string
	State                AgentState
	AgentVersion, BootID string
	LastReport           time.Time
	LastFullReport       time.Time
	LastError            string
	GroupID              string // current group (agent or nodeinfo); "" before the first reconcile
	KernelRelease        string
	RebootPending        bool
	RebootReason         string
	Coverage             []NodeCoverageGap // stored gaps + GapNodeAgentMissing when State != reporting
	Problems             []string          // collection problems from the last report
}

// NodeImage is an image cached on a node.
type NodeImage struct {
	Digest, ConfigDigest string
	Kind                 string   // "manifest" | "index"
	Names                []string // from node.status.images
	SizeBytes            int64
	Complete             bool     // every layer blob present in the content store
	InUse                bool     // a pod on the node runs it (pod informer)
	Nodes                []string // per-node queries: [node]; group queries: members holding it
	Status               ImageStatus
	StatusReason         string // from the images row
	// Source is node_images.source: "content-store" | "status" | "both". It is where the node
	// reported the image, not the image's SBOM source.
	Source string
}

// UnresolvableClass says why ffs cannot catalogue an image by pulling it.
type UnresolvableClass string

const (
	UnresolvableSideLoaded      UnresolvableClass = "sideloaded"
	UnresolvableAuth            UnresolvableClass = "auth"
	UnresolvableUnreachable     UnresolvableClass = "unreachable"
	UnresolvableNotFound        UnresolvableClass = "notfound"
	UnresolvableLayersDiscarded UnresolvableClass = "layers_discarded"
	UnresolvableOther           UnresolvableClass = "other"
)
