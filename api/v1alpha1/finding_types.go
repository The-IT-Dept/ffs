package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// FindingStatus is the observed state of a finding. ffs writes status only.
type FindingStatus struct {
	// Cluster is the name of the cluster the finding belongs to.
	Cluster string `json:"cluster,omitempty"`
	// Fingerprint is the stable identity of the finding.
	Fingerprint string `json:"fingerprint,omitempty"`
	// Subject describes the affected workload and images.
	Subject FindingSubject `json:"subject"`
	// Advisory summarises the vulnerability advisory.
	Advisory AdvisorySummary `json:"advisory"`
	// Packages lists the affected packages. The primary package is first.
	// +listType=atomic
	Packages []AffectedPackage `json:"packages,omitempty"`
	// Fix is the first available fixed version, or the fix state when none is available.
	Fix string `json:"fix,omitempty"`
	// Priority is the computed priority.
	// +kubebuilder:validation:Enum=urgent;high;medium;low
	Priority string `json:"priority"`
	// Reasons explains the computed priority.
	// +listType=atomic
	Reasons []string `json:"reasons,omitempty"`
	// Exposure summarises how exposed the workload is.
	Exposure ExposureSummary `json:"exposure,omitempty"`
	// Suggestion is the suggested image update, if any.
	Suggestion *SuggestionSummary `json:"suggestion,omitempty"`
	// State is the lifecycle state of the finding.
	// +kubebuilder:validation:Enum=open;excepted;resolved
	State string `json:"state"`
	// Provisional is true while the finding rests on incomplete data.
	Provisional bool `json:"provisional,omitempty"`
	// GoStdlib is true when the affected package is the Go standard library.
	GoStdlib bool `json:"goStdlib,omitempty"`
	// Published is when the advisory was published.
	Published *metav1.Time `json:"published,omitempty"`
	// Observed is when the finding was first observed.
	Observed *metav1.Time `json:"observed,omitempty"`
	// Matched is when the finding was first matched.
	Matched *metav1.Time `json:"matched,omitempty"`
	// LastSeen is when the finding was last seen.
	LastSeen *metav1.Time `json:"lastSeen,omitempty"`
}

// FindingSubject describes the affected workload.
type FindingSubject struct {
	// Owner is the top-level workload.
	Owner OwnerReference `json:"owner,omitempty"`
	// Containers lists the affected container names.
	// +listType=atomic
	Containers []string `json:"containers,omitempty"`
	// ImageRepository is the normalised image repository.
	ImageRepository string `json:"imageRepository,omitempty"`
	// Digests lists the affected image digests.
	// +listType=atomic
	Digests []string `json:"digests,omitempty"`
	// ManagedBy identifies the tool managing the workload.
	ManagedBy *ManagedBy `json:"managedBy,omitempty"`
}

// AdvisorySummary summarises an advisory.
type AdvisorySummary struct {
	// ID is the advisory identifier.
	ID string `json:"id,omitempty"`
	// Aliases lists other identifiers for the advisory.
	// +listType=atomic
	Aliases []string `json:"aliases,omitempty"`
	// Title is the advisory title.
	Title string `json:"title,omitempty"`
	// Severity is the advisory severity.
	// +kubebuilder:validation:Enum=critical;high;medium;low;negligible;unknown
	Severity string `json:"severity,omitempty"`
	// SeveritySource names where the severity came from.
	SeveritySource string `json:"severitySource,omitempty"`
	// Links lists reference URLs.
	// +listType=atomic
	Links []string `json:"links,omitempty"`
}

// AffectedPackage is a package affected by an advisory.
type AffectedPackage struct {
	// Name is the package name.
	Name string `json:"name,omitempty"`
	// Type is the package type.
	Type string `json:"type,omitempty"`
	// Installed is the installed version.
	Installed string `json:"installed,omitempty"`
	// Fixed lists versions that fix the advisory.
	// +listType=atomic
	Fixed []string `json:"fixed,omitempty"`
	// Path is where the package was found in the image.
	Path string `json:"path,omitempty"`
}

// ExposureSummary summarises workload exposure.
type ExposureSummary struct {
	// Exposed is true when the workload is reachable from outside the cluster.
	Exposed bool `json:"exposed,omitempty"`
	// ExposurePaths describes how the workload is exposed.
	// +listType=atomic
	ExposurePaths []string `json:"exposurePaths,omitempty"`
	// Privileged is true when the workload runs with elevated privileges.
	Privileged bool `json:"privileged,omitempty"`
	// PrivilegeReasons explains why the workload is considered privileged.
	// +listType=atomic
	PrivilegeReasons []string `json:"privilegeReasons,omitempty"`
	// PowerfulServiceAccount is true when the service account has broad permissions.
	PowerfulServiceAccount bool `json:"powerfulServiceAccount,omitempty"`
	// ServiceAccountReasons explains why the service account is considered powerful.
	// +listType=atomic
	ServiceAccountReasons []string `json:"serviceAccountReasons,omitempty"`
}

// SuggestionSummary describes a suggested image update.
type SuggestionSummary struct {
	// Target is what to upgrade to, as alerts and Events name it: "nginx:1.30.7",
	// "nginx:1.30.6 (new digest)" for a rebuilt tag, or "kubernetes v1.35.10" for the cluster.
	// It is display text, not a pullable image reference.
	Target string `json:"target,omitempty"`
	// Digest is the digest of the suggested image.
	Digest string `json:"digest,omitempty"`
	// Tier is the update tier.
	Tier string `json:"tier,omitempty"`
	// Fixes counts findings fixed by the update, keyed by priority.
	Fixes map[string]int32 `json:"fixes,omitempty"`
	// Remaining counts findings remaining after the update, keyed by priority.
	Remaining map[string]int32 `json:"remaining,omitempty"`
	// Introduces counts findings introduced by the update, keyed by priority.
	Introduces map[string]int32 `json:"introduces,omitempty"`
}

// Finding is a vulnerability affecting a workload.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,categories={ffs,anxiety}
// +kubebuilder:printcolumn:name="Advisory",type=string,JSONPath=`.status.advisory.id`
// +kubebuilder:printcolumn:name="Severity",type=string,JSONPath=`.status.advisory.severity`
// +kubebuilder:printcolumn:name="Priority",type=string,JSONPath=`.status.priority`
// +kubebuilder:printcolumn:name="Package",type=string,JSONPath=`.status.packages[0].name`
// +kubebuilder:printcolumn:name="Installed",type=string,JSONPath=`.status.packages[0].installed`
// +kubebuilder:printcolumn:name="Fix",type=string,JSONPath=`.status.fix`
// +kubebuilder:printcolumn:name="Suggested",type=string,JSONPath=`.status.suggestion.target`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type Finding struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Status FindingStatus `json:"status,omitempty"`
}

// FindingList is a list of findings.
//
// +kubebuilder:object:root=true
type FindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Finding `json:"items"`
}

func init() { register(&Finding{}, &FindingList{}) }
