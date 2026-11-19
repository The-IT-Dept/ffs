package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// ExceptionSpec defines which findings are excepted and why.
//
// +kubebuilder:validation:XValidation:rule="has(self.advisories) || has(self.packages) || has(self.imageRepositories) || has(self.owners)",message="at least one of advisories, packages, imageRepositories or owners is required"
type ExceptionSpec struct {
	// Advisories lists advisory IDs or aliases.
	// +kubebuilder:validation:MinItems=1
	// +listType=atomic
	Advisories []string `json:"advisories,omitempty"`
	// Packages lists package names.
	// +kubebuilder:validation:MinItems=1
	// +listType=atomic
	Packages []string `json:"packages,omitempty"`
	// ImageRepositories lists path.Match globs over normalised image repositories.
	// +kubebuilder:validation:MinItems=1
	// +listType=atomic
	ImageRepositories []string `json:"imageRepositories,omitempty"`
	// Owners lists workload names, or Kind/name.
	// +kubebuilder:validation:MinItems=1
	// +listType=atomic
	Owners []string `json:"owners,omitempty"`
	// Reason explains why the exception exists.
	// +kubebuilder:validation:MinLength=1
	Reason string `json:"reason"`
	// Expires is when the exception stops applying (RFC 3339).
	Expires metav1.Time `json:"expires"`
	// VEXStatus is the VEX status to record for excepted findings.
	// +kubebuilder:validation:Enum=not_affected;affected;fixed;under_investigation
	VEXStatus string `json:"vexStatus,omitempty"`
	// Justification is the VEX justification.
	// +kubebuilder:validation:Enum=component_not_present;vulnerable_code_not_present;vulnerable_code_not_in_execute_path;vulnerable_code_cannot_be_controlled_by_adversary;inline_mitigations_already_exist
	Justification string `json:"justification,omitempty"`
}

// ExceptionStatus is the observed state of an exception.
type ExceptionStatus struct {
	// MatchedFindings is the number of findings the exception matches.
	MatchedFindings int32 `json:"matchedFindings,omitempty"`
	// UrgentNotExcepted is the number of matching urgent findings that are not excepted.
	UrgentNotExcepted int32 `json:"urgentNotExcepted,omitempty"`
	// Expired is true once the exception has expired.
	Expired bool `json:"expired,omitempty"`
	// ObservedGeneration is the last generation processed.
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
	// Conditions describe the exception state.
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// Exception excludes matching findings from alerting.
//
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,categories=ffs
// +kubebuilder:printcolumn:name="Expires",type=string,JSONPath=`.spec.expires`
// +kubebuilder:printcolumn:name="Matched",type=integer,JSONPath=`.status.matchedFindings`
// +kubebuilder:printcolumn:name="Expired",type=boolean,JSONPath=`.status.expired`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
type Exception struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ExceptionSpec   `json:"spec"`
	Status ExceptionStatus `json:"status,omitempty"`
}

// ExceptionList is a list of exceptions.
//
// +kubebuilder:object:root=true
type ExceptionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Exception `json:"items"`
}

func init() { register(&Exception{}, &ExceptionList{}) }
