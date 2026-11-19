package v1alpha1

// OwnerReference identifies the top-level workload that owns a set of pods.
type OwnerReference struct {
	// Kind is the workload kind, for example Deployment.
	Kind string `json:"kind,omitempty"`
	// Namespace is the workload namespace.
	Namespace string `json:"namespace,omitempty"`
	// Name is the workload name.
	Name string `json:"name,omitempty"`
	// UID is the workload UID.
	UID string `json:"uid,omitempty"`
}

// ManagedBy identifies the tool that manages a workload, such as a GitOps controller.
type ManagedBy struct {
	// Tool is the managing tool.
	Tool string `json:"tool,omitempty"`
	// Name is the name of the managing resource.
	Name string `json:"name,omitempty"`
	// Namespace is the namespace of the managing resource.
	Namespace string `json:"namespace,omitempty"`
}
