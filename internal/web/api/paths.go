package api

import "github.com/the-it-dept/ffs/internal/model"

// clusterLevel stands for the empty namespace of a cluster-level owner in a URL path, which cannot
// carry an empty segment.
const clusterLevel = "-"

// OwnerPath is the URL path of an owner below /owners/: "Deployment/shop/web", and
// "Cluster/-/test" for a cluster-level owner.
func OwnerPath(ref model.OwnerRef) string {
	ns := ref.Namespace
	if ns == "" {
		ns = clusterLevel
	}
	return ref.Kind + "/" + ns + "/" + ref.Name
}

// ParseOwnerPath is the inverse of OwnerPath: "-" as the namespace means none.
func ParseOwnerPath(kind, namespace, name string) model.OwnerRef {
	if namespace == clusterLevel {
		namespace = ""
	}
	return model.OwnerRef{Kind: kind, Namespace: namespace, Name: name}
}
