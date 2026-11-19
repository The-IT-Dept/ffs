// Package v1alpha1 contains the ffs API types.
//
// +kubebuilder:object:generate=true
// +groupName=ffs.theitdept.au
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// GroupVersion is the group and version of the ffs API.
	GroupVersion = schema.GroupVersion{Group: "ffs.theitdept.au", Version: "v1alpha1"}
	// SchemeBuilder registers the ffs types.
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}
	// AddToScheme adds the ffs types to a scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)
