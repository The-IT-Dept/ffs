// Package v1alpha1 contains the ffs API types.
//
// +kubebuilder:object:generate=true
// +groupName=ffs.theitdept.au
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	// GroupVersion is the group and version of the ffs API.
	GroupVersion = schema.GroupVersion{Group: "ffs.theitdept.au", Version: "v1alpha1"}
	// SchemeBuilder registers the ffs types.
	SchemeBuilder runtime.SchemeBuilder
)

// AddToScheme adds the ffs types to a scheme.
func AddToScheme(s *runtime.Scheme) error { return SchemeBuilder.AddToScheme(s) }

// register queues object types for registration under GroupVersion.
func register(objs ...runtime.Object) {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(GroupVersion, objs...)
		metav1.AddToGroupVersion(s, GroupVersion)
		return nil
	})
}
