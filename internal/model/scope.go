package model

import (
	"errors"
	"fmt"
	"strings"
)

// ScopeKind names what a scope narrows the cluster down to.
type ScopeKind string

const (
	ScopeCluster      ScopeKind = "cluster"
	ScopeNamespace    ScopeKind = "namespace"
	ScopeWorkload     ScopeKind = "workload"
	ScopeImage        ScopeKind = "image"
	ScopeNodeGroup    ScopeKind = "nodegroup"
	ScopeNode         ScopeKind = "node"
	ScopeControlPlane ScopeKind = "controlplane"
)

// Scope is the part of the cluster a view or a query covers. Value is the namespace, the owner key
// "Kind/Namespace/Name", the image digest, the node group ID or the node name, by Kind; it is ""
// for the cluster and control plane scopes.
type Scope struct {
	Kind  ScopeKind
	Value string
}

// ErrBadScope is returned, wrapped with the input, for a string that is not a scope.
var ErrBadScope = errors.New("model: invalid scope")

// ParseScope parses "" or "cluster", "controlplane", or "<kind>:<value>" with a non-empty value.
// The kind is split off at the first colon, so an image digest keeps its own. A workload value is
// an owner key: three parts, with a non-empty kind and name.
func ParseScope(s string) (Scope, error) {
	switch s {
	case "", string(ScopeCluster):
		return Scope{Kind: ScopeCluster}, nil
	case string(ScopeControlPlane):
		return Scope{Kind: ScopeControlPlane}, nil
	}
	kind, value, ok := strings.Cut(s, ":")
	if !ok || value == "" {
		return Scope{}, badScope(s)
	}
	switch k := ScopeKind(kind); k {
	case ScopeNamespace, ScopeImage, ScopeNodeGroup, ScopeNode:
		return Scope{Kind: k, Value: value}, nil
	case ScopeWorkload:
		if _, ok := ownerOfKey(value); ok {
			return Scope{Kind: k, Value: value}, nil
		}
	}
	return Scope{}, badScope(s)
}

func badScope(s string) error { return fmt.Errorf("%w: %q", ErrBadScope, s) }

// String is the inverse of ParseScope; the cluster scope is "cluster".
func (s Scope) String() string {
	switch s.Kind {
	case ScopeCluster, ScopeControlPlane:
		return string(s.Kind)
	}
	return string(s.Kind) + ":" + s.Value
}

// Owner returns the owner a workload scope names, and false for every other scope.
func (s Scope) Owner() (OwnerRef, bool) {
	if s.Kind != ScopeWorkload {
		return OwnerRef{}, false
	}
	return ownerOfKey(s.Value)
}

// ownerOfKey splits an owner key, "Kind/Namespace/Name", whose kind and name are non-empty.
func ownerOfKey(key string) (OwnerRef, bool) {
	parts := strings.Split(key, "/")
	if len(parts) != 3 || parts[0] == "" || parts[2] == "" {
		return OwnerRef{}, false
	}
	return OwnerRef{Kind: parts[0], Namespace: parts[1], Name: parts[2]}, true
}
