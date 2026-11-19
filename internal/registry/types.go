// Package registry holds the registry types shared by inventory and the registry client.
package registry

import (
	"errors"
	"sort"
	"strings"
)

// CredSet identifies the pull credentials in play for a workload.
type CredSet struct {
	Namespace, ServiceAccount string
	PullSecrets               []string
}

// Key returns "ns|sa|s1,s2" with the secrets sorted; it is the keychain cache key.
func (c CredSet) Key() string {
	s := append([]string(nil), c.PullSecrets...)
	sort.Strings(s)
	return c.Namespace + "|" + c.ServiceAccount + "|" + strings.Join(s, ",")
}

// Manifest is a resolved platform manifest.
type Manifest struct {
	Digest      string            // platform manifest digest
	IndexDigest string            // "" when the input digest was already a platform manifest
	Platform    string            // PlatformKey, e.g. "linux/arm64"
	Annotations map[string]string // index annotations when resolved through an index, else nil
}

var (
	ErrNotFound     = errors.New("registry: not found")
	ErrUnauthorized = errors.New("registry: unauthorized")
	ErrRateLimited  = errors.New("registry: rate limited")
	ErrNoPlatform   = errors.New("registry: no manifest for platform")
)

const (
	ReasonUnauthorized = "registry denied access to %s with the available pull secrets" // %s = repo
	ReasonNotFound     = "%s was not found in the registry"                             // %s = repo@digest
	AnnotationVersion  = "org.opencontainers.image.version"
)
