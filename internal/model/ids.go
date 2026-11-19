package model

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

func hashParts(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])
}

// PackageID is the persisted identity of a package within an image. Codename, source, PURL,
// layer and SyftID are deliberately not part of it. The output must never change.
func PackageID(digest string, p Package) string {
	distro := ""
	if p.Distro != nil {
		distro = p.Distro.ID + "/" + p.Distro.VersionID
	}
	return hashParts(digest, p.Ecosystem, distro, p.Name, p.Version, p.Arch, p.Path)
}

// FindingFingerprint is the persisted identity of a finding. The owner UID is deliberately
// not part of it. The output must never change.
func FindingFingerprint(cluster string, o OwnerRef, repo, advisoryID string) string {
	return hashParts(cluster, o.Kind, o.Namespace, o.Name, repo, advisoryID)
}

// Key returns "Kind/Namespace/Name"; Namespace is empty for cluster-level owners.
func (o OwnerRef) Key() string { return o.Kind + "/" + o.Namespace + "/" + o.Name }

// CanonicalID returns the smallest CVE- id, else the smallest GHSA- id, else ids[0], else "".
func CanonicalID(ids ...string) string {
	for _, prefix := range []string{"CVE-", "GHSA-"} {
		best := ""
		for _, id := range ids {
			if strings.HasPrefix(id, prefix) && (best == "" || id < best) {
				best = id
			}
		}
		if best != "" {
			return best
		}
	}
	if len(ids) > 0 {
		return ids[0]
	}
	return ""
}
