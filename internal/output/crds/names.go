package crds

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/the-it-dept/ffs/internal/model"
)

const (
	// maxNameLength keeps resource names valid as label values too.
	maxNameLength = 63
	// truncatedPrefix is how much of an over-long name survives before the hash suffix.
	truncatedPrefix = 54
	// nameHashLength is the number of hex characters of the hash suffix.
	nameHashLength = 8
)

// FindingName returns the Finding resource name for an owner's finding on an advisory:
// "<kind>-<name>-<advisory>", lowercased, with characters outside [a-z0-9.-] mapped to "-".
// A name over 63 characters keeps its first 54 and ends in "-" plus 8 hex characters of a hash
// of the full identity, so distinct long names stay distinct.
func FindingName(o model.OwnerRef, advisoryID string) string {
	name := sanitize(strings.ToLower(o.Kind + "-" + o.Name + "-" + advisoryID))
	if len(name) <= maxNameLength {
		return name
	}
	sum := sha256.Sum256([]byte(o.Kind + "/" + o.Namespace + "/" + o.Name + "/" + advisoryID))
	return strings.TrimRight(name[:truncatedPrefix], "-.") + "-" + hex.EncodeToString(sum[:])[:nameHashLength]
}

// VulnerabilityName returns the Vulnerability resource name for an advisory: the lowercased id
// with characters outside [a-z0-9.-] mapped to "-".
func VulnerabilityName(advisoryID string) string {
	return sanitize(strings.ToLower(advisoryID))
}

// sanitize maps every character outside [a-z0-9.-] to "-" and trims "-" and "." at both ends.
func sanitize(s string) string {
	mapped := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-' {
			return r
		}
		return '-'
	}, s)
	return strings.Trim(mapped, "-.")
}
