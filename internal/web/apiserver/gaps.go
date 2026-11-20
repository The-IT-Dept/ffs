package apiserver

import (
	"strings"

	"github.com/the-it-dept/ffs/internal/inventory"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/registry"
	"github.com/the-it-dept/ffs/internal/web/apigen"
)

// imageGaps lists what ffs cannot see in an image: why it is not catalogued, or, for a catalogued
// image, each coverage note in order (attestation-only SBOM, unattributed executables, Rust without
// cargo-auditable, classifier-found packages matched daily against CPE data only). cpeOnly are the
// names of those packages. A digest with no images row is pending.
func imageGaps(img model.Image, hasRow bool, cpeOnly []string) []apigen.GapCode {
	if !hasRow || img.Status == model.ImagePending {
		return []apigen.GapCode{apigen.GapCodePending}
	}
	switch img.Status {
	case model.ImageUnresolvable:
		return []apigen.GapCode{unresolvableGap(img.StatusReason)}
	case model.ImageCatalogFailed:
		return []apigen.GapCode{apigen.GapCodeCatalogFailed}
	case model.ImagePending, model.ImageCatalogued:
	}
	out := []apigen.GapCode{}
	if img.Source == "attestation" {
		out = append(out, apigen.GapCodeAttestationPartial)
	}
	if img.Coverage.UnattributedELF > 0 {
		out = append(out, apigen.GapCodeUnattributedExecutables)
	}
	if img.Coverage.RustWithoutAuditable > 0 {
		out = append(out, apigen.GapCodeRustNoAuditable)
	}
	if len(cpeOnly) > 0 {
		out = append(out, apigen.GapCodeCpeOnlyClassifier)
	}
	return out
}

// unresolvableGap classifies why an image could not be resolved, by the reason formats of the
// registry client and the inventory.
func unresolvableGap(reason string) apigen.GapCode {
	switch {
	case strings.HasPrefix(reason, formatPrefix(registry.ReasonUnauthorized)):
		return apigen.GapCodeUnresolvableAuth
	case strings.HasSuffix(reason, formatSuffix(registry.ReasonNotFound)):
		return apigen.GapCodeUnresolvableNotfound
	case reason == inventory.ReasonSideLoadedNoTag, strings.HasPrefix(reason, formatPrefix(inventory.ReasonSideLoadedMismatch)):
		return apigen.GapCodeUnresolvableSideloaded
	case strings.HasPrefix(reason, formatPrefix(inventory.ReasonUnreachable)):
		return apigen.GapCodeUnresolvableUnreachable
	}
	return apigen.GapCodeUnresolvableOther
}

// formatPrefix is the fixed text of a format string before its first verb.
func formatPrefix(format string) string {
	before, _, _ := strings.Cut(format, "%")
	return before
}

// formatSuffix is the fixed text of a format string after its last verb.
func formatSuffix(format string) string {
	i := strings.LastIndex(format, "%")
	if i < 0 || i+2 > len(format) {
		return format
	}
	return format[i+2:]
}
