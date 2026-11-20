package sbom

import (
	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/registry"
)

// DefaultSources returns the sources ffs acquires SBOMs with: the cataloguer for every image, and
// build attestations only as the fallback for an image the cataloguer refuses as too large. SPDX and
// CycloneDX attestations lose what Syft's binary classifiers found, so taking them first would hide
// runtimes built from source (php, node, python) from the upstream-runtime fast path.
func DefaultSources(reg *registry.Client, cfg config.CatalogConfig) (sources []Source, fallback Source) {
	return []Source{NewCatalogSource(reg, cfg)}, NewAttestationSource(reg)
}
