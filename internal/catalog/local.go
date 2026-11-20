package catalog

import (
	"context"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"

	"github.com/the-it-dept/ffs/internal/sbom"
)

// hostCatalogers are the only catalogers run on a staged host directory: the package databases and
// the Go modules of the known host binaries. Anything else the staging copied by accident (an npm
// tree, say) is not the host's inventory.
var hostCatalogers = []string{"dpkg-db-cataloger", "rpm-db-cataloger", "apk-db-cataloger", "go-module-binary-cataloger"}

// catalogOCIDir catalogues the one image of the OCI layout at req.Path for req.Platform, with the
// same SBOM settings as a registry image.
func catalogOCIDir(ctx context.Context, req sbom.CatalogRequest) (*sbom.CatalogResponse, error) {
	platform, err := image.NewPlatform(req.Platform)
	if err != nil {
		return nil, &WorkError{Kind: sbom.KindBadRequest, Msg: err.Error()}
	}
	src, err := syft.GetSource(ctx, req.Path, syft.DefaultGetSourceConfig().WithSources("oci-dir").WithPlatform(platform))
	if err != nil {
		return nil, workError(err)
	}
	defer func() { _ = src.Close() }()
	return catalogImage(ctx, src)
}

// catalogHostDir catalogues a staged copy of a node's host inputs at req.Path. Locations are relative
// to it, so they read as host paths ("/usr/bin/k3s"). It takes no platform (Syft refuses one for a
// directory), runs only hostCatalogers and reports no unknowns.
func catalogHostDir(ctx context.Context, req sbom.CatalogRequest) (*sbom.CatalogResponse, error) {
	src, err := syft.GetSource(ctx, req.Path, syft.DefaultGetSourceConfig().WithSources("local-directory").WithBasePath(req.Path))
	if err != nil {
		return nil, workError(err)
	}
	defer func() { _ = src.Close() }()
	cfg := imageSBOMConfig().
		WithUnknownsConfig(cataloging.UnknownsConfig{}).
		WithCatalogerSelection(cataloging.NewSelectionRequest().WithDefaults(hostCatalogers...))
	doc, err := syft.CreateSBOM(ctx, src, cfg)
	if err != nil {
		return nil, workError(err)
	}
	b, err := sbom.EncodeSyftJSON(doc)
	if err != nil {
		return nil, workError(err)
	}
	return &sbom.CatalogResponse{SyftJSON: b, Coverage: sbom.CoverageOf(doc)}, nil
}
