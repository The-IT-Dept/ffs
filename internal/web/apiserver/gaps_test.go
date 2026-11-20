package apiserver

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/inventory"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/registry"
	"github.com/the-it-dept/ffs/internal/web/apigen"
)

func TestUnresolvableGap_ClassifiesReasons(t *testing.T) {
	for reason, want := range map[string]apigen.GapCode{
		fmt.Sprintf(registry.ReasonUnauthorized, "r"):               apigen.GapCodeUnresolvableAuth,
		fmt.Sprintf(registry.ReasonNotFound, "r@d"):                 apigen.GapCodeUnresolvableNotfound,
		inventory.ReasonSideLoadedNoTag:                             apigen.GapCodeUnresolvableSideloaded,
		fmt.Sprintf(inventory.ReasonSideLoadedMismatch, "r", "1.0"): apigen.GapCodeUnresolvableSideloaded,
		fmt.Sprintf(inventory.ReasonUnreachable, "r", "dial"):       apigen.GapCodeUnresolvableUnreachable,
		"x": apigen.GapCodeUnresolvableOther,
		fmt.Sprintf(inventory.ReasonNoPlatform, "sha256:1", "linux/arm64"): apigen.GapCodeUnresolvableOther,
		inventory.ReasonLayersDiscarded:                                    apigen.GapCodeLayersDiscarded,
	} {
		require.Equal(t, want, unresolvableGap(reason), reason)
	}
}

func TestImageGaps_InOrder(t *testing.T) {
	require.Equal(t, []apigen.GapCode{apigen.GapCodePending}, imageGaps(model.Image{}, false, nil))
	require.Equal(t, []apigen.GapCode{apigen.GapCodePending}, imageGaps(model.Image{Status: model.ImagePending}, true, nil))
	require.Equal(t, []apigen.GapCode{apigen.GapCodeCatalogFailed}, imageGaps(model.Image{Status: model.ImageCatalogFailed}, true, nil))
	require.Equal(t, []apigen.GapCode{apigen.GapCodeUnresolvableAuth},
		imageGaps(model.Image{Status: model.ImageUnresolvable, StatusReason: fmt.Sprintf(registry.ReasonUnauthorized, "r")}, true, nil))
	require.Equal(t, []apigen.GapCode{}, imageGaps(model.Image{Status: model.ImageCatalogued, Source: "registry"}, true, nil))
	require.Equal(t, []apigen.GapCode{apigen.GapCodeAttestationPartial, apigen.GapCodeUnattributedExecutables,
		apigen.GapCodeRustNoAuditable, apigen.GapCodeCpeOnlyClassifier},
		imageGaps(model.Image{Status: model.ImageCatalogued, Source: "attestation",
			Coverage: model.Coverage{UnattributedELF: 1, RustWithoutAuditable: 2}}, true, []string{"traefik"}))
}
