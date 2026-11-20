package inventory

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/registry"
)

func TestClassifyUnresolvable(t *testing.T) {
	for reason, want := range map[string]model.UnresolvableClass{
		ReasonSideLoadedNoTag: model.UnresolvableSideLoaded,
		fmt.Sprintf(ReasonSideLoadedMismatch, "docker.io/library/app", "dev"):                         model.UnresolvableSideLoaded,
		fmt.Sprintf(registry.ReasonUnauthorized, "ghcr.io/acme/app"):                                  model.UnresolvableAuth,
		fmt.Sprintf(ReasonUnreachable, "registry.local:5000/app", "DNS lookup failed"):                model.UnresolvableUnreachable,
		fmt.Sprintf(registry.ReasonNotFound, "docker.io/library/app@sha256:"+strings.Repeat("1", 64)): model.UnresolvableNotFound,
		ReasonLayersDiscarded: model.UnresolvableLayersDiscarded,
		fmt.Sprintf(ReasonNoPlatform, "sha256:"+strings.Repeat("2", 64), "linux/arm64"): model.UnresolvableOther,
		fmt.Sprintf(ReasonUnparseable, "x"):                                             model.UnresolvableOther,
		"":                                                                              model.UnresolvableOther,
	} {
		assert.Equal(t, want, ClassifyUnresolvable(reason), reason)
	}
}
