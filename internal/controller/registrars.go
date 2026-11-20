package controller

import (
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/the-it-dept/ffs/internal/agentapi"
	"github.com/the-it-dept/ffs/internal/controller/deps"
	"github.com/the-it-dept/ffs/internal/notify"
	"github.com/the-it-dept/ffs/internal/notify/sinks"
	"github.com/the-it-dept/ffs/internal/output/crds"
	"github.com/the-it-dept/ffs/internal/output/events"
	"github.com/the-it-dept/ffs/internal/output/openreports"
	"github.com/the-it-dept/ffs/internal/upgrade"
	"github.com/the-it-dept/ffs/internal/web"
)

// registrar is an output package's Registrar, under the package's name, which its errors carry.
type registrar struct {
	name string
	add  deps.Registrar
}

// registrars add the output packages to the manager, in order, after the core components are wired.
var registrars = []registrar{
	{"crds", crds.Register},
	{"events", events.Register},
	{"openreports", openreports.Register},
	{"notify", func(m manager.Manager, d deps.Deps) error { return notify.Register(m, d, sinks.New) }},
	{"upgrade", upgrade.Register},
	{"web", web.Register},
	{"agentapi", agentapi.Register},
}

// register runs rs in order and stops at the first error, which names the package that failed.
func register(m manager.Manager, d deps.Deps, rs []registrar) error {
	for _, r := range rs {
		if err := r.add(m, d); err != nil {
			return fmt.Errorf("register %s: %w", r.name, err)
		}
	}
	return nil
}
