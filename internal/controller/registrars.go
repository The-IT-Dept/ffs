package controller

import (
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

// registrars add the output packages to the manager, in order, after the core components are wired.
var registrars = []deps.Registrar{
	crds.Register,
	events.Register,
	openreports.Register,
	func(m manager.Manager, d deps.Deps) error { return notify.Register(m, d, sinks.New) },
	upgrade.Register,
	web.Register,
	agentapi.Register,
}
