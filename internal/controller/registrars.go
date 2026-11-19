package controller

import (
	"github.com/the-it-dept/ffs/internal/controller/deps"
	"github.com/the-it-dept/ffs/internal/output/crds"
	"github.com/the-it-dept/ffs/internal/output/events"
)

// registrars add the output packages to the manager, in order, after the core components are wired.
var registrars = []deps.Registrar{crds.Register, events.Register}
