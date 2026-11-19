package notify

import (
	"time"
	_ "time/tzdata" // the distroless image has no zoneinfo; digest schedules and quiet hours need IANA zones

	"github.com/robfig/cron/v3"

	"github.com/the-it-dept/ffs/internal/model"
)

// DigestConfig is a target's digest: a standard 5-field cron Schedule read in Location (UTC when
// nil), the lowest priority listed as new or escalated, and whether resolved findings are listed.
type DigestConfig struct {
	Schedule        string
	Location        *time.Location
	MinPriority     model.Priority
	IncludeResolved bool
}

// TargetConfig is one AlertTarget as the engine sees it. UID keys all stored state; ConfigHash
// changes when the spec or the endpoint changes, which re-enables a disabled target.
type TargetConfig struct {
	UID, Name, Type, ConfigHash string
	ImmediateMin                model.Priority
	Digest                      DigestConfig
	// NamespaceMatch limits the target to some namespaces; nil means all of them. Cluster-level
	// subjects (Namespace "") pass only when it is nil.
	NamespaceMatch          func(ns string) bool
	QuietHours              []TimeInterval
	AllowUrgentInQuietHours bool
	NotifyOnFeedStale       bool
	Paused                  bool
}

// allows reports whether the target covers findings in namespace ns.
func (c TargetConfig) allows(ns string) bool {
	return c.NamespaceMatch == nil || (ns != "" && c.NamespaceMatch(ns))
}

// target is a registered target: its config, sink and parsed digest schedule.
type target struct {
	cfg   TargetConfig
	sink  Sink
	sched cron.Schedule
}

// The spec's AlertTarget defaults (§6.8), for fields left at their zero value.
const (
	defaultImmediateMin = model.PriorityUrgent
	defaultDigestMin    = model.PriorityMedium
)
