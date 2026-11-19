// Package priority evaluates the priority of a finding from its advisory and cluster context.
package priority

import (
	"fmt"
	"strings"
	"time"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/model"
)

// Input is everything the priority rules look at for one finding.
type Input struct {
	Severity         model.Severity
	SeverityPending  bool // no severity from any source yet
	FixAvailable     bool // a fixed package version exists
	FixState         model.FixState
	FixedVersions    []string // sorted, de-duplicated
	KEVAdded         *time.Time
	Malicious        bool
	EPSS             float64
	Exposed          bool
	ExposurePaths    []string
	Privileged       bool
	PrivilegeReasons []string
	PowerfulSA       bool
	SAReasons        []string
	NotRunning       bool
	GoStdlib         bool
	VEXNotAffected   bool
}

// Evaluate returns the priority of a finding and the facts that explain it.
func Evaluate(in Input, cfg config.PriorityConfig) (model.Priority, []string) {
	return rank(in, cfg), reasons(in, cfg)
}

func rank(in Input, cfg config.PriorityConfig) model.Priority {
	if in.Malicious {
		return model.PriorityUrgent
	}
	kev := in.KEVAdded != nil
	critical := in.Severity == model.SeverityCritical
	high := in.Severity == model.SeverityHigh

	p := model.PriorityLow
	switch {
	case kev || (critical && in.Exposed):
		p = model.PriorityUrgent
	case (critical && in.FixAvailable) ||
		(high && (in.Exposed || in.Privileged || in.PowerfulSA)) ||
		in.EPSS >= cfg.EPSSHigh:
		p = model.PriorityHigh
	case critical || high ||
		(in.Severity == model.SeverityMedium && in.Exposed && in.FixAvailable) ||
		in.SeverityPending:
		p = model.PriorityMedium
	}

	if !kev && (in.FixState == model.FixWontFix || in.FixState == model.FixNotAffected ||
		in.VEXNotAffected || in.Severity == model.SeverityNegligible) {
		return model.PriorityLow
	}
	if in.EPSS >= cfg.EPSSBump && p < model.PriorityHigh {
		p++
	}
	if in.GoStdlib && !kev && (!critical || !in.Exposed) && p > model.PriorityMedium {
		p = model.PriorityMedium
	}
	if in.NotRunning && p > model.PriorityLow {
		p--
	}
	return p
}

func reasons(in Input, cfg config.PriorityConfig) []string {
	var r []string
	if in.KEVAdded != nil {
		r = append(r, "actively exploited (CISA KEV, added "+in.KEVAdded.UTC().Format("2006-01-02")+")")
	}
	if in.Malicious {
		r = append(r, "malicious package")
	}
	switch {
	case in.Malicious && in.SeverityPending:
	case in.SeverityPending:
		r = append(r, "severity pending")
	default:
		r = append(r, in.Severity.String()+" severity")
	}
	if in.Exposed {
		if len(in.ExposurePaths) > 0 {
			r = append(r, "exposed via "+more(in.ExposurePaths[0], len(in.ExposurePaths)-1))
		} else {
			r = append(r, "exposed outside the cluster")
		}
	}
	if in.Privileged && len(in.PrivilegeReasons) > 0 {
		r = append(r, "privileged: "+more(in.PrivilegeReasons[0], len(in.PrivilegeReasons)-1))
	}
	if in.PowerfulSA && len(in.SAReasons) > 0 {
		r = append(r, more(in.SAReasons[0], len(in.SAReasons)-1))
	}
	switch {
	case in.VEXNotAffected || in.FixState == model.FixNotAffected:
		r = append(r, "not affected (VEX)")
	case in.FixState == model.FixWontFix:
		r = append(r, "won't fix upstream")
	case in.FixAvailable:
		v := in.FixedVersions
		if len(v) > 3 {
			v = v[:3]
		}
		r = append(r, "fix available: "+more(strings.Join(v, ", "), len(in.FixedVersions)-len(v)))
	default:
		r = append(r, "no fix available")
	}
	if in.EPSS >= cfg.EPSSBump {
		r = append(r, fmt.Sprintf("EPSS %.2f", in.EPSS))
	}
	if in.GoStdlib {
		r = append(r, "Go standard library")
	}
	if in.NotRunning {
		r = append(r, "not running")
	}
	return r
}

// more appends " (+n more)" when n is positive.
func more(s string, n int) string {
	if n > 0 {
		return fmt.Sprintf("%s (+%d more)", s, n)
	}
	return s
}
