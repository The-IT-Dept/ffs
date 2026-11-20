package model

import "slices"

// Signal is a value of the signals facet: a priority input, or a mark, a finding carries.
type Signal string

const (
	SignalExposed     Signal = "exposed"
	SignalPrivileged  Signal = "privileged"
	SignalSAPower     Signal = "sa_power"
	SignalExploited   Signal = "exploited" // listed in CISA KEV
	SignalMalicious   Signal = "malicious"
	SignalProvisional Signal = "provisional"
	SignalNotRunning  Signal = "not_running"
	SignalEPSS        Signal = "epss" // EPSS at or above the configured bump
)

// Signals lists every signal in bit order: a signal's bit in the read model's signals column is
// 1 << its index here.
var Signals = []Signal{SignalExposed, SignalPrivileged, SignalSAPower, SignalExploited, SignalMalicious,
	SignalProvisional, SignalNotRunning, SignalEPSS}

// Bit is the signal's bit in the read model's signals column, and 0 for an unknown signal.
func (s Signal) Bit() int64 {
	i := slices.Index(Signals, s)
	if i < 0 {
		return 0
	}
	return int64(1) << i
}

// ParseSignal returns the signal named s, and false when there is none.
func ParseSignal(s string) (Signal, bool) {
	if !slices.Contains(Signals, Signal(s)) {
		return "", false
	}
	return Signal(s), true
}

// SignalsOf returns the signals whose bit is set in bits, in Signals order; nil for 0.
func SignalsOf(bits int64) []Signal {
	var out []Signal
	for _, s := range Signals {
		if bits&s.Bit() != 0 {
			out = append(out, s)
		}
	}
	return out
}

// FindingSignals are the priority inputs a finding was ranked with (findings.Build copies them from the
// priority.Input it ranked the finding with), kept so the read model can filter on them.
type FindingSignals struct {
	Exposed, Privileged, PowerfulSA, NotRunning bool
	KEV, Malicious                              bool
	EPSSElevated                                bool // EPSS >= PriorityConfig.EPSSBump
	EPSS                                        float64
}

// SignalBits is the finding's value of the read model's signals column: the bit of every signal it
// carries, provisional included.
func (f Finding) SignalBits() int64 {
	var bits int64
	for _, s := range Signals {
		if f.hasSignal(s) {
			bits |= s.Bit()
		}
	}
	return bits
}

func (f Finding) hasSignal(s Signal) bool {
	switch s {
	case SignalExposed:
		return f.Signals.Exposed
	case SignalPrivileged:
		return f.Signals.Privileged
	case SignalSAPower:
		return f.Signals.PowerfulSA
	case SignalExploited:
		return f.Signals.KEV
	case SignalMalicious:
		return f.Signals.Malicious
	case SignalProvisional:
		return f.Provisional
	case SignalNotRunning:
		return f.Signals.NotRunning
	case SignalEPSS:
		return f.Signals.EPSSElevated
	}
	return false
}

// FixKind is the kind of action that clears a finding.
type FixKind string

const (
	FixKindUpgrade FixKind = "upgrade"
	FixKindRebuild FixKind = "rebuild"
	FixKindPackage FixKind = "package"
	FixKindNone    FixKind = "none"
	FixKindWontFix FixKind = "wontfix"
)

// Fix action copy.
const (
	FixLabelNone    = "No fix yet"
	FixLabelWontFix = "Won't fix"
	FixTitleRebuild = "Rebuild to pick up distro fixes" // the title of every rebuild action
)

// FixAction is how a finding is cleared (spec §11.1). Build never sets FixKindUpgrade: the store derives it from Suggestion.
type FixAction struct {
	Kind FixKind
	// Key is "rebuild:<distro id>:<version id>", "package:<ecosystem>:<name>:<from>:<to>", "none" or
	// "wontfix"; the store forms upgrade keys, "upgrade:<repo>:<toTag>".
	Key                          string
	Label                        string  // the action as shown
	Distro                       *Distro // rebuild
	Package, Ecosystem, From, To string  // package
}

// UpgradeAction is the action of moving the image to the suggested tag.
func UpgradeAction(sg Suggestion) FixAction {
	label := sg.FromTag + " → " + sg.ToTag
	if sg.Tier == TierRefresh {
		label = "Image refresh (" + sg.ToTag + ")"
	}
	return FixAction{Kind: FixKindUpgrade, Key: "upgrade:" + sg.Repo + ":" + sg.ToTag, Label: label}
}

// EffectiveFix is the action that clears the finding, in the precedence of the read model's fix_key
// and fix_class columns: the image-tag upgrade of its Suggestion (whose Repo is the finding's
// ImageRepo), else the action Build set, else won't fix or no fix yet by FixState.
func (f Finding) EffectiveFix() FixAction {
	switch {
	case f.Suggestion != nil:
		return UpgradeAction(*f.Suggestion)
	case f.Fix != nil:
		return *f.Fix
	case f.FixState == FixWontFix:
		return FixAction{Kind: FixKindWontFix, Key: "wontfix", Label: FixLabelWontFix}
	}
	return FixAction{Kind: FixKindNone, Key: "none", Label: FixLabelNone}
}

// FixClass is a value of the fix facet. The values are exclusive, in precedence order.
type FixClass string

const (
	FixClassUpgrade FixClass = "upgrade" // a Suggestion exists
	FixClassFixed   FixClass = "fixed"   // a fixed version exists, no Suggestion
	FixClassNone    FixClass = "none"
	FixClassWontFix FixClass = "wontfix"
)

// CoverageClass is how far ffs sees into an image.
type CoverageClass string

const (
	// CoverageFull: catalogued, not attestation-sourced, no unattributed executables and no Rust
	// without cargo-auditable (spec §11.7).
	CoverageFull CoverageClass = "full"
	// CoveragePartial: catalogued otherwise.
	CoveragePartial CoverageClass = "partial"
	// CoverageNone: pending, unresolvable, catalogFailed, or no images row.
	CoverageNone CoverageClass = "none"
)

// EntryKind is the kind of entry point an exposure edge starts from.
type EntryKind string

const (
	EntryGateway      EntryKind = "gateway"
	EntryIngress      EntryKind = "ingress"
	EntryLoadBalancer EntryKind = "loadbalancer"
	EntryNodePort     EntryKind = "nodeport"
	EntryExternalIP   EntryKind = "externalip"
	EntryHostNetwork  EntryKind = "hostnetwork"
	EntryHostPort     EntryKind = "hostport"
)

// ExposureEdge is one way in to a workload: an entry point and what it routes through.
type ExposureEdge struct {
	Entry EntryKind
	// EntryName is the Gateway "ns/name", the IngressClass name ("" = none), or the Service "ns/name"
	// for loadbalancer, nodeport and externalip; "" for the host kinds.
	EntryName string
	Listener  string // gateway: the parentRef sectionName ("" = every listener); hostport: "8080/TCP"; else ""
	Hostname  string // the route hostname or Ingress rule host; "" for none (the UI shows "*")
	Route     string // "HTTPRoute ns/name" (any route kind), "Ingress ns/name", or ""
	Service   string // "ns/name:port" when the route or rule names a port, "ns/name" otherwise; "" for the host kinds
	Internal  bool   // marked internal by config.exposure (gateway name or class, ingress class, LB annotation)
	Path      string // the exact WorkloadContext.ExposurePaths entry this edge yields; "" when Internal
}
