package priority

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/model"
)

const (
	crit = model.SeverityCritical
	high = model.SeverityHigh
	med  = model.SeverityMedium
	low  = model.SeverityLow
	negl = model.SeverityNegligible
	unk  = model.SeverityUnknown

	pU = model.PriorityUrgent
	pH = model.PriorityHigh
	pM = model.PriorityMedium
	pL = model.PriorityLow
)

type opt func(*Input)

func in(sev model.Severity, opts ...opt) Input {
	i := Input{Severity: sev}
	for _, o := range opts {
		o(&i)
	}
	return i
}

func kev(i *Input)        { t := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC); i.KEVAdded = &t }
func mal(i *Input)        { i.Malicious = true }
func pend(i *Input)       { i.SeverityPending = true }
func exposed(i *Input)    { i.Exposed = true }
func priv(i *Input)       { i.Privileged = true }
func sa(i *Input)         { i.PowerfulSA = true }
func wontfix(i *Input)    { i.FixState = model.FixWontFix }
func vex(i *Input)        { i.VEXNotAffected = true }
func notRunning(i *Input) { i.NotRunning = true }
func stdlib(i *Input)     { i.GoStdlib = true }
func fix(v string) opt {
	return func(i *Input) {
		i.FixAvailable = true
		i.FixState = model.FixFixed
		i.FixedVersions = []string{v}
	}
}
func epss(x float64) opt { return func(i *Input) { i.EPSS = x } }

func TestEvaluate_Table(t *testing.T) {
	cfg := config.Default().Priority
	cases := []struct {
		name string
		in   Input
		want model.Priority
	}{
		{"kev", in(low, kev), pU},
		{"malicious", in(unk, pend, mal), pU},
		{"critical exposed", in(crit, exposed), pU},
		{"critical fix", in(crit, fix("1.2")), pH},
		{"critical no fix", in(crit), pM},
		{"high exposed", in(high, exposed), pH},
		{"high privileged", in(high, priv), pH},
		{"high powerful sa", in(high, sa), pH},
		{"high alone", in(high), pM},
		{"epss 0.5 on low", in(low, epss(0.5)), pH},
		{"medium exposed fix", in(med, exposed, fix("1.2")), pM},
		{"medium exposed no fix", in(med, exposed), pL},
		{"medium fix", in(med, fix("1.2")), pL},
		{"low", in(low), pL},
		{"pending", in(unk, pend), pM},
		{"critical exposed wont-fix", in(crit, exposed, wontfix), pL},
		{"kev wont-fix", in(crit, kev, wontfix), pU},
		{"critical fix vex", in(crit, fix("1.2"), vex), pL},
		{"negligible exposed fix", in(negl, exposed, fix("1.2")), pL},
		{"negligible epss 0.6", in(negl, epss(0.6)), pL},
		{"kev negligible", in(negl, kev), pU},
		{"critical fix not running", in(crit, fix("1.2"), notRunning), pM},
		{"kev not running", in(low, kev, notRunning), pH},
		{"low not running floor", in(low, notRunning), pL},
		{"medium epss bump", in(med, epss(0.2)), pM},
		{"high epss bump", in(high, epss(0.2)), pH},
		{"critical fix epss cap high", in(crit, fix("1.2"), epss(0.2)), pH},
		{"critical exposed epss stays urgent", in(crit, exposed, epss(0.2)), pU},
		{"stdlib critical fix capped", in(crit, fix("1.2"), stdlib), pM},
		{"stdlib critical exposed", in(crit, exposed, stdlib), pU},
		{"stdlib kev", in(low, kev, stdlib), pU},
		{"stdlib high exposed epss", in(high, exposed, epss(0.2), stdlib), pM},
		{"high epss not running", in(high, epss(0.2), notRunning), pM},
		{"stdlib critical fix not running", in(crit, fix("1.2"), stdlib, notRunning), pL},
		{"malicious ignores modifiers", in(unk, pend, mal, notRunning, wontfix), pU},
		{"pending epss bump", in(unk, pend, epss(0.2)), pH},
		{"pending stdlib epss", in(unk, pend, epss(0.2), stdlib), pM},
	}
	for _, c := range cases {
		if got, _ := Evaluate(c.in, cfg); got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
}

func TestEvaluate_Reasons(t *testing.T) {
	cfg := config.Default().Priority
	added := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	check := func(name string, got, want []string) {
		t.Helper()
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %q want %q", name, got, want)
		}
	}

	p, r := Evaluate(Input{Severity: model.SeverityCritical, FixAvailable: true, FixState: model.FixFixed,
		FixedVersions: []string{"8.3.16"}, KEVAdded: &added, EPSS: 0.63, Exposed: true,
		ExposurePaths: []string{"HTTPRoute web/api on Gateway public/edge", "Service web/api type LoadBalancer"}}, cfg)
	if p != pU {
		t.Errorf("priority: got %s want urgent", p)
	}
	check("full", r, []string{"actively exploited (CISA KEV, added 2026-11-02)", "critical severity",
		"exposed via HTTPRoute web/api on Gateway public/edge (+1 more)", "fix available: 8.3.16", "EPSS 0.63"})

	_, r = Evaluate(Input{Severity: model.SeverityCritical, Exposed: true}, cfg)
	if r[1] != "exposed outside the cluster" {
		t.Errorf("no paths: got %q", r)
	}

	_, r = Evaluate(Input{Severity: model.SeverityHigh, FixState: model.FixWontFix, GoStdlib: true, NotRunning: true}, cfg)
	check("wontfix", r, []string{"high severity", "won't fix upstream", "Go standard library", "not running"})

	_, r = Evaluate(Input{Malicious: true, SeverityPending: true}, cfg)
	check("malicious", r, []string{"malicious package", "no fix available"})

	_, r = Evaluate(Input{SeverityPending: true, FixAvailable: true, FixedVersions: []string{"1.2.4", "1.3.1", "2.0.1", "2.1.0"}}, cfg)
	check("pending", r, []string{"severity pending", "fix available: 1.2.4, 1.3.1, 2.0.1 (+1 more)"})

	_, r = Evaluate(Input{Severity: model.SeverityHigh, Privileged: true, PrivilegeReasons: []string{"privileged container"},
		PowerfulSA: true, SAReasons: []string{"service account can read secrets cluster-wide", "service account is bound to cluster-admin"},
		VEXNotAffected: true}, cfg)
	check("priv+sa", r, []string{"high severity", "privileged: privileged container",
		"service account can read secrets cluster-wide (+1 more)", "not affected (VEX)"})
}

func TestEvaluate_ConfigThresholds(t *testing.T) {
	cfg := config.PriorityConfig{EPSSHigh: 0.7, EPSSBump: 0.3}
	if p, _ := Evaluate(in(low, epss(0.6)), cfg); p != pM {
		t.Errorf("epss 0.6 on low: got %s want medium", p)
	}
	p, r := Evaluate(in(low, epss(0.2)), cfg)
	if p != pL {
		t.Errorf("epss 0.2 on low: got %s want low", p)
	}
	for _, s := range r {
		if len(s) >= 4 && s[:4] == "EPSS" {
			t.Errorf("unexpected EPSS reason %q", s)
		}
	}
}

func TestEvaluate_EPSSHysteresis(t *testing.T) {
	cfg := config.Default().Priority
	prev := func(p model.Priority) opt { return func(i *Input) { i.Previous = p } }
	cases := []struct {
		name string
		in   Input
		want model.Priority
	}{
		// the bump edge: 0.1 to enter, below 0.09 to leave
		{"new, just under the bump", in(low, epss(0.0999)), pL},
		{"new, at the bump", in(low, epss(0.1)), pM},
		{"low before, inside the band", in(low, epss(0.095), prev(pL)), pL},
		{"low before, at the bump", in(low, epss(0.1), prev(pL)), pM},
		{"bumped before, inside the band", in(low, epss(0.095), prev(pM)), pM},
		{"bumped before, at the leave edge", in(low, epss(0.09), prev(pM)), pM},
		{"bumped before, below the leave edge", in(low, epss(0.0899), prev(pM)), pL},
		// the high edge: 0.5 to enter, below 0.45 to leave
		{"new, just under high", in(low, epss(0.4999)), pM},
		{"new, at high", in(low, epss(0.5)), pH},
		{"medium before, inside the band", in(low, epss(0.47), prev(pM)), pM},
		{"medium before, at high", in(low, epss(0.5), prev(pM)), pH},
		{"high before, inside the band", in(low, epss(0.47), prev(pH)), pH},
		{"high before, at the leave edge", in(low, epss(0.45), prev(pH)), pH},
		{"high before, below the leave edge", in(low, epss(0.4499), prev(pH)), pM},
		// the band only keeps what EPSS gave: never above the leave edges' rank, nor above Previous
		{"urgent before (KEV removed), inside the band", in(low, epss(0.47), prev(pU)), pH},
		{"high before for another reason, EPSS below both bands", in(low, epss(0.05), prev(pH)), pL},
		{"not running, bumped before, inside the band", in(low, epss(0.095), notRunning, prev(pM)), pL},
		{"medium severity exposed with a fix, high before, inside the band", in(med, exposed, fix("1.2"), epss(0.47), prev(pH)), pH},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, reasons := Evaluate(c.in, cfg)
			if got != c.want {
				t.Fatalf("priority = %v, want %v", got, c.want)
			}
			held := c.in.Previous > rank(c.in, cfg) && got > rank(c.in, cfg)
			wantReason := c.in.EPSS >= cfg.EPSSBump || held
			hasReason := false
			for _, r := range reasons {
				hasReason = hasReason || strings.HasPrefix(r, "EPSS ")
			}
			if hasReason != wantReason {
				t.Fatalf("reasons %q: EPSS reason %v, want %v", reasons, hasReason, wantReason)
			}
		})
	}

	// the leave edges are 90% of the configured ones
	custom := config.PriorityConfig{EPSSHigh: 0.8, EPSSBump: 0.2}
	if got := Thresholds(in(low, epss(0.75), prev(pH)), custom); got != (config.PriorityConfig{EPSSHigh: 0.72, EPSSBump: 0.18}) {
		t.Fatalf("leave edges = %+v", got)
	}
	if got := Thresholds(in(low, epss(0.75)), custom); got != custom {
		t.Fatalf("a new finding enters at the configured edges, got %+v", got)
	}
}

// TestEPSSEdges_CoverEveryChange (W7): an EPSS feed queues a recompute only for a score that crosses
// one of EPSSEdges, so every score move that changes a stored finding's priority or EPSS signal must
// cross one: the leave edges too, or a finding held in the band keeps a priority the rules no longer
// give it until something else recomputes it.
func TestEPSSEdges_CoverEveryChange(t *testing.T) {
	cfg := config.Default().Priority
	if got, want := EPSSEdges(cfg), []float64{0.1, 0.5, 0.09, 0.45}; !reflect.DeepEqual(got, want) {
		t.Errorf("EPSSEdges = %v, want %v", got, want)
	}
	crossed := func(from, to float64) bool {
		for _, e := range EPSSEdges(cfg) {
			if (from < e) != (to < e) {
				return true
			}
		}
		return false
	}
	elevated := func(i Input) bool { return i.EPSS >= Thresholds(i, cfg).EPSSBump }
	scores := []float64{0, 0.05, 0.085, 0.0899, 0.09, 0.095, 0.0999, 0.1, 0.2, 0.44, 0.4499, 0.45, 0.47, 0.4999, 0.5, 0.9}
	inputs := []Input{in(low), in(med), in(high), in(crit), in(low, notRunning), in(med, exposed, fix("1.2")),
		in(high, priv), in(crit, fix("1.2")), in(low, pend), in(high, stdlib), in(low, wontfix)}
	for _, base := range inputs {
		for _, prev := range []model.Priority{model.PriorityNone, pL, pM, pH, pU} {
			for _, from := range scores {
				// The finding as stored at score from, after its own recompute settled.
				i := base
				i.EPSS, i.Previous = from, prev
				i.Previous, _ = Evaluate(i, cfg)
				stored, was := i.Previous, elevated(i)
				for _, to := range scores {
					i.EPSS = to
					now, _ := Evaluate(i, cfg)
					if (now != stored || elevated(i) != was) && !crossed(from, to) {
						t.Errorf("%+v, previous %v: EPSS %v -> %v moves priority %v -> %v (elevated %v -> %v) across no edge",
							base, prev, from, to, stored, now, was, elevated(i))
					}
				}
			}
		}
	}
	if !crossed(0.095, 0.085) || !crossed(0.47, 0.44) {
		t.Fatal("the leave edges are crossings")
	}
}
