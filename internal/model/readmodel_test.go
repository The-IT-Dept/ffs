package model

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSignal_BitsMatchReadModelColumn(t *testing.T) {
	for i, s := range Signals {
		require.Equal(t, int64(1)<<i, s.Bit(), s)
		p, ok := ParseSignal(string(s))
		require.True(t, ok)
		require.Equal(t, s, p)
	}
	require.Zero(t, Signal("kev").Bit())
	_, ok := ParseSignal("kev")
	require.False(t, ok)
	f := Finding{Provisional: true, Signals: FindingSignals{Exposed: true, KEV: true, EPSSElevated: true}}
	require.Equal(t, int64(1|8|32|128), f.SignalBits())
	require.Equal(t, []Signal{SignalExposed, SignalExploited, SignalProvisional, SignalEPSS}, SignalsOf(f.SignalBits()))
	require.Nil(t, SignalsOf(0))
}

func TestEffectiveFix_Precedence(t *testing.T) {
	sg := &Suggestion{Repo: "ghcr.io/example/web", FromTag: "1.2.3", ToTag: "1.2.4", Tier: TierPatch}
	rebuild := &FixAction{Kind: FixKindRebuild, Key: "rebuild:debian:12", Label: "debian 12 rebuild", Distro: &Distro{ID: "debian", VersionID: "12"}}
	require.Equal(t, FixAction{Kind: FixKindUpgrade, Key: "upgrade:ghcr.io/example/web:1.2.4", Label: "1.2.3 → 1.2.4"},
		Finding{ImageRepo: sg.Repo, Suggestion: sg, Fix: rebuild}.EffectiveFix())
	refresh := *sg
	refresh.FromTag, refresh.Tier = "1.2.4", TierRefresh
	require.Equal(t, FixAction{Kind: FixKindUpgrade, Key: "upgrade:ghcr.io/example/web:1.2.4", Label: "Image refresh (1.2.4)"},
		Finding{ImageRepo: sg.Repo, Suggestion: &refresh, Fix: rebuild}.EffectiveFix())
	require.Equal(t, *rebuild, Finding{Fix: rebuild}.EffectiveFix())
	require.Equal(t, FixAction{Kind: FixKindWontFix, Key: "wontfix", Label: "Won't fix"}, Finding{FixState: FixWontFix}.EffectiveFix())
	// a finding stored before Build set Fix: FixAvailable but no Fix → none
	require.Equal(t, FixAction{Kind: FixKindNone, Key: "none", Label: "No fix yet"}, Finding{FixAvailable: true}.EffectiveFix())
}
