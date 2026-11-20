package findings

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/model"
)

func maliciousAdv(a *model.Advisory) { a.Malicious = true }

func withEPSS(v float64) advOpt { return func(a *model.Advisory) { a.EPSS = v } }

func TestBuild_SignalsFromRankedInput(t *testing.T) {
	in := input([]model.Match{match(model.SourceGrype, lodashAmd, "CVE-2026-0001")},
		advisory("CVE-2026-0001", kev, maliciousAdv, withEPSS(0.2)))
	in.Owner.Context = model.WorkloadContext{Exposed: true, ExposurePaths: []string{"Ingress web/api"}, PowerfulSA: true, SAReasons: []string{"secrets: get"}}
	in.Owner.NotRunning = true
	in.Owner.Containers[0].RootUnlessImageUser, in.ImageUsers = true, map[string]string{amd: ""} // privileged only via ownerContext
	f := one(t, Build(in))
	require.Equal(t, model.FindingSignals{Exposed: true, Privileged: true, PowerfulSA: true, NotRunning: true, KEV: true,
		Malicious: true, EPSSElevated: true, EPSS: 0.2}, f.Signals)

	// EPSS against config.Default().Priority's bump, with the same >= rule as priority
	require.InDelta(t, 0.1, config.Default().Priority.EPSSBump, 0)
	for _, c := range []struct {
		epss     float64
		elevated bool
	}{{0.05, false}, {0.1, true}} {
		f := one(t, Build(input([]model.Match{match(model.SourceGrype, lodashAmd, "CVE-2026-0001")},
			advisory("CVE-2026-0001", withEPSS(c.epss)))))
		require.Equal(t, model.FindingSignals{EPSSElevated: c.elevated, EPSS: c.epss}, f.Signals, c.epss)
	}

	// carried: the stored Fix stands and the signals are ranked afresh
	stored := one(t, Build(input([]model.Match{match(model.SourceGrype, libssl3Amd, "CVE-2026-0002", fixedIn("3.0.15-1"))})))
	require.Zero(t, stored.Signals)
	require.Equal(t, &model.FixAction{Kind: model.FixKindRebuild, Key: "rebuild:debian:12", Label: "debian 12 rebuild", Distro: deb12}, stored.Fix)
	carry := input(nil, advisory("CVE-2026-0002", kev))
	carry.Carry = []model.Finding{stored}
	got := one(t, Build(carry))
	require.Equal(t, model.FindingSignals{KEV: true}, got.Signals)
	require.Equal(t, stored.Fix, got.Fix)

	// carried: a finding stored before Build set Fix gets one from what it stored
	pre := func(fp string, state model.FixState, available bool, p model.FindingPackage) model.Finding {
		return model.Finding{Fingerprint: fp, Owner: api().Ref, ImageRepo: phpRepo, AdvisoryID: "CVE-2026-0003", Packages: []model.FindingPackage{p},
			Digests: []string{amd}, FixState: state, FixAvailable: available, State: model.StateOpen}
	}
	lodash := model.FindingPackage{Name: "lodash", Ecosystem: "npm", Installed: "4.17.20", Fixed: []string{"4.17.21"}}
	libssl3 := model.FindingPackage{Name: "libssl3", Ecosystem: "deb", Installed: "3.0.13-1", Fixed: []string{"3.0.15-1"}}
	for _, c := range []struct {
		stored model.Finding
		want   *model.FixAction
	}{
		{pre("fp-lodash", model.FixFixed, true, lodash), &model.FixAction{Kind: model.FixKindPackage, Key: "package:npm:lodash:4.17.20:4.17.21",
			Label: "lodash 4.17.20 → 4.17.21", Package: "lodash", Ecosystem: "npm", From: "4.17.20", To: "4.17.21"}},
		{pre("fp-deb", model.FixFixed, true, libssl3), &model.FixAction{Kind: model.FixKindRebuild, Key: "rebuild::", Label: "Rebuild"}},
		{pre("fp-wontfix", model.FixWontFix, false, libssl3), &model.FixAction{Kind: model.FixKindWontFix, Key: "wontfix", Label: "Won't fix"}},
		{pre("fp-none", model.FixNotFixed, false, lodash), &model.FixAction{Kind: model.FixKindNone, Key: "none", Label: "No fix yet"}},
	} {
		require.Nil(t, c.stored.Fix)
		carry := input(nil, advisory("CVE-2026-0003"))
		carry.Carry = []model.Finding{c.stored}
		require.Equal(t, c.want, one(t, Build(carry)).Fix, c.stored.Fingerprint)
	}
}

func TestBuild_FixAction(t *testing.T) {
	requestsAmd := newPkg(amd, model.Package{Ecosystem: "python", Name: "requests", Version: "2.9.0", Path: "/usr/lib/python3/dist-packages/requests"})
	containerdAmd := newPkg(amd, model.Package{Ecosystem: "go-module", Name: "github.com/containerd/containerd", Version: "v1.7.17",
		Path: "/usr/local/bin/tool"})
	debTesting := &model.Distro{ID: "debian", Codename: "trixie"} // a testing release has no version ID
	libssl3Testing := newPkg(amd, model.Package{Ecosystem: "deb", Distro: debTesting, Name: "libssl3", Version: "3.0.13-1", Arch: "amd64",
		Path: "/var/lib/dpkg/status"})
	const id = "CVE-2026-0001"
	grype := func(p model.Package, opts ...matchOpt) model.Match { return match(model.SourceGrype, p, id, opts...) }
	lodashTo := func(to string) *model.FixAction {
		return &model.FixAction{Kind: model.FixKindPackage, Key: "package:npm:lodash:4.17.20:" + to, Label: "lodash 4.17.20 → " + to,
			Package: "lodash", Ecosystem: "npm", From: "4.17.20", To: to}
	}
	rebuild := &model.FixAction{Kind: model.FixKindRebuild, Key: "rebuild:debian:12", Label: "debian 12 rebuild", Distro: deb12}
	// A host finding is the Nodes owner's: a node has no image to rebuild, so an OS package gets the
	// package action (spec decision 16).
	nodes := model.Owner{Ref: model.NodesOwner("test"), Containers: []model.ContainerUse{{Name: "g1", Kind: model.ContainerRegular,
		ImageRef: "g1", Repo: model.HostRepo, Digest: amd}}}
	libssl3To := &model.FixAction{Kind: model.FixKindPackage, Key: "package:deb:libssl3:3.0.13-1:3.0.15-1",
		Label: "libssl3 3.0.13-1 → 3.0.15-1", Package: "libssl3", Ecosystem: "deb", From: "3.0.13-1", To: "3.0.15-1"}
	cases := []struct {
		name string
		ms   []model.Match
		want *model.FixAction
	}{
		{"won't fix", []model.Match{grype(libssl3Amd, wontFix)}, &model.FixAction{Kind: model.FixKindWontFix, Key: "wontfix", Label: "Won't fix"}},
		{"no fix", []model.Match{grype(libssl3Amd)}, &model.FixAction{Kind: model.FixKindNone, Key: "none", Label: "No fix yet"}},
		{"os package → rebuild", []model.Match{grype(libssl3Amd, fixedIn("3.0.15-1"))}, rebuild},
		{"os package wins over a language package", []model.Match{grype(libssl3Amd, fixedIn("3.0.15-1")), grype(lodashAmd, fixedIn("4.17.21"))},
			rebuild},
		{"smallest fixed above installed", []model.Match{grype(lodashAmd, fixedIn("4.17.19", "4.18.0", "4.17.21"))}, lodashTo("4.17.21")},
		{"PyPI order, not string order", []model.Match{grype(requestsAmd, fixedIn("2.10.0", "2.9.5"))},
			&model.FixAction{Kind: model.FixKindPackage, Key: "package:python:requests:2.9.0:2.9.5", Label: "requests 2.9.0 → 2.9.5",
				Package: "requests", Ecosystem: "python", From: "2.9.0", To: "2.9.5"}},
		{"binary falls back to semver", []model.Match{grype(phpAmd, fixedIn("8.3.100", "8.3.20"))},
			&model.FixAction{Kind: model.FixKindPackage, Key: "package:binary:php:8.3.14:8.3.20", Label: "php 8.3.14 → 8.3.20",
				Package: "php", Ecosystem: "binary", From: "8.3.14", To: "8.3.20"}},
		{"Go toolchain version compares without its go and moves to a go version", []model.Match{grype(stdlibAmd, fixedIn("1.21.11", "1.22.5"))},
			&model.FixAction{Kind: model.FixKindPackage, Key: "package:go-module:stdlib:go1.22.3:go1.22.5", Label: "stdlib go1.22.3 → go1.22.5",
				Package: "stdlib", Ecosystem: "go-module", From: "go1.22.3", To: "go1.22.5"}},
		{"Go module version keeps the fixed version's spelling", []model.Match{grype(containerdAmd, fixedIn("1.7.18", "1.7.20"))},
			&model.FixAction{Kind: model.FixKindPackage, Key: "package:go-module:github.com/containerd/containerd:v1.7.17:1.7.18",
				Label: "github.com/containerd/containerd v1.7.17 → 1.7.18", Package: "github.com/containerd/containerd", Ecosystem: "go-module",
				From: "v1.7.17", To: "1.7.18"}},
		{"distro without a version → rebuild with a single space", []model.Match{grype(libssl3Testing, fixedIn("3.0.15-1"))},
			&model.FixAction{Kind: model.FixKindRebuild, Key: "rebuild:debian:", Label: "debian rebuild", Distro: debTesting}},
		{"nothing above installed → smallest", []model.Match{grype(lodashAmd, fixedIn("4.17.19", "4.17.10"))}, lodashTo("4.17.10")},
		{"first package by name with a fixed version", []model.Match{grype(aesonAmd), grype(lodashAmd, fixedIn("4.17.21"))}, lodashTo("4.17.21")},
		{"fixed state without versions", []model.Match{grype(lodashAmd, func(m *model.Match) { m.FixState = model.FixFixed })},
			&model.FixAction{Kind: model.FixKindPackage, Key: "package:npm:lodash:4.17.20:", Label: "lodash 4.17.20 → fixed version",
				Package: "lodash", Ecosystem: "npm", From: "4.17.20"}},
	}
	for _, tc := range cases {
		in := input(tc.ms)
		for _, p := range []model.Package{requestsAmd, containerdAmd, libssl3Testing} {
			in.Packages[p.ID] = p
		}
		require.Equal(t, tc.want, one(t, Build(in)).Fix, tc.name)
	}

	hostCases := []struct {
		name string
		ms   []model.Match
		want *model.FixAction
	}{
		{"host finding: os package → package action, never a rebuild", []model.Match{grype(libssl3Amd, fixedIn("3.0.15-1"))}, libssl3To},
		{"host finding: the smallest Debian fixed version above installed",
			[]model.Match{grype(libssl3Amd, fixedIn("3.0.16-1", "3.0.15-1"))}, libssl3To},
		{"host finding: Debian order, where a tilde sorts first", []model.Match{grype(libssl3Amd, fixedIn("3.0.15-1", "3.0.15~rc1-1"))},
			&model.FixAction{Kind: model.FixKindPackage, Key: "package:deb:libssl3:3.0.13-1:3.0.15~rc1-1",
				Label: "libssl3 3.0.13-1 → 3.0.15~rc1-1", Package: "libssl3", Ecosystem: "deb", From: "3.0.13-1", To: "3.0.15~rc1-1"}},
	}
	for _, tc := range hostCases {
		in := input(tc.ms)
		in.Owner = nodes
		f := one(t, Build(in))
		require.Equal(t, model.HostRepo, f.ImageRepo, tc.name)
		require.Equal(t, tc.want, f.Fix, tc.name)
	}

	// A host finding stored before Build set Fix is carried with the package action too.
	stored := model.Finding{Fingerprint: "fp-host", Owner: nodes.Ref, ImageRepo: model.HostRepo, AdvisoryID: id, Digests: []string{amd},
		Packages: []model.FindingPackage{{Name: "libssl3", Ecosystem: "deb", Installed: "3.0.13-1", Fixed: []string{"3.0.16-1", "3.0.15-1"}}},
		FixState: model.FixFixed, FixAvailable: true, State: model.StateOpen}
	carry := input(nil)
	carry.Owner, carry.Carry = nodes, []model.Finding{stored}
	carry.Advisories[id] = advisory(id)
	require.Equal(t, libssl3To, one(t, Build(carry)).Fix)
}

func TestDiff_SignalsAndFixMakeNoTransition(t *testing.T) {
	stored := model.Finding{Fingerprint: "fp", Owner: api().Ref, ImageRepo: phpRepo, AdvisoryID: "CVE-2026-0001", State: model.StateOpen,
		Priority: model.PriorityHigh, FixState: model.FixFixed, FixAvailable: true, Digests: []string{amd}}
	require.Zero(t, stored.Signals)
	require.Nil(t, stored.Fix)
	built := stored
	built.Signals = model.FindingSignals{Exposed: true, EPSS: 0.3}
	built.Fix = &model.FixAction{Kind: model.FixKindRebuild, Key: "rebuild:debian:12", Label: "debian 12 rebuild", Distro: deb12}
	ups, ts := Diff([]model.Finding{stored}, []model.Finding{built}, Withdrawals{}, now, CauseInventory)
	require.Empty(t, ts)
	require.Len(t, ups, 1)
	require.Equal(t, built.Signals, ups[0].Signals)
	require.Equal(t, built.Fix, ups[0].Fix)
}
