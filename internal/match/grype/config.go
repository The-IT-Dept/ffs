package grype

import (
	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/distro"
	grypematch "github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/matcher/dotnet"
	"github.com/anchore/grype/grype/matcher/dpkg"
	"github.com/anchore/grype/grype/matcher/golang"
	"github.com/anchore/grype/grype/matcher/hex"
	"github.com/anchore/grype/grype/matcher/java"
	"github.com/anchore/grype/grype/matcher/javascript"
	"github.com/anchore/grype/grype/matcher/python"
	"github.com/anchore/grype/grype/matcher/rpm"
	"github.com/anchore/grype/grype/matcher/ruby"
	"github.com/anchore/grype/grype/matcher/rust"
	"github.com/anchore/grype/grype/matcher/stock"
	grypepkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	syftpkg "github.com/anchore/syft/syft/pkg"

	"github.com/the-it-dept/ffs/internal/match"
)

// The settings below are the grype v0.122.1 CLI defaults (cmd/grype/cli/options/match.go and
// cmd/grype/cli/commands/root.go), so ffs matches what `grype sbom:<file> --by-cve` reports.

// matcherConfig is the CLI's default matcher configuration: CPE matching only for the stock
// matcher, no Maven upstream lookups.
func matcherConfig() matcher.Config {
	return matcher.Config{
		Java:       java.MatcherConfig{ExternalSearchConfig: java.ExternalSearchConfig{SearchMavenUpstream: false}, UseCPEs: false},
		Ruby:       ruby.MatcherConfig{UseCPEs: false},
		Python:     python.MatcherConfig{UseCPEs: false},
		Dotnet:     dotnet.MatcherConfig{UseCPEs: false},
		Javascript: javascript.MatcherConfig{UseCPEs: false},
		Golang:     golang.MatcherConfig{UseCPEs: false, AlwaysUseCPEForStdlib: false, AllowMainModulePseudoVersionComparison: false},
		Rust:       rust.MatcherConfig{UseCPEs: false},
		Hex:        hex.MatcherConfig{UseCPEs: false},
		Stock:      stock.MatcherConfig{UseCPEs: true},
		Dpkg:       dpkg.MatcherConfig{MissingEpochStrategy: version.MissingEpochStrategyZero},
		Rpm:        rpm.MatcherConfig{MissingEpochStrategy: version.MissingEpochStrategyAuto},
	}
}

// ignoreRules are the CLI's default ignore rules: the kernel-header rules it adds unless
// --match-upstream-kernel-headers is set.
func ignoreRules() []grypematch.IgnoreRule {
	out := make([]grypematch.IgnoreRule, len(match.KernelHeaderRules))
	for i, r := range match.KernelHeaderRules {
		out[i] = grypematch.IgnoreRule{
			Package:   grypematch.IgnoreRulePackage{Name: r.Name, UpstreamName: r.UpstreamName, Type: r.Type},
			MatchType: grypematch.ExactIndirectMatch,
		}
	}
	return out
}

// providerConfig reads an SBOM the way `grype sbom:<file>` does: the SBOM's distro with the
// default fix channels, and no synthesised CPEs.
func providerConfig() grypepkg.ProviderConfig {
	return grypepkg.ProviderConfig{SynthesisConfig: grypepkg.SynthesisConfig{
		GenerateMissingCPEs: false,
		Distro:              grypepkg.DistroConfig{FixChannels: distro.DefaultFixChannels()},
	}}
}

// newVulnerabilityMatcher returns a matcher over vp. NormalizeByCVE is the CLI's --by-cve;
// IncludeMatcherSuppressions reports the matches grype's matchers suppressed (distro fixed or NAK
// records, file ownership overlap, its false-positive list) as ignored matches, which ffs records as
// not affected. There is no exclusion provider, VEX processor or fail severity, as for the CLI with
// no VEX documents and no --fail-on.
func newVulnerabilityMatcher(vp vulnerability.Provider) *grype.VulnerabilityMatcher {
	return &grype.VulnerabilityMatcher{
		VulnerabilityProvider:      vp,
		Matchers:                   matcher.NewDefaultMatchers(matcherConfig()),
		IgnoreRules:                ignoreRules(),
		NormalizeByCVE:             true,
		IncludeMatcherSuppressions: true,
	}
}

// cpeSearchTypes returns whether grype, configured as above, searches packages of a type by CPE:
// every type no default matcher claims goes to the stock matcher, which uses CPEs, and the apk
// matcher always adds NVD CPE results for the package and its origin package.
func cpeSearchTypes() func(syftpkg.Type) bool {
	claimed := map[syftpkg.Type]bool{}
	for _, m := range matcher.NewDefaultMatchers(matcherConfig()) {
		if m.Type() == grypematch.StockMatcher {
			continue
		}
		for _, t := range m.PackageTypes() {
			claimed[t] = true
		}
	}
	return func(t syftpkg.Type) bool { return !claimed[t] || t == syftpkg.ApkPkg }
}
