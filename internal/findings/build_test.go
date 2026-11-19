package findings

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/model"
)

const (
	phpRepo   = "docker.io/library/php"
	amd       = "sha256:amd"
	arm       = "sha256:arm"
	k8sDigest = "k8s:1.31.2"
	ctrDigest = "runtime:containerd@1.7.20"
)

var (
	now   = time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	obs   = now.Add(-72 * time.Hour) // when ffs observed the OSV record behind an osv match
	deb12 = &model.Distro{ID: "debian", VersionID: "12", Codename: "bookworm"}

	libssl3Amd = newPkg(amd, model.Package{Ecosystem: "deb", Distro: deb12, Name: "libssl3", Version: "3.0.13-1", Arch: "amd64",
		SourceName: "openssl", SourceVersion: "3.0.13-1", Path: "/var/lib/dpkg/status"})
	libssl3Arm = newPkg(arm, model.Package{Ecosystem: "deb", Distro: deb12, Name: "libssl3", Version: "3.0.13-1", Arch: "arm64",
		SourceName: "openssl", SourceVersion: "3.0.13-1", Path: "/var/lib/dpkg/status"})
	opensslAmd = newPkg(amd, model.Package{Ecosystem: "deb", Distro: deb12, Name: "openssl", Version: "3.0.13-1", Arch: "amd64",
		SourceName: "openssl", SourceVersion: "3.0.13-1", Path: "/var/lib/dpkg/status"})
	phpAmd = newPkg(amd, model.Package{Ecosystem: "binary", Name: "php", Version: "8.3.14", Classifier: "php-cli-binary",
		Path: "/usr/local/bin/php"})
	stdlibAmd = newPkg(amd, model.Package{Ecosystem: "go-module", Name: "stdlib", Version: "go1.22.3", Path: "/usr/local/bin/tool",
		GoStdlib: true})
	lodashAmd = newPkg(amd, model.Package{Ecosystem: "npm", Name: "lodash", Version: "4.17.20",
		Path: "/app/node_modules/lodash/package.json"})
	aesonAmd   = newPkg(amd, model.Package{Ecosystem: "hackage", Name: "aeson", Version: "2.1.0.0", Path: "/opt/app/bin/server"})
	kubernetes = newPkg(k8sDigest, model.Package{Ecosystem: "kubernetes", Name: "kubernetes", Version: "1.31.2",
		Path: "control-plane; kubelet"})
	containerd = newPkg(ctrDigest, model.Package{Ecosystem: "go-module", Name: "github.com/containerd/containerd",
		Version: "v1.7.20", Path: "3 nodes"})

	allPkgs = []model.Package{libssl3Amd, libssl3Arm, opensslAmd, phpAmd, stdlibAmd, lodashAmd, aesonAmd, kubernetes, containerd}
)

func newPkg(digest string, p model.Package) model.Package {
	p.ImageDigest = digest
	p.ID = model.PackageID(digest, p)
	return p
}

func api() model.Owner {
	return model.Owner{
		Ref: model.OwnerRef{Kind: "Deployment", Namespace: "web", Name: "api", UID: "u1"},
		Containers: []model.ContainerUse{
			{Name: "php", Kind: model.ContainerRegular, Repo: phpRepo, Digest: amd, Platform: "linux/amd64"},
			{Name: "php", Kind: model.ContainerRegular, Repo: phpRepo, Digest: arm, Platform: "linux/arm64"},
		},
	}
}

func clusterOwner() model.Owner {
	return model.Owner{
		Ref:        model.OwnerRef{Kind: "Cluster", Name: "prod"},
		Containers: []model.ContainerUse{{Name: "kubernetes", Kind: model.ContainerRegular, Repo: "kubernetes", Digest: k8sDigest}},
	}
}

func runtimeOwner() model.Owner {
	return model.Owner{
		Ref:        model.OwnerRef{Kind: "ContainerRuntime", Name: "containerd"},
		Containers: []model.ContainerUse{{Name: "containerd", Kind: model.ContainerRegular, Repo: "containerd", Digest: ctrDigest}},
	}
}

type matchOpt func(*model.Match)

// match builds a not-fixed match observed at obs; grype matches come from a DB built an hour later.
func match(src model.MatchSource, p model.Package, advisoryID string, opts ...matchOpt) model.Match {
	m := model.Match{ImageDigest: p.ImageDigest, PackageID: p.ID, AdvisoryID: advisoryID, Source: src,
		FixState: model.FixNotFixed, ObservedAt: obs}
	if src == model.SourceGrype {
		m.DBBuilt = obs.Add(time.Hour)
	}
	for _, o := range opts {
		o(&m)
	}
	return m
}

func fixedIn(vs ...string) matchOpt {
	return func(m *model.Match) { m.FixState, m.FixedVersions = model.FixFixed, vs }
}
func notAffected(m *model.Match) { m.FixState = model.FixNotAffected }
func wontFix(m *model.Match)     { m.FixState = model.FixWontFix }
func vendor(s model.Severity, src string) matchOpt {
	return func(m *model.Match) { m.VendorSeverity, m.VendorSeveritySource = s, src }
}
func built(t time.Time) matchOpt    { return func(m *model.Match) { m.DBBuilt = t } }
func observed(t time.Time) matchOpt { return func(m *model.Match) { m.ObservedAt = t } }

type advOpt func(*model.Advisory)

func advisory(id string, opts ...advOpt) model.Advisory {
	a := model.Advisory{ID: id, Published: now.Add(-96 * time.Hour), Observed: obs}
	for _, o := range opts {
		o(&a)
	}
	return a
}

func cna(s model.Severity) advOpt { return func(a *model.Advisory) { a.CNASeverity = s } }
func kev(a *model.Advisory) {
	t := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	a.KEVAdded = &t
}

// input builds a BuildInput for api over ms; advisories not given get a plain one.
func input(ms []model.Match, advs ...model.Advisory) BuildInput {
	in := BuildInput{Cluster: "prod", Owner: api(), Matches: ms, Packages: map[string]model.Package{},
		Advisories: map[string]model.Advisory{}, Now: now, PriorityConfig: config.Default().Priority}
	for _, p := range allPkgs {
		in.Packages[p.ID] = p
	}
	for _, a := range advs {
		in.Advisories[a.ID] = a
	}
	for _, m := range ms {
		if _, ok := in.Advisories[m.AdvisoryID]; !ok {
			in.Advisories[m.AdvisoryID] = advisory(m.AdvisoryID)
		}
	}
	return in
}

func one(t *testing.T, fs []model.Finding) model.Finding {
	t.Helper()
	require.Len(t, fs, 1)
	return fs[0]
}

func byAdvisory(t *testing.T, fs []model.Finding, id string) model.Finding {
	t.Helper()
	for _, f := range fs {
		if f.AdvisoryID == id {
			return f
		}
	}
	t.Fatalf("no finding for %s", id)
	return model.Finding{}
}

func TestBuild_OneFindingPerOwnerRepoAdvisory(t *testing.T) {
	ms := []model.Match{
		match(model.SourceGrype, libssl3Amd, "CVE-2026-0001", fixedIn("3.0.15-1")),
		match(model.SourceGrype, libssl3Arm, "CVE-2026-0001", fixedIn("3.0.15-1")),
		match(model.SourceGrype, opensslAmd, "CVE-2026-0001", fixedIn("3.0.15-1")),
	}
	f := one(t, Build(input(ms)))
	assert.Equal(t, model.FindingFingerprint("prod", api().Ref, phpRepo, "CVE-2026-0001"), f.Fingerprint)
	assert.Equal(t, api().Ref, f.Owner)
	assert.Equal(t, phpRepo, f.ImageRepo)
	assert.Equal(t, "CVE-2026-0001", f.AdvisoryID)
	assert.Equal(t, model.StateOpen, f.State)
	assert.Equal(t, []string{amd, arm}, f.Digests)
	assert.Equal(t, []model.FindingPackage{
		{Name: "libssl3", Ecosystem: "deb", Installed: "3.0.13-1", Path: "/var/lib/dpkg/status", Fixed: []string{"3.0.15-1"}},
		{Name: "openssl", Ecosystem: "deb", Installed: "3.0.13-1", Path: "/var/lib/dpkg/status", Fixed: []string{"3.0.15-1"}},
	}, f.Packages)

	t.Run("each repo is its own finding", func(t *testing.T) {
		side := newPkg("sha256:side", model.Package{Ecosystem: "deb", Distro: deb12, Name: "libssl3", Version: "3.0.11-1",
			Path: "/var/lib/dpkg/status"})
		in := input(append(ms, match(model.SourceGrype, side, "CVE-2026-0001")))
		in.Packages[side.ID] = side
		in.Owner.Containers = append(in.Owner.Containers,
			model.ContainerUse{Name: "sidecar", Kind: model.ContainerSidecar, Repo: "ghcr.io/acme/sidecar", Digest: "sha256:side"})
		fs := Build(in)
		require.Len(t, fs, 2)
		assert.ElementsMatch(t, []string{
			model.FindingFingerprint("prod", api().Ref, phpRepo, "CVE-2026-0001"),
			model.FindingFingerprint("prod", api().Ref, "ghcr.io/acme/sidecar", "CVE-2026-0001"),
		}, []string{fs[0].Fingerprint, fs[1].Fingerprint})
		assert.Less(t, fs[0].Fingerprint, fs[1].Fingerprint)
	})

	t.Run("unknown digest or package is ignored", func(t *testing.T) {
		stray := newPkg("sha256:gone", model.Package{Ecosystem: "deb", Name: "zlib1g", Version: "1.2.13"})
		unknown := match(model.SourceGrype, libssl3Amd, "CVE-2026-0002")
		unknown.PackageID = "not-catalogued"
		in := input(append(ms, match(model.SourceGrype, stray, "CVE-2026-0003"), unknown))
		in.Packages[stray.ID] = stray
		assert.Equal(t, "CVE-2026-0001", one(t, Build(in)).AdvisoryID)
	})
}

func TestBuild_GrypeOpinionBeatsOSV(t *testing.T) {
	after, before := built(obs.Add(time.Hour)), built(obs.Add(-time.Hour))
	osvFix := fixedIn("3.0.14-1")
	ms := []model.Match{
		match(model.SourceGrype, libssl3Amd, "CVE-A", fixedIn("3.0.15-1"), vendor(model.SeverityMedium, "debian"), after),
		match(model.SourceOSV, libssl3Amd, "CVE-A", osvFix),
		match(model.SourceGrype, libssl3Amd, "CVE-B", notAffected, after),
		match(model.SourceOSV, libssl3Amd, "CVE-B", osvFix),
		match(model.SourceGrype, libssl3Amd, "CVE-C", notAffected, before),
		match(model.SourceOSV, libssl3Amd, "CVE-C", osvFix),
		match(model.SourceGrype, libssl3Amd, "CVE-D", fixedIn("3.0.15-1"), before),
		match(model.SourceOSV, libssl3Amd, "CVE-D", osvFix),
	}
	in := input(ms)
	in.GrypeDBBuilds = []time.Time{obs.Add(-time.Hour), obs.Add(time.Hour)}
	fs := Build(in)
	require.Len(t, fs, 3)

	a := byAdvisory(t, fs, "CVE-A")
	assert.Equal(t, []string{"3.0.15-1"}, a.Packages[0].Fixed)
	assert.Equal(t, model.SeverityMedium, a.Severity)
	assert.Equal(t, "debian", a.SeveritySource)
	assert.False(t, a.Provisional)

	for _, id := range []string{"CVE-C", "CVE-D"} {
		f := byAdvisory(t, fs, id)
		assert.True(t, f.Provisional, id)
		assert.Equal(t, []string{"3.0.14-1"}, f.Packages[0].Fixed, id)
	}
}

func TestBuild_MergesStandingMatches(t *testing.T) {
	// No grype opinion on CVE-E: the osv and k8s matches merge. On CVE-F grype's DB was built after
	// the earliest observation on the triple (the k8s match's), so grype wins.
	k8sEarly := observed(obs.Add(-time.Hour))
	ms := []model.Match{
		match(model.SourceOSV, libssl3Amd, "CVE-E", vendor(model.SeverityLow, "debian")),
		match(model.SourceK8s, libssl3Amd, "CVE-E", fixedIn("3.0.16-1"), vendor(model.SeverityCritical, "k8s"), k8sEarly),
		match(model.SourceOSV, libssl3Amd, "CVE-F", fixedIn("3.0.14-1")),
		match(model.SourceK8s, libssl3Amd, "CVE-F", k8sEarly),
		match(model.SourceGrype, libssl3Amd, "CVE-F", fixedIn("3.0.17-1"), built(obs.Add(-30*time.Minute))),
	}
	fs := Build(input(ms))

	e := byAdvisory(t, fs, "CVE-E")
	assert.Equal(t, []string{"3.0.16-1"}, e.Packages[0].Fixed)
	assert.Equal(t, model.FixFixed, e.FixState)
	assert.Equal(t, model.SeverityLow, e.Severity)
	assert.Equal(t, "debian", e.SeveritySource)
	assert.False(t, e.Provisional, "a non-OSV source on the triple is authoritative")

	assert.Equal(t, []string{"3.0.17-1"}, byAdvisory(t, fs, "CVE-F").Packages[0].Fixed)
}

func TestBuild_RunsAsRootFromImageUser(t *testing.T) {
	ms := []model.Match{
		match(model.SourceGrype, libssl3Amd, "CVE-R", fixedIn("3.0.15-1"), vendor(model.SeverityHigh, "debian")),
		match(model.SourceGrype, libssl3Arm, "CVE-S", fixedIn("3.0.15-1"), vendor(model.SeverityHigh, "debian")),
	}
	users := func(u string) map[string]string { return map[string]string{amd: u} }
	cases := []struct {
		name       string
		users      map[string]string
		asImage    bool // the amd container runs as the image's user
		privileged bool
	}{
		{"no user", users(""), true, true},
		{"uid 0", users("0"), true, true},
		{"root", users("root"), true, true},
		{"root:root", users("root:root"), true, true},
		{"0:0", users("0:0"), true, true},
		{"uid 65532", users("65532"), true, false},
		{"named user", users("nginx"), true, false},
		{"uid:gid", users("1000:1000"), true, false},
		{"not catalogued", nil, true, false},
		{"root image on another digest", map[string]string{arm: ""}, true, false},
		{"pod sets the user", users(""), false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := input(ms)
			in.Owner.Containers[0].RootUnlessImageUser = c.asImage
			in.ImageUsers = c.users
			fs := Build(in)
			require.Len(t, fs, 2)
			for _, f := range fs { // every finding of the owner, whichever digest it is on
				if c.privileged {
					assert.Contains(t, f.Reasons, "privileged: runs as root")
					assert.Equal(t, model.PriorityHigh, f.Priority)
				} else {
					assert.NotContains(t, f.Reasons, "privileged: runs as root")
					assert.Equal(t, model.PriorityMedium, f.Priority)
				}
			}
		})
	}

	t.Run("reason appears once", func(t *testing.T) {
		in := input(ms)
		in.Owner.Containers[0].RootUnlessImageUser = true
		in.Owner.Context = model.WorkloadContext{Privileged: true, PrivilegeReasons: []string{"runs as root"}}
		in.ImageUsers = users("")
		assert.Contains(t, Build(in)[0].Reasons, "privileged: runs as root")
	})

	t.Run("merged with other reasons", func(t *testing.T) {
		in := input(ms)
		in.Owner.Containers[0].RootUnlessImageUser = true
		in.Owner.Context = model.WorkloadContext{Privileged: true, PrivilegeReasons: []string{"hostPath volume /var/run"}}
		in.ImageUsers = users("")
		assert.Contains(t, Build(in)[0].Reasons, "privileged: hostPath volume /var/run (+1 more)")
	})
}

func TestBuild_Provisional(t *testing.T) {
	hour := time.Hour
	osvDeb := []model.Match{match(model.SourceOSV, libssl3Amd, "CVE-P")}
	cases := []struct {
		name   string
		ms     []model.Match
		builds []time.Time
		owner  func() model.Owner
		want   bool
	}{
		{"osv deb, no builds", osvDeb, nil, nil, true},
		{"one build after", osvDeb, []time.Time{obs.Add(hour)}, nil, true},
		{"one before, one after", osvDeb, []time.Time{obs.Add(-hour), obs.Add(hour)}, nil, true},
		{"two builds after", osvDeb, []time.Time{obs.Add(hour), obs.Add(25 * hour)}, nil, false},
		{"type grype does not cover", []model.Match{match(model.SourceOSV, aesonAmd, "CVE-P")}, nil, nil, false},
		{"upstream runtime", []model.Match{match(model.SourceUpstream, phpAmd, "CVE-P")}, nil, nil, false},
		{"go stdlib", []model.Match{match(model.SourceOSV, stdlibAmd, "CVE-P")}, nil, nil, false},
		{"kubernetes source", []model.Match{match(model.SourceK8s, containerd, "CVE-P")}, nil, runtimeOwner, false},
		{"grype built after observation", append(osvDeb, match(model.SourceGrype, libssl3Amd, "CVE-P")), nil, nil, false},
		{"grype built before observation", append(osvDeb, match(model.SourceGrype, libssl3Amd, "CVE-P", built(obs.Add(-hour)))),
			[]time.Time{obs.Add(-hour)}, nil, true},
		{"one standing match is not provisional", append(osvDeb, match(model.SourceGrype, opensslAmd, "CVE-P")), nil, nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := input(c.ms)
			in.GrypeDBBuilds = c.builds
			if c.owner != nil {
				in.Owner = c.owner()
			}
			assert.Equal(t, c.want, one(t, Build(in)).Provisional)
		})
	}
}

func TestBuild_SeveritySelection(t *testing.T) {
	cases := []struct {
		name    string
		ms      []model.Match
		cna     model.Severity
		owner   func() model.Owner
		want    model.Severity
		wantSrc string
	}{
		{"distro rating beats CNA", []model.Match{match(model.SourceGrype, libssl3Amd, "CVE-V",
			vendor(model.SeverityHigh, "debian"))}, model.SeverityCritical, nil, model.SeverityHigh, "debian"},
		{"no distro rating", []model.Match{match(model.SourceGrype, libssl3Amd, "CVE-V")},
			model.SeverityCritical, nil, model.SeverityCritical, "cna"},
		{"language package", []model.Match{match(model.SourceOSV, lodashAmd, "CVE-V", vendor(model.SeverityHigh, "ghsa"))},
			model.SeverityMedium, nil, model.SeverityHigh, "ghsa"},
		{"upstream runtime uses CNA only", []model.Match{match(model.SourceUpstream, phpAmd, "CVE-V",
			vendor(model.SeverityCritical, "php"))}, model.SeverityHigh, nil, model.SeverityHigh, "cna"},
		{"highest vendor rating across packages", []model.Match{
			match(model.SourceGrype, libssl3Amd, "CVE-V", vendor(model.SeverityMedium, "debian")),
			match(model.SourceGrype, opensslAmd, "CVE-V", vendor(model.SeverityHigh, "debian")),
		}, model.SeverityLow, nil, model.SeverityHigh, "debian"},
		{"negligible distro rating stays", []model.Match{match(model.SourceGrype, libssl3Amd, "CVE-V",
			vendor(model.SeverityNegligible, "debian"))}, model.SeverityCritical, nil, model.SeverityNegligible, "debian"},
		{"NVD after CNA", []model.Match{match(model.SourceGrype, phpAmd, "CVE-V", vendor(model.SeverityHigh, "nvd"))},
			model.SeverityMedium, nil, model.SeverityMedium, "cna"},
		{"NVD without CNA", []model.Match{match(model.SourceGrype, phpAmd, "CVE-V", vendor(model.SeverityHigh, "nvd"))},
			model.SeverityUnknown, nil, model.SeverityHigh, "nvd"},
		{"kubernetes without CNA", []model.Match{match(model.SourceK8s, kubernetes, "CVE-V")},
			model.SeverityUnknown, clusterOwner, model.SeverityUnknown, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := input(c.ms, advisory("CVE-V", cna(c.cna)))
			if c.owner != nil {
				in.Owner = c.owner()
			}
			f := one(t, Build(in))
			assert.Equal(t, c.want, f.Severity)
			assert.Equal(t, c.wantSrc, f.SeveritySource)
			switch c.want {
			case model.SeverityUnknown:
				assert.Equal(t, model.PriorityMedium, f.Priority)
				assert.Equal(t, "severity pending", f.Reasons[0])
			case model.SeverityNegligible:
				assert.Equal(t, model.PriorityLow, f.Priority)
			}
		})
	}
}

func TestBuild_PriorityInputs(t *testing.T) {
	t.Run("exposure and KEV", func(t *testing.T) {
		in := input([]model.Match{match(model.SourceGrype, libssl3Amd, "CVE-X", vendor(model.SeverityMedium, "debian"))},
			advisory("CVE-X", kev))
		in.Owner.Context = model.WorkloadContext{Exposed: true,
			ExposurePaths: []string{"HTTPRoute web/api on Gateway public/edge"}}
		f := one(t, Build(in))
		assert.Equal(t, model.PriorityUrgent, f.Priority)
		assert.Equal(t, "actively exploited (CISA KEV, added 2026-11-02)", f.Reasons[0])
		assert.Contains(t, f.Reasons, "exposed via HTTPRoute web/api on Gateway public/edge")
	})

	t.Run("fix state", func(t *testing.T) {
		cases := []struct {
			name         string
			ms           []model.Match
			want         model.FixState
			fixAvailable bool
		}{
			{"one fixed, one wont-fix", []model.Match{
				match(model.SourceGrype, libssl3Amd, "CVE-X", fixedIn("3.0.15-1")),
				match(model.SourceGrype, opensslAmd, "CVE-X", wontFix),
			}, model.FixFixed, true},
			{"all wont-fix", []model.Match{
				match(model.SourceGrype, libssl3Amd, "CVE-X", wontFix),
				match(model.SourceGrype, opensslAmd, "CVE-X", wontFix),
			}, model.FixWontFix, false},
			{"not-fixed and wont-fix", []model.Match{
				match(model.SourceGrype, libssl3Amd, "CVE-X"),
				match(model.SourceGrype, opensslAmd, "CVE-X", wontFix),
			}, model.FixNotFixed, false},
			{"unknown", []model.Match{match(model.SourceGrype, libssl3Amd, "CVE-X", func(m *model.Match) {
				m.FixState = model.FixUnknown
			})}, model.FixUnknown, false},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				f := one(t, Build(input(c.ms)))
				assert.Equal(t, c.want, f.FixState)
				assert.Equal(t, c.fixAvailable, f.FixAvailable)
			})
		}
	})

	t.Run("go stdlib and not running", func(t *testing.T) {
		in := input([]model.Match{match(model.SourceOSV, stdlibAmd, "CVE-X", fixedIn("1.22.5"))})
		in.Owner.NotRunning = true
		f := one(t, Build(in))
		assert.True(t, f.GoStdlib)
		assert.Contains(t, f.Reasons, "Go standard library")
		assert.Contains(t, f.Reasons, "not running")

		mixed := one(t, Build(input([]model.Match{
			match(model.SourceOSV, stdlibAmd, "CVE-X"),
			match(model.SourceGrype, libssl3Amd, "CVE-X"),
		})))
		assert.False(t, mixed.GoStdlib)
	})

	t.Run("timestamps", func(t *testing.T) {
		a := advisory("CVE-X")
		a.Published = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
		a.Observed = time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
		f := one(t, Build(input([]model.Match{match(model.SourceGrype, libssl3Amd, "CVE-X")}, a)))
		assert.Equal(t, a.Published, f.Published)
		assert.Equal(t, a.Observed, f.Observed)
		assert.Equal(t, now, f.Matched)
		assert.Equal(t, now, f.LastSeen)
		assert.Nil(t, f.ResolvedAt)
	})

	t.Run("installed version carries the epoch", func(t *testing.T) {
		rpm := newPkg(amd, model.Package{Ecosystem: "rpm", Name: "openssl-libs", Version: "3.0.7-27.el9", Epoch: "1"})
		deb := newPkg(amd, model.Package{Ecosystem: "deb", Name: "libc6", Version: "1:2.36-9", Epoch: "1"})
		in := input([]model.Match{match(model.SourceGrype, rpm, "CVE-X"), match(model.SourceGrype, deb, "CVE-X")})
		in.Packages[rpm.ID], in.Packages[deb.ID] = rpm, deb
		f := one(t, Build(in))
		assert.Equal(t, []string{"1:2.36-9", "1:3.0.7-27.el9"}, []string{f.Packages[0].Installed, f.Packages[1].Installed})
	})
}

// TestBuild_WithdrawnAdvisoryIgnored covers a REJECTED CVE (cvelistV5), the only source of
// Advisory.Withdrawn.
func TestBuild_WithdrawnAdvisoryIgnored(t *testing.T) {
	gone := advisory("CVE-W")
	gone.Withdrawn = true
	in := input([]model.Match{
		match(model.SourceOSV, libssl3Amd, "CVE-W"),
		match(model.SourceGrype, libssl3Amd, "CVE-2026-0001"),
	}, gone)
	assert.Equal(t, "CVE-2026-0001", one(t, Build(in)).AdvisoryID)
}
