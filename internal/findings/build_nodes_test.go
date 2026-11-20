package findings

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

var (
	grpA = "nodegroup:" + strings.Repeat("a", 64)
	grpB = "nodegroup:" + strings.Repeat("b", 64)

	nodesRef = model.NodesOwner("prod")
	ubuntu   = &model.Distro{ID: "ubuntu", VersionID: "26.04"}
	hostA    = newPkg(grpA, model.Package{Ecosystem: "deb", Distro: ubuntu, Name: "libssl3t64", Version: "3.0.13-0ubuntu3.4",
		Arch: "amd64", SourceName: "openssl", Path: "/var/lib/dpkg/status"})
	hostB = newPkg(grpB, model.Package{Ecosystem: "deb", Distro: ubuntu, Name: "libssl3t64", Version: "3.0.13-0ubuntu3.5",
		Arch: "amd64", SourceName: "openssl", Path: "/var/lib/dpkg/status"})
	k8sMod = newPkg(grpA, model.Package{Ecosystem: "go-module", Name: "k8s.io/kubernetes", Version: "v1.35.2", Path: "/usr/local/bin/k3s"})
	ctrMod = newPkg(grpA, model.Package{Ecosystem: "go-module", Name: "github.com/containerd/containerd/v2", Version: "v2.1.4",
		Path: "/usr/local/bin/k3s"})
	k8sBin = newPkg(grpA, model.Package{Ecosystem: "binary", Name: "k8s.io/kubernetes", Version: "1.35.2", Path: "/usr/bin/kubelet"})
)

// nodesOwner: group A (exposed via edge-1) and group B (not exposed). The owner-level context is set on
// purpose; Build must ignore it for Nodes.
func nodesOwner() model.Owner {
	return model.Owner{Ref: nodesRef,
		Context: model.WorkloadContext{Exposed: true, ExposurePaths: []string{"owner-level path"}, Privileged: true,
			PrivilegeReasons: []string{"hostPath /"}, PowerfulSA: true, SAReasons: []string{"can read every Secret"}},
		Containers: []model.ContainerUse{
			{Name: "ubuntu-26.04-k7.0.0-34-aaaaaa", Kind: model.ContainerRegular, ImageRef: "ubuntu-26.04-k7.0.0-34-aaaaaa",
				Repo: model.HostRepo, Digest: grpA, Platform: "linux/amd64", ExposurePaths: []string{"node edge-1"}},
			{Name: "ubuntu-26.04-k7.0.0-38-bbbbbb", Kind: model.ContainerRegular, ImageRef: "ubuntu-26.04-k7.0.0-38-bbbbbb",
				Repo: model.HostRepo, Digest: grpB, Platform: "linux/amd64"},
		}}
}

// addPkgs makes ps known to in.
func addPkgs(in *BuildInput, ps ...model.Package) {
	for _, p := range ps {
		in.Packages[p.ID] = p
	}
}

// exposed reports whether any of f's reasons is an exposure reason.
func exposed(f model.Finding) bool {
	return slices.ContainsFunc(f.Reasons, func(r string) bool { return strings.HasPrefix(r, "exposed") })
}

func TestBuild_NodesFindingSpansGroups(t *testing.T) { // Review Focus 2
	in := input([]model.Match{
		match(model.SourceGrype, hostA, "CVE-2026-0001", fixedIn("3.0.13-0ubuntu3.6")),
		match(model.SourceGrype, hostB, "CVE-2026-0001", fixedIn("3.0.13-0ubuntu3.6")),
		match(model.SourceGrype, hostB, "CVE-2026-0002", fixedIn("3.0.13-0ubuntu3.6")),
	})
	in.Owner = nodesOwner()
	addPkgs(&in, hostA, hostB)
	fs := Build(in)
	require.Len(t, fs, 2)

	f := byAdvisory(t, fs, "CVE-2026-0001")
	assert.Equal(t, model.FindingFingerprint("prod", nodesRef, model.HostRepo, "CVE-2026-0001"), f.Fingerprint)
	assert.Equal(t, model.HostRepo, f.ImageRepo)
	assert.Equal(t, []string{grpA, grpB}, f.Digests)
	assert.Equal(t, []string{"3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.5"},
		[]string{f.Packages[0].Installed, f.Packages[1].Installed}) // both groups' installed versions
	assert.Contains(t, f.Reasons, "exposed via node edge-1")
	for _, r := range f.Reasons {
		assert.NotContains(t, r, "privileged")
		assert.NotContains(t, r, "Secret")
		assert.NotContains(t, r, "owner-level")
	}

	g := byAdvisory(t, fs, "CVE-2026-0002") // group B only: not exposed
	assert.Equal(t, []string{grpB}, g.Digests)
	assert.False(t, exposed(g))
}

func TestBuild_NodesCarriedFindingUsesItsOwnDigests(t *testing.T) {
	carry := func(advisoryID, digest string) model.Finding {
		return model.Finding{Fingerprint: model.FindingFingerprint("prod", nodesRef, model.HostRepo, advisoryID), Owner: nodesRef,
			ImageRepo: model.HostRepo, AdvisoryID: advisoryID, Digests: []string{digest}, State: model.StateOpen,
			Packages: []model.FindingPackage{{Name: "libssl3t64", Ecosystem: "deb", Installed: "3.0.13-0ubuntu3.4",
				Path: "/var/lib/dpkg/status", Fixed: []string{"3.0.13-0ubuntu3.6"}}},
			FixState: model.FixFixed, FixAvailable: true, Severity: model.SeverityHigh, SeveritySource: "ubuntu",
			Matched: now.Add(-time.Hour), LastSeen: now.Add(-time.Hour)}
	}
	in := input(nil, advisory("CVE-2026-0001"), advisory("CVE-2026-0002"))
	in.Owner = nodesOwner()
	in.Carry = []model.Finding{carry("CVE-2026-0001", grpA), carry("CVE-2026-0002", grpB)}
	fs := Build(in)
	require.Len(t, fs, 2)
	a := byAdvisory(t, fs, "CVE-2026-0001")
	assert.Contains(t, a.Reasons, "exposed via node edge-1")
	b := byAdvisory(t, fs, "CVE-2026-0002")
	assert.False(t, exposed(b))
	for _, f := range fs {
		for _, r := range f.Reasons {
			assert.NotContains(t, r, "privileged")
			assert.NotContains(t, r, "owner-level")
		}
	}
}

func TestBuild_SuppressModulesDropsGoModulesOnly(t *testing.T) {
	ms := []model.Match{
		match(model.SourceGrype, k8sMod, "CVE-2026-0003", fixedIn("v1.35.3")),
		match(model.SourceGrype, ctrMod, "CVE-2026-0004", fixedIn("v2.1.5")),
		match(model.SourceGrype, k8sBin, "CVE-2026-0005", fixedIn("1.35.3")),
	}
	advisories := func(fs []model.Finding) []string {
		var ids []string
		for _, f := range fs {
			ids = append(ids, f.AdvisoryID)
		}
		slices.Sort(ids)
		return ids
	}
	in := input(ms)
	in.Owner = nodesOwner()
	in.Owner.SuppressModules = []string{"k8s.io/kubernetes"}
	addPkgs(&in, k8sMod, ctrMod, k8sBin)
	res := BuildResult(in)
	assert.Equal(t, []string{"CVE-2026-0004", "CVE-2026-0005"}, advisories(res.Findings),
		"the k8s.io/kubernetes Go module is suppressed; the binary package of that name is not")
	assert.Empty(t, res.NotAffected)

	// The same matches on an owner that suppresses nothing build all three.
	in = input(ms)
	in.Owner = api()
	in.Owner.Containers = append(in.Owner.Containers,
		model.ContainerUse{Name: "host", Kind: model.ContainerRegular, Repo: phpRepo, Digest: grpA, Platform: "linux/amd64"})
	addPkgs(&in, k8sMod, ctrMod, k8sBin)
	require.Nil(t, in.Owner.SuppressModules)
	assert.Equal(t, []string{"CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005"}, advisories(Build(in)))
}

func TestBuild_RuntimeExceptionFollowsRehome(t *testing.T) {
	ms := []model.Match{
		match(model.SourceGrype, ctrMod, "CVE-2026-0004", fixedIn("v2.1.5")),
		match(model.SourceGrype, hostA, "CVE-2026-0001", fixedIn("3.0.13-0ubuntu3.6")),
	}
	expires := now.Add(time.Hour)
	for name, rule := range map[string]ExceptionRule{
		"owner": {Namespace: "ffs", Name: "runtime-owner", ClusterWide: true, Owners: []string{"ContainerRuntime/containerd"}, Expires: expires},
		"repo":  {Namespace: "ffs", Name: "runtime-repo", ClusterWide: true, ImageRepoGlobs: []string{"containerd"}, Expires: expires},
	} {
		in := input(ms)
		in.Owner = nodesOwner()
		addPkgs(&in, ctrMod, hostA)
		in.Exceptions = []ExceptionRule{rule}
		fs := Build(in)
		ctr := byAdvisory(t, fs, "CVE-2026-0004")
		assert.Equal(t, model.StateExcepted, ctr.State, name)
		assert.Equal(t, rule.Key(), ctr.ExceptedBy, name)
		assert.Equal(t, nodesRef, ctr.Owner, name)
		assert.Equal(t, model.HostRepo, ctr.ImageRepo, name)
		host := byAdvisory(t, fs, "CVE-2026-0001")
		assert.Equal(t, model.StateOpen, host.State, name)
		assert.Empty(t, host.ExceptedBy, name)
	}

	// A rule written for the Nodes owner applies to the same finding while it is a ContainerRuntime finding.
	in := input([]model.Match{match(model.SourceGrype, ctrMod, "CVE-2026-0004", fixedIn("v2.1.5"))})
	in.Owner = model.Owner{Ref: model.OwnerRef{Kind: model.OwnerKindContainerRuntime, Name: "containerd"},
		Containers: []model.ContainerUse{{Name: "containerd", Kind: model.ContainerRegular, Repo: "containerd", Digest: ctrMod.ImageDigest}}}
	addPkgs(&in, ctrMod)
	nodesRule := ExceptionRule{Namespace: "ffs", Name: "nodes", ClusterWide: true, Owners: []string{"Nodes/prod"}, Expires: expires}
	in.Exceptions = []ExceptionRule{nodesRule}
	f := one(t, Build(in))
	assert.Equal(t, model.StateExcepted, f.State)
	assert.Equal(t, nodesRule.Key(), f.ExceptedBy)
	assert.Equal(t, "containerd", f.ImageRepo)
}

// TestException_BareNameNeverMatchesClusterLevel: the Nodes and Cluster owners are both named after the
// cluster, so a bare owner entry naming the cluster must not except Cluster, Nodes or ContainerRuntime
// findings, directly or through the runtime cutover alias. Only the Kind/Name form names them.
func TestException_BareNameNeverMatchesClusterLevel(t *testing.T) {
	expires := now.Add(time.Hour)
	rule := func(owners ...string) ExceptionRule {
		return ExceptionRule{Namespace: "ffs", Name: "accept", ClusterWide: true, Owners: owners, Expires: expires}
	}
	// Each case builds one finding: on the Nodes owner (a host package, and a containerd module whose
	// alias is ContainerRuntime/containerd), on the Cluster owner, and on the ContainerRuntime owner
	// (whose alias is Nodes/prod).
	builds := map[string]func(rules ...ExceptionRule) model.Finding{
		"Nodes host package": func(rules ...ExceptionRule) model.Finding {
			in := input([]model.Match{match(model.SourceGrype, hostA, "CVE-2026-0001", fixedIn("3.0.13-0ubuntu3.6"))})
			in.Owner = nodesOwner()
			addPkgs(&in, hostA)
			in.Exceptions = rules
			return one(t, Build(in))
		},
		"Nodes containerd (ContainerRuntime alias)": func(rules ...ExceptionRule) model.Finding {
			in := input([]model.Match{match(model.SourceGrype, ctrMod, "CVE-2026-0004", fixedIn("v2.1.5"))})
			in.Owner = nodesOwner()
			addPkgs(&in, ctrMod)
			in.Exceptions = rules
			return one(t, Build(in))
		},
		"Cluster": func(rules ...ExceptionRule) model.Finding {
			in := input([]model.Match{match(model.SourceGrype, kubernetes, "CVE-2026-0005", fixedIn("1.31.3"))})
			in.Owner = clusterOwner()
			in.Exceptions = rules
			return one(t, Build(in))
		},
		"ContainerRuntime (Nodes alias)": func(rules ...ExceptionRule) model.Finding {
			in := input([]model.Match{match(model.SourceGrype, containerd, "CVE-2026-0006", fixedIn("v1.7.21"))})
			in.Owner = runtimeOwner()
			in.Exceptions = rules
			return one(t, Build(in))
		},
	}
	kindName := map[string][]string{
		"Nodes host package":                        {"Nodes/prod", "nodes/PROD"},
		"Nodes containerd (ContainerRuntime alias)": {"Nodes/prod", "ContainerRuntime/containerd"},
		"Cluster":                        {"Cluster/prod", "cluster/Prod"},
		"ContainerRuntime (Nodes alias)": {"ContainerRuntime/containerd", "Nodes/prod"},
	}
	for name, build := range builds {
		for _, bare := range []string{"prod", "PROD", "containerd"} {
			f := build(rule(bare))
			assert.Equal(t, model.StateOpen, f.State, "%s: bare %q must not except it", name, bare)
			assert.Empty(t, f.ExceptedBy, "%s: bare %q", name, bare)
		}
		for _, kn := range kindName[name] {
			f := build(rule(kn))
			assert.Equal(t, model.StateExcepted, f.State, "%s: %q excepts it", name, kn)
		}
	}

	// A bare name still matches a namespaced owner, including a namespaced Cluster CR named after the cluster.
	cnpg := model.OwnerRef{Kind: "Cluster", Namespace: "db", Name: "prod"}
	assert.True(t, rule("prod").Matches(model.Finding{Owner: cnpg, AdvisoryID: "CVE-2026-0007"}, nil, now))
	assert.True(t, rule("api").Matches(model.Finding{Owner: api().Ref, AdvisoryID: "CVE-2026-0007"}, nil, now))
	for _, ref := range []model.OwnerRef{nodesRef, clusterOwner().Ref, runtimeOwner().Ref} {
		assert.False(t, rule(ref.Name).Matches(model.Finding{Owner: ref, AdvisoryID: "CVE-2026-0007"}, nil, now), ref.Key())
		assert.True(t, rule(ref.Kind+"/"+ref.Name).Matches(model.Finding{Owner: ref, AdvisoryID: "CVE-2026-0007"}, nil, now), ref.Key())
	}
}
