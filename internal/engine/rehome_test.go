package engine_test

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/engine"
	"github.com/the-it-dept/ffs/internal/model"
)

const (
	rehomeCVE      = "CVE-2026-50001"
	rehomeRTDigest = "runtime:containerd@2.1.4"
	containerdMod  = "github.com/containerd/containerd/v2"
)

var rehomeGrpA = model.NodeGroupDigestPrefix + strings.Repeat("a", 64)

// rehomeFixture is the cutover fixture: a ContainerRuntime owner on runtime:containerd@2.1.4 and the
// Nodes owner on a group digest, both catalogued with containerd v2.1.4, which grype matches on
// CVE-2026-50001 (fixed in 2.1.5). The Nodes owner suppresses the containerd module, so after setup the
// one finding is the runtime owner's.
type rehomeFixture struct {
	h                                  *harness
	rt, nodes                          model.OwnerRef
	rtOwner                            model.Owner
	nodesSuppressed, nodesUnsuppressed model.Owner
	fpRT, fpNodes                      string
}

func newRehomeFixture(t *testing.T) *rehomeFixture {
	t.Helper()
	h := newHarness(t)
	const cve = rehomeCVE
	x := &rehomeFixture{
		h:     h,
		rt:    model.OwnerRef{Kind: model.OwnerKindContainerRuntime, Name: "containerd"},
		nodes: model.NodesOwner("prod"),
	}
	x.rtOwner = model.Owner{Ref: x.rt, Containers: []model.ContainerUse{{Name: "containerd", Kind: model.ContainerRegular,
		ImageRef: "containerd://2.1.4", Repo: "containerd", Digest: rehomeRTDigest}}}
	x.nodesUnsuppressed = model.Owner{Ref: x.nodes, Containers: []model.ContainerUse{{Name: "g", Kind: model.ContainerRegular,
		ImageRef: "g", Repo: model.HostRepo, Digest: rehomeGrpA, Platform: "linux/amd64"}}}
	x.nodesSuppressed = x.nodesUnsuppressed
	x.nodesSuppressed.SuppressModules = []string{containerdMod}
	x.fpRT = model.FindingFingerprint("prod", x.rt, "containerd", cve)
	x.fpNodes = model.FindingFingerprint("prod", x.nodes, model.HostRepo, cve)

	var matches []model.Match
	for _, img := range []struct{ digest, repo, path string }{
		{rehomeRTDigest, "containerd", "/usr/bin/containerd"},
		{rehomeGrpA, model.HostRepo, "/usr/local/bin/k3s"},
	} {
		p := model.Package{ImageDigest: img.digest, Ecosystem: "go-module", Name: containerdMod, Version: "v2.1.4", Path: img.path}
		p.ID = model.PackageID(img.digest, p)
		require.NoError(t, h.st.UpsertImage(ctx, model.Image{Digest: img.digest, Repo: img.repo, Platform: "linux/amd64",
			Status: model.ImageCatalogued, Source: "registry", CataloguedAt: t0.Add(-time.Hour)}))
		require.NoError(t, h.st.PutSBOM(ctx, img.digest, []byte(`{"artifacts":[]}`), []model.Package{p}))
		m := newMatch(p, cve, model.SourceGrype, "2.1.5")
		m.VendorSeverity, m.VendorSeveritySource = model.SeverityHigh, "github"
		m.DBBuilt = t0.Add(time.Hour)
		matches = append(matches, m)
	}
	require.NoError(t, h.st.UpsertAdvisory(ctx, model.Advisory{ID: cve, Title: "containerd escape",
		Published: t0.Add(-48 * time.Hour), Observed: t0.Add(-24 * time.Hour), CNASeverity: model.SeverityHigh, CNASource: "github"}))
	require.NoError(t, h.st.UpsertOwner(ctx, x.rtOwner))
	require.NoError(t, h.st.UpsertOwner(ctx, x.nodesSuppressed))
	h.grype.fn = matchOn(matchOn(nil, rehomeRTDigest, matches[0]), rehomeGrpA, matches[1])
	require.NoError(t, h.e.OnImageCatalogued(ctx, rehomeRTDigest))
	require.NoError(t, h.e.OnImageCatalogued(ctx, rehomeGrpA))
	require.NoError(t, h.e.Drain(ctx))

	fs := h.findings(x.rt.Key())
	require.Len(t, fs, 1)
	require.Equal(t, x.fpRT, fs[0].Fingerprint)
	require.Equal(t, model.StateOpen, fs[0].State)
	require.Empty(t, h.findings(x.nodes.Key()), "the Nodes owner suppresses the containerd module")
	return x
}

// forwardAndBack re-homes the runtime finding onto the Nodes owner and back, without storing the
// runtime owner again, and drains.
func (x *rehomeFixture) forwardAndBack(t *testing.T) {
	t.Helper()
	require.NoError(t, x.h.e.Rehome(ctx, engine.Rehome{Upsert: &x.nodesUnsuppressed,
		Moves: []engine.FindingMove{{Fingerprint: x.fpRT, To: x.nodes, ToRepo: model.HostRepo}}, Drop: []string{x.rt.Key()}}))
	require.NoError(t, x.h.e.Drain(ctx))
	require.NoError(t, x.h.e.Rehome(ctx, engine.Rehome{Upsert: &x.nodesSuppressed,
		Moves: []engine.FindingMove{{Fingerprint: x.fpNodes, To: x.rt, ToRepo: "containerd"}}}))
	require.NoError(t, x.h.e.Drain(ctx))
}

func TestEngineRehome_NoTransitionsBothWays(t *testing.T) {
	const cve = rehomeCVE
	x := newRehomeFixture(t)
	h, rt, nodes := x.h, x.rt, x.nodes
	n0 := len(h.transitions())

	require.NoError(t, h.e.Rehome(ctx, engine.Rehome{Upsert: &x.nodesUnsuppressed,
		Moves: []engine.FindingMove{{Fingerprint: x.fpRT, To: nodes, ToRepo: model.HostRepo}}, Drop: []string{rt.Key()}}))
	require.NoError(t, h.e.Drain(ctx))
	require.Len(t, h.transitions(), n0) // no detected, no resolved
	require.Equal(t, model.StateOpen, h.finding(nodes.Key(), cve).State)
	_, ok, _ := h.st.GetOwner(ctx, rt.Key())
	require.False(t, ok)

	// Back again; the runtime owner is not stored yet.
	require.NoError(t, h.e.Rehome(ctx, engine.Rehome{Upsert: &x.nodesSuppressed,
		Moves: []engine.FindingMove{{Fingerprint: x.fpNodes, To: rt, ToRepo: "containerd"}}}))
	require.NoError(t, h.e.Drain(ctx))
	require.NoError(t, h.e.OnAdvisoriesEnriched(ctx, []string{cve})) // queues rt.Key() through its findings
	require.NoError(t, h.e.Drain(ctx))
	require.Len(t, h.transitions(), n0) // the absent, awaited owner is not resolved
	require.NoError(t, h.st.UpsertOwner(ctx, x.rtOwner))
	require.NoError(t, h.e.OnOwnersChanged(ctx, []string{rt.Key()}))
	require.NoError(t, h.e.Drain(ctx))
	require.Len(t, h.transitions(), n0)
	require.Equal(t, model.StateOpen, h.finding(rt.Key(), cve).State)
}

func TestEngineRehome_AbsentOwnerResolvesAfterWait(t *testing.T) {
	const cve = rehomeCVE
	x := newRehomeFixture(t)
	h := x.h
	n0 := len(h.transitions())
	x.forwardAndBack(t)
	require.Len(t, h.transitions(), n0)

	h.clock.now = h.clock.now.Add(16 * time.Minute) // rehomeWait (15m) + 1m
	require.NoError(t, h.e.OnAdvisoriesEnriched(ctx, []string{cve}))
	require.NoError(t, h.e.Drain(ctx))
	ts := h.transitions()
	require.Len(t, ts, n0+1)
	require.Equal(t, model.StateResolved, ts[n0].ToState)
	require.Equal(t, x.fpRT, ts[n0].Fingerprint)
}

func TestEngineRehome_SkipsMissingFingerprints(t *testing.T) {
	x := newRehomeFixture(t)
	h := x.h
	before, n0 := h.findings(x.rt.Key()), len(h.transitions())

	require.NoError(t, h.e.Rehome(ctx, engine.Rehome{Moves: []engine.FindingMove{{Fingerprint: "gone", To: x.nodes, ToRepo: model.HostRepo}}}))
	require.NoError(t, h.e.Drain(ctx))
	require.Equal(t, before, h.findings(x.rt.Key()))
	require.Empty(t, h.findings(x.nodes.Key()))
	require.Len(t, h.transitions(), n0)
	require.True(t, h.e.Idle())
}
