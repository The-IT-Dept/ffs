package upgrade

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/eol"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

const (
	clusterKey = "Cluster//test"
	advK       = "CVE-2026-2001"
)

var clusterRef = model.OwnerRef{Kind: "Cluster", Name: "test"}

func TestLatestPatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/stable-1.35.txt":
			_, _ = w.Write([]byte("v1.35.10\n"))
		case "/stable-1.36.txt":
			_, _ = w.Write([]byte("garbage"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	got, err := LatestPatch(rctx, srv.Client(), srv.URL, 1, 35)
	require.NoError(t, err)
	require.Equal(t, "1.35.10", got)

	_, err = LatestPatch(rctx, srv.Client(), srv.URL, 1, 99)
	require.ErrorIs(t, err, ErrNoRelease)

	_, err = LatestPatch(rctx, srv.Client(), srv.URL, 1, 36)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrNoRelease)
}

// crig is a store holding a Cluster owner with an open high finding, a release server and a resolver.
type crig struct {
	t    *testing.T
	st   *store.Store
	sc   *fakeScorer
	srv  *httptest.Server
	hits *atomic.Int32
	r    *Resolver
}

func newClusterRig(t *testing.T, dist string, versions []string, release map[string]string) *crig {
	t.Helper()
	st, err := store.Open(rctx, filepath.Join(t.TempDir(), "ffs.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })

	cr := &crig{t: t, st: st, hits: &atomic.Int32{}, sc: &fakeScorer{byDigest: map[string][]model.Finding{}}}
	cr.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cr.hits.Add(1)
		if release == nil {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		minor := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/stable-"), ".txt")
		if v, ok := release[minor]; ok {
			_, _ = w.Write([]byte(v + "\n"))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(cr.srv.Close)

	var cs []model.ContainerUse
	for _, v := range versions {
		d := "k8s:" + v
		cs = append(cs, model.ContainerUse{Name: v, Kind: model.ContainerRegular, ImageRef: "v" + v, Repo: "kubernetes", Digest: d})
		cr.seedImage(d, "kubernetes", "kubernetes", "kubernetes", v)
		cr.sc.byDigest[d] = []model.Finding{cf(advK, model.PriorityHigh)}
	}
	owner := model.Owner{Ref: clusterRef, Containers: cs}
	require.NoError(t, st.UpsertOwner(rctx, owner))
	require.NoError(t, st.PutClusterInfo(rctx, model.ClusterInfo{Name: "test", Version: versions[0], Distribution: dist}))
	f := model.Finding{Fingerprint: model.FindingFingerprint("default", clusterRef, "kubernetes", advK), Owner: clusterRef,
		ImageRepo: "kubernetes", AdvisoryID: advK, Digests: []string{"k8s:" + versions[0]}, State: model.StateOpen,
		Priority: model.PriorityHigh, FixAvailable: true, Matched: rnow, LastSeen: rnow}
	require.NoError(t, st.ApplyFindings(rctx, []model.Finding{f}, nil))

	require.NoError(t, st.ReplaceEOL(rctx, []store.EOLCycle{
		{Product: "kubernetes", Cycle: "1.35", Latest: "1.35.10", EOLDate: day(2027, 2, 28)},
		{Product: "kubernetes", Cycle: "1.34", EOLDate: day(2026, 10, 27)},
		{Product: "containerd", Cycle: "2.2", EOLDate: day(2026, 11, 6)},
	}))
	ev := eol.New(st, func() time.Time { return rnow })
	require.NoError(t, ev.Reload(rctx))
	p, err := NewParser(nil)
	require.NoError(t, err)
	cfg := config.Default()
	cfg.Upgrades.KubernetesReleaseURL = cr.srv.URL
	cr.r = NewResolver(Options{Store: st, Registry: &fakeRegistry{}, Acquirer: &fakeAcquirer{}, Scorer: cr.sc, EOL: ev, Parser: p,
		Config: cfg, HTTP: cr.srv.Client(), Now: func() time.Time { return rnow }})
	return cr
}

func (cr *crig) seedImage(digest, repo, eco, name, version string) {
	cr.t.Helper()
	require.NoError(cr.t, cr.st.UpsertImage(rctx, model.Image{Digest: digest, Repo: repo, Status: model.ImageCatalogued,
		Source: "inventory", CataloguedAt: rnow}))
	p := model.Package{Ecosystem: eco, Name: name, Version: version, ImageDigest: digest}
	p.ID = model.PackageID(digest, p)
	require.NoError(cr.t, cr.st.PutSBOM(rctx, digest, nil, []model.Package{p}))
}

func (cr *crig) owner() model.Owner {
	cr.t.Helper()
	o, ok, err := cr.st.GetOwner(rctx, clusterKey)
	require.NoError(cr.t, err)
	require.True(cr.t, ok)
	return o
}

func (cr *crig) suggestion(key, repo string) store.OwnerSuggestion {
	cr.t.Helper()
	got, ok, err := cr.st.GetSuggestion(rctx, key, repo)
	require.NoError(cr.t, err)
	require.True(cr.t, ok, "a suggestion is stored")
	return got
}

var twoMinors = map[string]string{"1.35": "v1.35.10", "1.34": "v1.34.13"}

func TestAdviseCluster_LatestPatchFixes(t *testing.T) {
	cr := newClusterRig(t, "", []string{"1.35.1"}, twoMinors)
	// the target no longer matches the advisory
	cr.sc.byDigest["k8s:1.35.10"] = nil
	require.NoError(t, cr.r.AdviseCluster(rctx, cr.owner()))

	got := cr.suggestion(clusterKey, "kubernetes")
	sg := got.Suggestion
	require.Equal(t, "kubernetes", sg.Repo)
	require.Equal(t, "v1.35.1", sg.FromTag)
	require.Equal(t, "v1.35.10", sg.ToTag)
	require.Equal(t, "k8s:1.35.10", sg.ToDigest)
	require.Equal(t, model.TierPatch, sg.Tier)
	require.Equal(t, map[model.Priority]int{model.PriorityHigh: 1}, sg.Fixes)
	require.Equal(t, []string{advK}, sg.FixedIDs)
	require.Equal(t, []store.CandidateDigest{{Tag: "v1.35.10", Tier: model.TierPatch, Digest: "k8s:1.35.10"}}, got.Candidates)

	img, ok, err := cr.st.GetImage(rctx, "k8s:1.35.10")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "inventory", img.Source)
	require.Equal(t, model.ImageCatalogued, img.Status)
	pkgs, err := cr.st.PackagesForImage(rctx, "k8s:1.35.10")
	require.NoError(t, err)
	require.Len(t, pkgs, 1)
	require.Equal(t, "1.35.10", pkgs[0].Version)
	require.Equal(t, "k8s:1.35.10", pkgs[0].ImageDigest)
}

func TestAdviseCluster_K3sNoteAndEOL(t *testing.T) {
	cr := newClusterRig(t, "k3s", []string{"1.34.2"}, twoMinors)
	cr.sc.byDigest["k8s:1.34.13"] = nil
	require.NoError(t, cr.r.AdviseCluster(rctx, cr.owner()))

	sg := cr.suggestion(clusterKey, "kubernetes").Suggestion
	require.Equal(t, "v1.34.13", sg.ToTag)
	require.Contains(t, sg.Notes, "upgrade to the matching k3s release")
	require.Equal(t, "k3s 1.34 reached end of life 2026-10-27", sg.EOL)
}

func TestAdviseCluster_OtherMinorNote(t *testing.T) {
	cr := newClusterRig(t, "", []string{"1.35.1", "1.34.2"}, twoMinors)
	cr.sc.byDigest["k8s:1.35.10"] = nil
	cr.sc.byDigest["k8s:1.34.13"] = nil
	require.NoError(t, cr.r.AdviseCluster(rctx, cr.owner()))

	sg := cr.suggestion(clusterKey, "kubernetes").Suggestion
	require.Equal(t, "v1.35.1", sg.FromTag)
	require.Equal(t, "v1.35.10", sg.ToTag)
	require.Contains(t, sg.Notes, "kubelets on 1.34: v1.34.13")
}

func TestAdviseCluster_AlreadyLatest(t *testing.T) {
	cr := newClusterRig(t, "", []string{"1.35.10"}, twoMinors)
	require.NoError(t, cr.r.AdviseCluster(rctx, cr.owner()))

	got := cr.suggestion(clusterKey, "kubernetes")
	require.Equal(t, model.TierNone, got.Suggestion.Tier)
	require.Empty(t, got.Suggestion.ToTag)
	require.Empty(t, got.Candidates)
	require.Equal(t, "", got.Suggestion.EOL) // cycle 1.35 ends 2027-02-28, outside the warning window
}

func TestAdviseCluster_ReleaseServerDown(t *testing.T) {
	cr := newClusterRig(t, "", []string{"1.35.1"}, nil)
	cr.sc.byDigest["k8s:1.35.10"] = nil
	require.NoError(t, cr.r.AdviseCluster(rctx, cr.owner()))
	require.Positive(t, cr.hits.Load())

	sg := cr.suggestion(clusterKey, "kubernetes").Suggestion
	require.Equal(t, "v1.35.10", sg.ToTag, "falls back to the latest patch of the end-of-life cycle")
}

const (
	rtKey    = "ContainerRuntime//containerd"
	rtDigest = "runtime:containerd@2.2.1"
)

func newRuntimeRig(t *testing.T, fixed ...[]string) *crig {
	t.Helper()
	cr := newClusterRig(t, "", []string{"1.35.1"}, twoMinors)
	ref := model.OwnerRef{Kind: "ContainerRuntime", Name: "containerd"}
	require.NoError(t, cr.st.UpsertOwner(rctx, model.Owner{Ref: ref, Containers: []model.ContainerUse{{Name: "containerd",
		Kind: model.ContainerRegular, ImageRef: "containerd://2.2.1", Repo: "containerd", Digest: rtDigest}}}))
	cr.seedImage(rtDigest, "containerd", "go-module", "github.com/containerd/containerd/v2", "v2.2.1")
	pkgs, err := cr.st.PackagesForImage(rctx, rtDigest)
	require.NoError(t, err)

	var fs []model.Finding
	var ms []model.Match
	for i, fv := range fixed {
		id := "CVE-2026-300" + string(rune('1'+i))
		require.NoError(t, cr.st.UpsertAdvisory(rctx, model.Advisory{ID: id, Observed: rnow}))
		fs = append(fs, model.Finding{Fingerprint: model.FindingFingerprint("default", ref, "containerd", id), Owner: ref,
			ImageRepo: "containerd", AdvisoryID: id, Digests: []string{rtDigest}, State: model.StateOpen,
			Priority: model.PriorityHigh, FixAvailable: true, Matched: rnow, LastSeen: rnow})
		ms = append(ms, model.Match{ImageDigest: rtDigest, PackageID: pkgs[0].ID, AdvisoryID: id, Source: model.SourceOSV,
			FixState: model.FixFixed, FixedVersions: fv, ObservedAt: rnow})
		cr.sc.byDigest[rtDigest] = append(cr.sc.byDigest[rtDigest], cf(id, model.PriorityHigh))
	}
	_, err = cr.st.ReplaceMatches(rctx, store.MatchScope{Digests: []string{rtDigest}}, ms)
	require.NoError(t, err)
	require.NoError(t, cr.st.ApplyFindings(rctx, fs, nil))
	return cr
}

func (cr *crig) runtimeOwner() model.Owner {
	cr.t.Helper()
	o, ok, err := cr.st.GetOwner(rctx, rtKey)
	require.NoError(cr.t, err)
	require.True(cr.t, ok)
	return o
}

func TestAdviseRuntime_FixedVersionFromMatches(t *testing.T) {
	cr := newRuntimeRig(t, []string{"2.2.2"}, []string{"2.1.6", "2.2.3"})
	// the target fixes both advisories
	cr.sc.byDigest["runtime:containerd@2.2.3"] = nil
	require.NoError(t, cr.r.AdviseRuntime(rctx, cr.runtimeOwner()))

	got := cr.suggestion(rtKey, "containerd")
	sg := got.Suggestion
	require.Equal(t, "2.2.1", sg.FromTag)
	require.Equal(t, "2.2.3", sg.ToTag)
	require.Equal(t, "runtime:containerd@2.2.3", sg.ToDigest)
	require.Equal(t, model.TierPatch, sg.Tier)
	require.Contains(t, sg.Notes, "containerd >= 2.2.3")
	require.Equal(t, "containerd 2.2 reached end of life 2026-11-06", sg.EOL)

	pkgs, err := cr.st.PackagesForImage(rctx, "runtime:containerd@2.2.3")
	require.NoError(t, err)
	require.Len(t, pkgs, 1)
	require.Equal(t, "v2.2.3", pkgs[0].Version)
}

func TestAdviseRuntime_NoFixInLine(t *testing.T) {
	cr := newRuntimeRig(t, []string{"2.3.0"})
	cr.sc.byDigest["runtime:containerd@2.3.0"] = nil
	require.NoError(t, cr.r.AdviseRuntime(rctx, cr.runtimeOwner()))

	sg := cr.suggestion(rtKey, "containerd").Suggestion
	require.Equal(t, "2.3.0", sg.ToTag)
	require.Equal(t, model.TierMinor, sg.Tier)
}

func TestResolver_RoutesClusterOwners(t *testing.T) {
	cr := newClusterRig(t, "", []string{"1.35.1"}, twoMinors)
	cr.sc.byDigest["k8s:1.35.10"] = nil
	reg := &fakeRegistry{listErr: context.Canceled}
	cr.r.o.Registry = reg
	require.NoError(t, cr.r.ResolveOwner(rctx, clusterKey))

	require.Equal(t, "v1.35.10", cr.suggestion(clusterKey, "kubernetes").Suggestion.ToTag)
	require.Empty(t, reg.platforms)
	require.Empty(t, cr.r.Pending())
}
