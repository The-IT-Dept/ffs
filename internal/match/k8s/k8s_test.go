package k8s_test

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/feeds/osv"
	"github.com/the-it-dept/ffs/internal/findings"
	"github.com/the-it-dept/ffs/internal/match"
	"github.com/the-it-dept/ffs/internal/match/k8s"
	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

var (
	ctx      = context.Background()
	testdata = os.DirFS("testdata")
)

const (
	cveK8s   = "CVE-2024-10220"
	cveCtrd  = "CVE-2024-40635"
	cveCRIO  = "CVE-2099-0002"
	goCtrd   = "GO-2025-3528"
	goCRIO   = "GO-2099-0001"
	k8sSpace = "git:github.com/kubernetes/kubernetes"
)

func newStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "ffs.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	return st
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := fs.ReadFile(testdata, name+".json")
	require.NoError(t, err)
	return raw
}

// cache stores a fixture in the OSV cache, indexed and with its advisory stored as the feed handler leaves it.
func cache(t *testing.T, st *store.Store, bucket, name string) []byte {
	t.Helper()
	raw := fixture(t, name)
	v, err := match.ParseOSV(raw)
	require.NoError(t, err)
	hash, err := osv.AffectedHash(raw)
	require.NoError(t, err)
	_, err = st.PutOSVRecord(ctx, bucket, v.GetId(), v.GetModified().AsTime(), hash, raw)
	require.NoError(t, err)
	var names []string
	for _, a := range v.GetAffected() {
		if bucket == osv.BucketGIT {
			for _, r := range a.GetRanges() {
				names = append(names, osv.NormalizeRepo(r.GetRepo()))
			}
		} else {
			names = append(names, a.GetPackage().GetName())
		}
	}
	require.NoError(t, st.PutOSVRecordNames(ctx, bucket, v.GetId(), names))
	_, err = match.UpsertOSVAdvisory(ctx, st, v)
	require.NoError(t, err)
	return raw
}

// synthetic stores the synthetic digest with its package and returns the stored package.
func synthetic(t *testing.T, st *store.Store, digest, module, version string) model.Package {
	t.Helper()
	require.NoError(t, st.PutSBOM(ctx, digest, []byte("{}"), []model.Package{{Ecosystem: "go-module", Name: module, Version: version}}))
	pkgs, err := st.PackagesForImage(ctx, digest)
	require.NoError(t, err)
	require.Len(t, pkgs, 1)
	return pkgs[0]
}

func matchDigest(t *testing.T, m *k8s.Matcher, digest string, p model.Package) []model.Match {
	t.Helper()
	ms, err := m.MatchImage(ctx, match.ImageInput{Digest: digest, Packages: []model.Package{p}})
	require.NoError(t, err)
	return ms
}

func TestK8s_ClusterVersionMatchesGitRecord(t *testing.T) {
	st := newStore(t)
	cache(t, st, osv.BucketGIT, cveK8s)
	m := k8s.New(st)
	require.Equal(t, model.SourceK8s, m.Source())

	p := synthetic(t, st, "k8s:1.30.2", "kubernetes", "1.30.2")
	require.Equal(t, []model.Match{{
		ImageDigest: "k8s:1.30.2",
		PackageID:   p.ID,
		AdvisoryID:  cveK8s,
		Source:      model.SourceK8s,
		FixState:    model.FixFixed,
		Namespace:   k8sSpace,
	}}, matchDigest(t, m, "k8s:1.30.2", p))
	// A leading v is stripped before the tag is built.
	require.Len(t, matchDigest(t, m, "k8s:v1.30.2", p), 1)

	p2 := synthetic(t, st, "k8s:1.30.3", "kubernetes", "1.30.3")
	require.Empty(t, matchDigest(t, m, "k8s:1.30.3", p2))
}

func TestK8s_Containerd(t *testing.T) {
	st := newStore(t)
	cache(t, st, osv.BucketGo, goCtrd)
	m := k8s.New(st)

	want := func(digest string, p model.Package, module, fixed string) []model.Match {
		return []model.Match{{
			ImageDigest: digest, PackageID: p.ID, AdvisoryID: cveCtrd, Source: model.SourceK8s,
			FixState: model.FixFixed, FixedVersions: []string{fixed}, Namespace: "go:" + module,
		}}
	}
	p := synthetic(t, st, "runtime:containerd@2.0.3", k8s.ContainerdV2, "v2.0.3")
	require.Equal(t, want("runtime:containerd@2.0.3", p, k8s.ContainerdV2, "2.0.4"), matchDigest(t, m, "runtime:containerd@2.0.3", p))

	p = synthetic(t, st, "runtime:containerd@2.0.4", k8s.ContainerdV2, "v2.0.4")
	require.Empty(t, matchDigest(t, m, "runtime:containerd@2.0.4", p))

	p = synthetic(t, st, "runtime:containerd@1.7.26", k8s.ContainerdV1, "v1.7.26")
	require.Equal(t, want("runtime:containerd@1.7.26", p, k8s.ContainerdV1, "1.7.27"), matchDigest(t, m, "runtime:containerd@1.7.26", p))

	p = synthetic(t, st, "runtime:containerd@1.7.27-k3s1", k8s.ContainerdV1, "v1.7.27")
	require.Empty(t, matchDigest(t, m, "runtime:containerd@1.7.27-k3s1", p))

	// No numeric version, or an unknown runtime, matches nothing.
	p = synthetic(t, st, "runtime:containerd@weird", k8s.ContainerdV1, "weird")
	require.Empty(t, matchDigest(t, m, "runtime:containerd@weird", p))
	p = synthetic(t, st, "runtime:other@1.0.0", "example.com/other", "v1.0.0")
	require.Empty(t, matchDigest(t, m, "runtime:other@1.0.0", p))
}

func TestK8s_CRIO(t *testing.T) {
	st := newStore(t)
	cache(t, st, osv.BucketGo, goCRIO)
	m := k8s.New(st)

	p := synthetic(t, st, "runtime:cri-o@1.30.4", k8s.CRIO, "v1.30.4")
	require.Equal(t, []model.Match{{
		ImageDigest: "runtime:cri-o@1.30.4", PackageID: p.ID, AdvisoryID: cveCRIO, Source: model.SourceK8s,
		FixState: model.FixFixed, FixedVersions: []string{"1.30.9"}, Namespace: "go:" + k8s.CRIO,
	}}, matchDigest(t, m, "runtime:cri-o@1.30.4", p))

	p = synthetic(t, st, "runtime:cri-o@1.30.9", k8s.CRIO, "v1.30.9")
	require.Empty(t, matchDigest(t, m, "runtime:cri-o@1.30.9", p))
}

func TestK8s_IgnoresImageDigests(t *testing.T) {
	st := newStore(t)
	cache(t, st, osv.BucketGIT, cveK8s)
	m := k8s.New(st)
	p := synthetic(t, st, "k8s:1.30.2", "kubernetes", "1.30.2")

	ms, err := m.MatchImage(ctx, match.ImageInput{Digest: "sha256:" + strings.Repeat("a", 64), Packages: []model.Package{p}})
	require.NoError(t, err)
	require.Nil(t, ms)
	ms, err = m.MatchImage(ctx, match.ImageInput{Digest: "k8s:1.30.2"})
	require.NoError(t, err)
	require.Nil(t, ms)
}

func TestK8s_ApplyOSVDelta(t *testing.T) {
	st := newStore(t)
	raw := fixture(t, cveK8s)
	p := synthetic(t, st, "k8s:1.30.2", "kubernetes", "1.30.2")
	synthetic(t, st, "k8s:1.31.0", "kubernetes", "1.31.0")
	for _, d := range []string{"k8s:1.30.2", "k8s:1.31.0"} {
		require.NoError(t, st.UpsertOwner(ctx, model.Owner{
			Ref:        model.OwnerRef{Kind: "Cluster", Name: d},
			Containers: []model.ContainerUse{{Name: "kubernetes", Digest: d}},
		}))
	}
	m := k8s.New(st)

	deltas, err := m.ApplyOSV(ctx, []osv.Changed{
		{Ecosystem: osv.BucketGIT, ID: cveK8s, Raw: raw},
		{Ecosystem: "PyPI", ID: "PYSEC-2024-1", Raw: []byte(`{"id":"PYSEC-2024-1"}`)},
	})
	require.NoError(t, err)
	require.Len(t, deltas, 1)
	require.Equal(t, store.MatchScope{Source: model.SourceK8s, AdvisoryIDs: []string{cveK8s}}, deltas[0].Scope)
	require.Len(t, deltas[0].Matches, 1)
	require.Equal(t, "k8s:1.30.2", deltas[0].Matches[0].ImageDigest)
	require.Equal(t, p.ID, deltas[0].Matches[0].PackageID)
	require.Equal(t, k8sSpace, deltas[0].Matches[0].Namespace)
	_, ok, err := st.GetAdvisory(ctx, cveK8s)
	require.NoError(t, err)
	require.True(t, ok)
}

// TestK8s_OldCVEGetsOSVSeverity is the F28 regression: a Kubernetes CVE older than cvelist's 30-day
// backfill has no CNA rating, so its cluster-level finding stayed "severity pending" (medium) for
// good. The CVSS vector on its OSV record now rates it.
func TestK8s_OldCVEGetsOSVSeverity(t *testing.T) {
	st := newStore(t)
	raw := bytes.Replace(fixture(t, cveK8s), []byte("{"),
		[]byte(`{"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"}],`), 1)
	const digest = "k8s:1.30.2"
	p := synthetic(t, st, digest, "kubernetes", "1.30.2")
	owner := model.Owner{Ref: model.OwnerRef{Kind: "Cluster", Name: "prod"},
		Containers: []model.ContainerUse{{Name: "kubernetes", Repo: "kubernetes", Digest: digest}}}
	require.NoError(t, st.UpsertOwner(ctx, owner))

	deltas, err := k8s.New(st).ApplyOSV(ctx, []osv.Changed{{Ecosystem: osv.BucketGIT, ID: cveK8s, Raw: raw}})
	require.NoError(t, err)
	require.Len(t, deltas, 1)
	advs, err := st.Advisories(ctx, []string{cveK8s})
	require.NoError(t, err)
	require.Equal(t, model.SeverityUnknown, advs[cveK8s].CNASeverity, "no cvelist record")

	fs := findings.Build(findings.BuildInput{Cluster: "prod", Owner: owner, Matches: deltas[0].Matches,
		Packages: map[string]model.Package{p.ID: p}, Advisories: advs, Now: time.Now(), PriorityConfig: config.Default().Priority})
	require.Len(t, fs, 1)
	require.Equal(t, model.SeverityHigh, fs[0].Severity, "CVSS 8.8 from the OSV record")
	require.Equal(t, "osv", fs[0].SeveritySource)
	require.NotContains(t, fs[0].Reasons, "severity pending")
}
