package model

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPriority_RoundTrip(t *testing.T) {
	ps := []Priority{PriorityLow, PriorityMedium, PriorityHigh, PriorityUrgent}
	for i, want := range []string{"low", "medium", "high", "urgent"} {
		require.Equal(t, want, ps[i].String())
		got, err := ParsePriority(want)
		require.NoError(t, err)
		require.Equal(t, ps[i], got)
	}
	got, err := ParsePriority(" High ")
	require.NoError(t, err)
	require.Equal(t, PriorityHigh, got)
	require.Equal(t, "", PriorityNone.String())
	for _, bad := range []string{"", "critical", "severe"} {
		_, err := ParsePriority(bad)
		require.Error(t, err, bad)
	}
	require.True(t, PriorityUrgent > PriorityHigh && PriorityHigh > PriorityMedium && PriorityMedium > PriorityLow && PriorityLow > PriorityNone)
}

func TestPriority_JSONText(t *testing.T) {
	b, err := json.Marshal(map[Priority]int{PriorityUrgent: 2, PriorityLow: 1})
	require.NoError(t, err)
	require.JSONEq(t, `{"urgent":2,"low":1}`, string(b))
	var back map[Priority]int
	require.NoError(t, json.Unmarshal(b, &back))
	require.Equal(t, 2, back[PriorityUrgent])
	b, _ = json.Marshal(struct {
		P Priority
		S Severity
	}{PriorityHigh, SeverityCritical})
	require.JSONEq(t, `{"P":"high","S":"critical"}`, string(b))
}

func TestSeverity_ParseTolerant(t *testing.T) {
	for in, want := range map[string]Severity{
		"critical": SeverityCritical, "CRITICAL": SeverityCritical, "high": SeverityHigh, "important": SeverityHigh,
		"medium": SeverityMedium, "moderate": SeverityMedium, "Moderate": SeverityMedium, "low": SeverityLow,
		"negligible": SeverityNegligible, "unimportant": SeverityNegligible, "none": SeverityNegligible,
		"": SeverityUnknown, "unknown": SeverityUnknown, "untriaged": SeverityUnknown, "banana": SeverityUnknown,
	} {
		require.Equal(t, want, ParseSeverity(in), in)
	}
	var names []string
	for s := SeverityUnknown; s <= SeverityCritical; s++ {
		names = append(names, s.String())
	}
	require.Equal(t, []string{"unknown", "negligible", "low", "medium", "high", "critical"}, names)
}

func TestPackageID_StableAndDistinct(t *testing.T) {
	p := Package{Ecosystem: "deb", Distro: &Distro{ID: "debian", VersionID: "12", Codename: "bookworm"},
		Name: "openssl", Version: "3.0.15-1~deb12u1", Arch: "amd64", Path: "/var/lib/dpkg/status"}
	// golden: sha256("sha256:aaaa|deb|debian/12|openssl|3.0.15-1~deb12u1|amd64|/var/lib/dpkg/status")
	require.Equal(t, "1f5ea6bbcaa9af730d50de63d3b33c3ea7a975c8ae3ec0906aaa76ef185dedce", PackageID("sha256:aaaa", p))
	seen := map[string]bool{PackageID("sha256:aaaa", p): true, PackageID("sha256:bbbb", p): true}
	for _, mut := range []func(*Package){
		func(q *Package) { q.Ecosystem = "rpm" }, func(q *Package) { q.Distro = &Distro{ID: "debian", VersionID: "11"} },
		func(q *Package) { q.Distro = nil }, func(q *Package) { q.Name = "libssl3" }, func(q *Package) { q.Version = "3.0.16" },
		func(q *Package) { q.Arch = "arm64" }, func(q *Package) { q.Path = "/usr/lib/x" },
	} {
		q := p
		mut(&q)
		id := PackageID("sha256:aaaa", q)
		require.False(t, seen[id])
		seen[id] = true
	}
	q := p
	q.Distro = &Distro{ID: "debian", VersionID: "12"}
	q.SourceName, q.PURL, q.Layer, q.SyftID = "openssl", "pkg:deb/debian/openssl", "sha256:l1", "abc"
	require.Equal(t, PackageID("sha256:aaaa", p), PackageID("sha256:aaaa", q)) // codename/source/purl/layer/syft id are not identity
}

func TestFindingFingerprint_StableAndDistinct(t *testing.T) {
	o := OwnerRef{Kind: "Deployment", Namespace: "netbox", Name: "netbox", UID: "u1"}
	// golden: sha256("prod|Deployment|netbox|netbox|ghcr.io/netbox-community/netbox|CVE-2026-0001")
	fp := FindingFingerprint("prod", o, "ghcr.io/netbox-community/netbox", "CVE-2026-0001")
	require.Equal(t, "4e28eef317edd7502471875049608623d13a1672a24acbb3470d3487c5f07cfb", fp)
	o2 := o
	o2.UID = "u2"
	require.Equal(t, fp, FindingFingerprint("prod", o2, "ghcr.io/netbox-community/netbox", "CVE-2026-0001")) // UID is not identity
	for _, other := range []string{
		FindingFingerprint("dev", o, "ghcr.io/netbox-community/netbox", "CVE-2026-0001"),
		FindingFingerprint("prod", OwnerRef{Kind: "StatefulSet", Namespace: "netbox", Name: "netbox"}, "ghcr.io/netbox-community/netbox", "CVE-2026-0001"),
		FindingFingerprint("prod", OwnerRef{Kind: "Deployment", Namespace: "other", Name: "netbox"}, "ghcr.io/netbox-community/netbox", "CVE-2026-0001"),
		FindingFingerprint("prod", o, "docker.io/library/nginx", "CVE-2026-0001"),
		FindingFingerprint("prod", o, "ghcr.io/netbox-community/netbox", "CVE-2026-0002"),
	} {
		require.NotEqual(t, fp, other)
	}
}

func TestOwnerRefKey(t *testing.T) {
	require.Equal(t, "Deployment/netbox/netbox", OwnerRef{Kind: "Deployment", Namespace: "netbox", Name: "netbox", UID: "x"}.Key())
	require.Equal(t, "Cluster//prod", OwnerRef{Kind: "Cluster", Name: "prod"}.Key())
}

func TestCanonicalID(t *testing.T) {
	require.Equal(t, "CVE-2026-0001", CanonicalID("GHSA-aaaa-bbbb-cccc", "CVE-2026-0002", "CVE-2026-0001"))
	require.Equal(t, "CVE-2026-0001", CanonicalID("CVE-2026-0001", "GHSA-aaaa-bbbb-cccc"))
	require.Equal(t, "GHSA-aaaa-bbbb-cccc", CanonicalID("PYSEC-2026-1", "GHSA-aaaa-bbbb-cccc"))
	require.Equal(t, "MAL-2026-7", CanonicalID("MAL-2026-7"))
	require.Equal(t, "", CanonicalID())
}
