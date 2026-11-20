package agentapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	syftsbom "github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/stretchr/testify/require"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/the-it-dept/ffs/internal/sbom"
	"github.com/the-it-dept/ffs/internal/store"
)

var t0 = time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)

// clock is a settable test clock.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock(at time.Time) *clock { return &clock{now: at} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "ffs.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	return st
}

// syftDoc is a host syft-json document of pkgs (each given its ID), with one evident-by relationship from each
// package to its first location, as the cataloguer produces.
func syftDoc(t *testing.T, distro *linux.Release, pkgs ...pkg.Package) []byte {
	t.Helper()
	var rels []artifact.Relationship
	for i := range pkgs {
		pkgs[i].SetID()
		if locs := pkgs[i].Locations.ToSlice(); len(locs) > 0 {
			rels = append(rels, artifact.Relationship{From: pkgs[i], To: locs[0].Coordinates, Type: artifact.EvidentByRelationship})
		}
	}
	doc := &syftsbom.SBOM{
		Artifacts:     syftsbom.Artifacts{Packages: pkg.NewCollection(pkgs...), LinuxDistribution: distro},
		Relationships: rels,
		Source:        source.Description{ID: "host", Name: "host", Metadata: source.DirectoryMetadata{Path: "/"}},
		Descriptor:    syftsbom.Descriptor{Name: "syft", Version: "1.57.2"},
	}
	b, err := sbom.EncodeSyftJSON(doc)
	require.NoError(t, err)
	return b
}

// debPkg is a dpkg package of the host.
func debPkg(name, version string) pkg.Package {
	return pkg.Package{Name: name, Version: version, Type: pkg.DebPkg, PURL: "pkg:deb/ubuntu/" + name + "@" + version,
		Locations: file.NewLocationSet(file.NewLocation("/var/lib/dpkg/status")),
		Metadata:  pkg.DpkgDBEntry{Package: name, Version: version, Architecture: "amd64"}}
}

// goPkg is a Go module found in the binary at path, whose main module is mainModule.
func goPkg(name, version, path, mainModule string) pkg.Package {
	return pkg.Package{Name: name, Version: version, Type: pkg.GoModulePkg, PURL: "pkg:golang/" + name + "@" + version,
		Locations: file.NewLocationSet(file.NewLocation(path)),
		Metadata:  pkg.GolangBinaryBuildinfoEntry{MainModule: mainModule, GoCompiledVersion: "go1.25.4", Architecture: "amd64"}}
}

// agentPod is a running pod on node whose containers report imageIDs.
func agentPod(ns, name, uid, node string, imageIDs ...string) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID(uid)},
		Spec:       corev1.PodSpec{NodeName: node, Containers: []corev1.Container{{Name: "c", Image: "example"}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
	for i, id := range imageIDs {
		p.Status.ContainerStatuses = append(p.Status.ContainerStatuses, corev1.ContainerStatus{
			Name: "c" + string(rune('0'+i)), ImageID: id, Ready: true})
	}
	return p
}

// writeCert writes a self-signed ECDSA P-256 certificate for localhost with the given serial to dir as
// tls.crt and tls.key. Both files get an mtime derived from the serial, so each pair is told apart.
func writeCert(t *testing.T, dir string, serial int64) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	kd, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	at := time.Unix(1_800_000_000+serial, 0)
	for name, b := range map[string][]byte{
		"tls.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		"tls.key": pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}),
	} {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, b, 0o600))
		require.NoError(t, os.Chtimes(p, at, at))
	}
}

// reviewer is a client whose TokenReview Create records each spec and answers with answer's status, or
// fails with its error.
func reviewer(t *testing.T, answer func(spec authenticationv1.TokenReviewSpec) (authenticationv1.TokenReviewStatus, error),
) (client.Client, *[]authenticationv1.TokenReviewSpec) {
	t.Helper()
	var (
		mu    sync.Mutex
		specs []authenticationv1.TokenReviewSpec
	)
	c := fake.NewClientBuilder().WithInterceptorFuncs(interceptor.Funcs{
		Create: func(_ context.Context, _ client.WithWatch, obj client.Object, _ ...client.CreateOption) error {
			tr := obj.(*authenticationv1.TokenReview)
			mu.Lock()
			specs = append(specs, tr.Spec)
			mu.Unlock()
			st, err := answer(tr.Spec)
			if err != nil {
				return err
			}
			tr.Status = st
			return nil
		},
	}).Build()
	return c, &specs
}

// fakePods is a PodIndex: node → the digests its pods run.
type fakePods struct {
	mu    sync.Mutex
	nodes map[string]map[string]bool
}

func newFakePods() *fakePods { return &fakePods{nodes: map[string]map[string]bool{}} }

// run records that a pod on node runs each digest.
func (f *fakePods) run(node string, digests ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.nodes[node] == nil {
		f.nodes[node] = map[string]bool{}
	}
	for _, d := range digests {
		f.nodes[node][d] = true
	}
}

func (f *fakePods) DigestsOnNode(_ context.Context, node string) (map[string]bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]bool{}
	for d := range f.nodes[node] {
		out[d] = true
	}
	return out, nil
}

// hexDigest is a sha256 digest whose hex is c repeated.
func hexDigest(c string) string { return "sha256:" + strings.Repeat(c, 64) }
