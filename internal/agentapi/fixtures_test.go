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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
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
