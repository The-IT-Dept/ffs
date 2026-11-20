package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/agentapi/wire"
	"github.com/the-it-dept/ffs/internal/version"
)

var serial atomic.Int64

// testCA is a CA generated in the test.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newCA(t *testing.T, cn string) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial.Add(1)), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return testCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// newLeaf is a serving certificate for the IP host, signed by ca.
func newLeaf(t *testing.T, ca testCA, host string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial.Add(1)), Subject: pkix.Name{CommonName: host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP(host)}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// tlsServer serves h over TLS on 127.0.0.1 with the certificate cert returns, without keep-alives (every
// request handshakes), until the test ends. It returns the server's https URL.
func tlsServer(t *testing.T, h http.Handler, cert func() *tls.Certificate) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12,
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert(), nil }}}
	srv.SetKeepAlivesEnabled(false)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.ServeTLS(ln, "", "")
	}()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		<-done
	})
	return "https://" + ln.Addr().String()
}

func writeTestFile(t *testing.T, p string, b []byte) {
	t.Helper()
	require.NoError(t, os.WriteFile(p, b, 0o600))
}

func TestClient_BearerUserAgentAndRereads(t *testing.T) {
	ctx := context.Background()
	ca1, ca2 := newCA(t, "ca-1"), newCA(t, "ca-2")
	leaf1, leaf2 := newLeaf(t, ca1, "127.0.0.1"), newLeaf(t, ca2, "127.0.0.1")
	var (
		mu      sync.Mutex
		current = &leaf1
		seen    []*http.Request
		bodies  []wire.Report
	)
	url := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rep wire.Report
		require.NoError(t, json.NewDecoder(r.Body).Decode(&rep))
		mu.Lock()
		seen, bodies = append(seen, r), append(bodies, rep)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(wire.ReportResponse{Applied: true, Config: wire.AgentConfig{JitterPercent: 7}})
	}), func() *tls.Certificate {
		mu.Lock()
		defer mu.Unlock()
		return current
	})
	dir := t.TempDir()
	caFile, tokenFile := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "token")
	writeTestFile(t, caFile, ca1.pem)
	writeTestFile(t, tokenFile, []byte("t1\n"))
	c, err := NewClient(url, caFile, tokenFile)
	require.NoError(t, err)

	report := wire.Report{Node: "worker-1", Kind: wire.KindFull, Seq: 1,
		Host: &wire.Host{PackageDB: "dpkg", SyftJSON: json.RawMessage(`{"artifacts": [ {"name":"openssl"} ]}`)}}
	resp, err := c.Report(ctx, report)
	require.NoError(t, err)
	require.Equal(t, wire.ReportResponse{Applied: true, Config: wire.AgentConfig{JitterPercent: 7}}, resp)
	mu.Lock()
	r := seen[0]
	require.Equal(t, "Bearer t1", r.Header.Get("Authorization"))
	require.Equal(t, version.UserAgent(), r.Header.Get("User-Agent"))
	require.Equal(t, "application/json", r.Header.Get("Content-Type"))
	require.Equal(t, http.MethodPost, r.Method)
	require.Equal(t, wire.PathReport, r.URL.Path)
	require.Positive(t, r.ContentLength, "the body size is known before it is sent")
	require.JSONEq(t, `{"artifacts":[{"name":"openssl"}]}`, string(bodies[0].Host.SyftJSON), "the host SBOM is spliced in unchanged")
	require.Equal(t, "dpkg", bodies[0].Host.PackageDB)
	mu.Unlock()
	require.JSONEq(t, `{"artifacts": [ {"name":"openssl"} ]}`, string(report.Host.SyftJSON), "the caller's report is not changed")

	writeTestFile(t, tokenFile, []byte("t2"))
	_, err = c.Report(ctx, wire.Report{Node: "worker-1", Kind: wire.KindImages})
	require.NoError(t, err)
	mu.Lock()
	require.Equal(t, "Bearer t2", seen[1].Header.Get("Authorization"), "the token is re-read on every request")
	current = &leaf2
	mu.Unlock()

	_, err = c.Report(ctx, wire.Report{Node: "worker-1", Kind: wire.KindImages})
	var unknown x509.UnknownAuthorityError
	require.ErrorAs(t, err, &unknown, "a leaf from another CA is refused")

	writeTestFile(t, caFile, ca2.pem)
	_, err = c.Report(ctx, wire.Report{Node: "worker-1", Kind: wire.KindImages})
	require.NoError(t, err, "the CA bundle is re-read when it changes")

	writeTestFile(t, caFile, []byte("not a certificate"))
	_, err = c.Report(ctx, wire.Report{Node: "worker-1", Kind: wire.KindImages})
	require.ErrorContains(t, err, "holds no certificate")
}

func TestClient_StatusErrors(t *testing.T) {
	ctx := context.Background()
	ca := newCA(t, "ca")
	leaf := newLeaf(t, ca, "127.0.0.1")
	url := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case wire.PathReport:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"node mismatch"}`))
		case wire.PathSBOM:
			w.WriteHeader(http.StatusRequestEntityTooLarge)
		case wire.PathConfig:
			require.Equal(t, http.MethodGet, r.Method)
			_ = json.NewEncoder(w).Encode(wire.AgentConfig{ReportIntervalSeconds: 60, ImageListIntervalSeconds: 5})
		}
	}), func() *tls.Certificate { return &leaf })
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "ca.crt"), ca.pem)
	writeTestFile(t, filepath.Join(dir, "token"), []byte("tok"))
	c, err := NewClient(url, filepath.Join(dir, "ca.crt"), filepath.Join(dir, "token"))
	require.NoError(t, err)

	_, err = c.Report(ctx, wire.Report{Node: "worker-2", Kind: wire.KindImages})
	var se *StatusError
	require.ErrorAs(t, err, &se)
	require.Equal(t, &StatusError{Code: 403, Msg: "node mismatch"}, se)
	require.EqualError(t, se, "controller answered 403: node mismatch")

	err = c.SBOM(ctx, wire.SBOMResult{ID: "w1", SyftJSON: json.RawMessage(`{}`)})
	require.True(t, errors.As(err, &se))
	require.Equal(t, &StatusError{Code: 413}, se)

	cfg, err := c.Config(ctx)
	require.NoError(t, err)
	require.Equal(t, wire.AgentConfig{ReportIntervalSeconds: 60, ImageListIntervalSeconds: 5}, cfg)

	_, err = NewClient("http://x", "ca", "token")
	require.EqualError(t, err, "controller URL must be https")
}
