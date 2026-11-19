package catalog_test

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-logr/logr/funcr"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/catalog"
	"github.com/the-it-dept/ffs/internal/registry/regtest"
	"github.com/the-it-dept/ffs/internal/sbom"
)

var ctx = context.Background()

// serve runs s on a unix socket until the test ends and returns a client for it.
func serve(t *testing.T, s *catalog.Server) *http.Client {
	t.Helper()
	dir, err := os.MkdirTemp("", "ffs") // short path: macOS caps unix socket paths at 104 bytes
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "c.sock")

	sctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- s.ListenAndServe(sctx, sock) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
	})
	c := &http.Client{Transport: &http.Transport{DialContext: func(dctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(dctx, "unix", sock)
	}}}
	require.Eventually(t, func() bool {
		resp, err := c.Get("http://catalog/healthz") //nolint:noctx // test probe
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 5*time.Second, 10*time.Millisecond)
	return c
}

// post sends req and returns the status and the decoded error body (zero on 200).
func post(t *testing.T, c *http.Client, req sbom.CatalogRequest) (int, sbom.CatalogError) {
	t.Helper()
	b, err := json.Marshal(req)
	require.NoError(t, err)
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://catalog/v1/catalog", bytes.NewReader(b))
	require.NoError(t, err)
	resp, err := c.Do(hreq)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var ce sbom.CatalogError
	if resp.StatusCode != http.StatusOK {
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&ce))
	}
	return resp.StatusCode, ce
}

// pushRandom pushes a random image and returns its digest reference.
func pushRandom(t *testing.T, reg *regtest.Server, size int64, layers int) (string, v1.Image) {
	t.Helper()
	img, err := random.Image(size, int64(layers))
	require.NoError(t, err)
	return reg.Host + "/app@" + reg.Push(t, "app", img), img
}

func okRunner(calls *atomic.Int32) catalog.Runner {
	return func(context.Context, sbom.CatalogRequest, string) (*sbom.CatalogResponse, error) {
		calls.Add(1)
		return &sbom.CatalogResponse{SyftJSON: json.RawMessage(`{}`)}, nil
	}
}

func TestCatalog_SizeLimit(t *testing.T) {
	reg := regtest.Start(t)
	ref, img := pushRandom(t, reg, 4096, 3)
	m, err := img.Manifest()
	require.NoError(t, err)
	var total int64
	for _, l := range m.Layers {
		total += l.Size
	}
	require.Greater(t, total, int64(1000))

	var calls atomic.Int32
	c := serve(t, &catalog.Server{ScratchDir: t.TempDir(), ScratchLimit: 1 << 30, Run: okRunner(&calls)})

	status, ce := post(t, c, sbom.CatalogRequest{Ref: ref, Platform: "linux/amd64", MaxBytes: 1000, TimeoutSeconds: 5})
	require.Equal(t, http.StatusRequestEntityTooLarge, status)
	require.Equal(t, sbom.CatalogError{Kind: sbom.KindTooLarge,
		Error: fmt.Sprintf("compressed layers total %d bytes, limit 1000 bytes", total)}, ce)
	require.Equal(t, int32(0), calls.Load())

	status, _ = post(t, c, sbom.CatalogRequest{Ref: ref, Platform: "linux/amd64", MaxBytes: 1 << 20, TimeoutSeconds: 5})
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, int32(1), calls.Load())
}

// tarEntry is one entry of a test image layer.
type tarEntry struct {
	hdr  tar.Header
	body string
}

// pushLayerImage pushes a linux/amd64 image with one layer holding entries and the config user, and
// returns its digest reference.
func pushLayerImage(t *testing.T, reg *regtest.Server, user string, entries ...tarEntry) string {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		if e.hdr.Typeflag == 0 {
			e.hdr.Typeflag, e.hdr.Mode = tar.TypeReg, 0o644
		}
		e.hdr.Size = int64(len(e.body))
		require.NoError(t, tw.WriteHeader(&e.hdr))
		_, err := io.WriteString(tw, e.body)
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(buf.Bytes())), nil })
	require.NoError(t, err)
	img, err := mutate.AppendLayers(empty.Image, layer)
	require.NoError(t, err)
	cf, err := img.ConfigFile()
	require.NoError(t, err)
	cf = cf.DeepCopy()
	cf.OS, cf.Architecture, cf.Config.User = "linux", "amd64", user
	img, err = mutate.ConfigFile(img, cf)
	require.NoError(t, err)
	return reg.Host + "/app@" + reg.Push(t, "app", img)
}

func TestCatalog_PathTraversalRejected(t *testing.T) {
	reg := regtest.Start(t)
	ref := pushLayerImage(t, reg, "",
		tarEntry{tar.Header{Name: "../../ffs-escape.txt"}, "escape\n"},
		tarEntry{tar.Header{Name: "/ffs-abs.txt"}, "absolute\n"},
		tarEntry{tar.Header{Name: "lnk", Typeflag: tar.TypeSymlink, Linkname: "../../..", Mode: 0o777}, ""},
		tarEntry{tar.Header{Name: "lnk/ffs-escape2.txt"}, "through the link\n"},
		tarEntry{tar.Header{Name: "app/main.go"}, "package main\n\nfunc main() {}\n"},
	)

	testTmp := os.TempDir() // the test process's, before TMPDIR points at the scratch directory
	wd, err := os.Getwd()
	require.NoError(t, err)
	scratch := t.TempDir()
	t.Setenv("TMPDIR", scratch)

	resp, err := catalog.Catalog(ctx, sbom.CatalogRequest{Ref: ref, Platform: "linux/amd64", MaxBytes: 1 << 30, TimeoutSeconds: 60})
	if err != nil {
		t.Logf("cataloguer refused the image: %v", err)
	} else {
		t.Logf("cataloguer accepted the image (%d bytes of syft-json)", len(resp.SyftJSON))
		doc, derr := sbom.DecodeSyftJSON(resp.SyftJSON)
		require.NoError(t, derr)
		for _, c := range doc.AllCoordinates() {
			require.NotContains(t, c.RealPath, "..")
		}
		for _, p := range doc.Artifacts.Packages.Sorted() {
			for _, l := range p.Locations.ToSlice() {
				require.NotContains(t, l.RealPath, "..")
			}
		}
	}

	escapes := []string{"ffs-escape.txt", "ffs-abs.txt", "ffs-escape2.txt"}
	root := filepath.Dir(scratch)
	require.NoError(t, filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // stereoscope may still be removing its directories
		}
		for _, name := range escapes {
			require.NotEqual(t, name, d.Name(), path)
		}
		return nil
	}))
	for _, dir := range []string{filepath.Dir(root), testTmp, wd, "/"} {
		for _, name := range escapes {
			_, err := os.Lstat(filepath.Join(dir, name))
			require.ErrorIs(t, err, fs.ErrNotExist, filepath.Join(dir, name))
		}
	}
}

func TestCatalog_Timeout(t *testing.T) {
	reg := regtest.Start(t)
	ref, _ := pushRandom(t, reg, 256, 1)
	var jobDir atomic.Value
	c := serve(t, &catalog.Server{ScratchDir: t.TempDir(), ScratchLimit: 1 << 30,
		Run: func(rctx context.Context, _ sbom.CatalogRequest, dir string) (*sbom.CatalogResponse, error) {
			jobDir.Store(dir)
			<-rctx.Done()
			return nil, rctx.Err()
		}})

	start := time.Now()
	status, ce := post(t, c, sbom.CatalogRequest{Ref: ref, Platform: "linux/amd64", MaxBytes: 1 << 20, TimeoutSeconds: 1})
	require.Less(t, time.Since(start), 3*time.Second)
	require.Equal(t, http.StatusGatewayTimeout, status)
	require.Equal(t, sbom.KindTimeout, ce.Kind)
	dir, _ := jobDir.Load().(string)
	require.NotEmpty(t, dir)
	require.NoDirExists(t, dir)
}

func TestCatalog_ScratchWatchdog(t *testing.T) {
	reg := regtest.Start(t)
	ref, _ := pushRandom(t, reg, 256, 1)
	var jobDir atomic.Value
	c := serve(t, &catalog.Server{ScratchDir: t.TempDir(), ScratchLimit: 1 << 20, Poll: 10 * time.Millisecond,
		Run: func(rctx context.Context, _ sbom.CatalogRequest, dir string) (*sbom.CatalogResponse, error) {
			jobDir.Store(dir)
			if err := os.WriteFile(filepath.Join(dir, "layer.tar"), make([]byte, 2<<20), 0o600); err != nil {
				return nil, err
			}
			<-rctx.Done()
			return nil, rctx.Err()
		}})

	status, ce := post(t, c, sbom.CatalogRequest{Ref: ref, Platform: "linux/amd64", MaxBytes: 1 << 20, TimeoutSeconds: 30})
	require.Equal(t, http.StatusInsufficientStorage, status)
	require.Equal(t, sbom.KindScratchFull, ce.Kind)
	dir, _ := jobDir.Load().(string)
	require.NotEmpty(t, dir)
	require.NoDirExists(t, dir)
}

func TestCatalog_BusyAndBadRequest(t *testing.T) {
	reg := regtest.Start(t)
	ref, _ := pushRandom(t, reg, 256, 1)
	started, release := make(chan struct{}), make(chan struct{})
	c := serve(t, &catalog.Server{ScratchDir: t.TempDir(), MaxConcurrent: 1,
		Run: func(rctx context.Context, _ sbom.CatalogRequest, _ string) (*sbom.CatalogResponse, error) {
			close(started)
			select {
			case <-release:
				return &sbom.CatalogResponse{SyftJSON: json.RawMessage(`{}`)}, nil
			case <-rctx.Done():
				return nil, rctx.Err()
			}
		}})
	req := sbom.CatalogRequest{Ref: ref, Platform: "linux/amd64", MaxBytes: 1 << 20, TimeoutSeconds: 30}

	body, err := json.Marshal(req)
	require.NoError(t, err)
	first := make(chan int, 1)
	go func() {
		resp, err := c.Post("http://catalog/v1/catalog", "application/json", bytes.NewReader(body)) //nolint:noctx // test request
		if err != nil {
			first <- 0
			return
		}
		_ = resp.Body.Close()
		first <- resp.StatusCode
	}()
	<-started

	status, ce := post(t, c, req)
	require.Equal(t, http.StatusServiceUnavailable, status)
	require.Equal(t, sbom.KindBusy, ce.Kind)

	bad := req
	bad.Ref = reg.Host + "/app:latest"
	status, ce = post(t, c, bad)
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, sbom.KindBadRequest, ce.Kind)

	close(release)
	require.Equal(t, http.StatusOK, <-first)
}

func TestCatalog_CredentialsNotLogged(t *testing.T) {
	const user, password = "puller", "s3cret-pull-password"
	reg := regtest.Start(t, regtest.WithBasicAuth(user, password))
	ref, _ := pushRandom(t, reg, 256, 1)

	var mu sync.Mutex
	var logs strings.Builder
	log := funcr.New(func(prefix, args string) {
		mu.Lock()
		defer mu.Unlock()
		logs.WriteString(prefix + " " + args + "\n")
	}, funcr.Options{Verbosity: 10})

	var calls atomic.Int32
	c := serve(t, &catalog.Server{ScratchDir: t.TempDir(), Log: log, Run: okRunner(&calls)})
	req := sbom.CatalogRequest{Ref: ref, Platform: "linux/amd64", MaxBytes: 1 << 20, TimeoutSeconds: 30,
		Auth: sbom.CatalogAuth{Username: user, Password: password}}

	status, _ := post(t, c, req)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, int32(1), calls.Load())

	wrong := req
	wrong.Auth.Password = password + "-wrong"
	status, ce := post(t, c, wrong)
	require.Equal(t, http.StatusUnauthorized, status)
	require.Equal(t, sbom.KindUnauthorized, ce.Kind)

	bad := req
	bad.Ref = reg.Host + "/app:latest"
	status, _ = post(t, c, bad)
	require.Equal(t, http.StatusBadRequest, status)

	mu.Lock()
	out := logs.String()
	mu.Unlock()
	require.Contains(t, out, ref)
	require.NotContains(t, out, password)
}

// TestCatalog_DebianImage runs Syft in process on a minimal Debian image: the worker must produce an
// SBOM that normalises to the dpkg package with its distro and the image's config user.
func TestCatalog_DebianImage(t *testing.T) {
	reg := regtest.Start(t)
	ref := pushLayerImage(t, reg, "65532:65532",
		tarEntry{tar.Header{Name: "etc/os-release"}, "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nNAME=\"Debian GNU/Linux\"\n" +
			"VERSION_ID=\"12\"\nVERSION=\"12 (bookworm)\"\nVERSION_CODENAME=bookworm\nID=debian\n"},
		tarEntry{tar.Header{Name: "var/lib/dpkg/status"}, "Package: libssl3\nStatus: install ok installed\nPriority: optional\n" +
			"Section: libs\nInstalled-Size: 6000\nMaintainer: Debian OpenSSL Team <pkg-openssl-devel@example.org>\n" +
			"Architecture: amd64\nMulti-Arch: same\nSource: openssl\nVersion: 3.0.15-1~deb12u1\n" +
			"Description: Secure Sockets Layer toolkit - shared libraries\n\n"},
	)
	t.Setenv("TMPDIR", t.TempDir())

	resp, err := catalog.Catalog(ctx, sbom.CatalogRequest{Ref: ref, Platform: "linux/amd64", MaxBytes: 1 << 30, TimeoutSeconds: 60})
	require.NoError(t, err)
	doc, err := sbom.DecodeSyftJSON(resp.SyftJSON)
	require.NoError(t, err)
	require.Equal(t, "65532:65532", sbom.ConfigUser(doc))

	digest := ref[strings.LastIndex(ref, "@")+1:]
	pkgs, cov := sbom.Normalize(digest, doc)
	require.Equal(t, resp.Coverage, cov)
	found := false
	for _, p := range pkgs {
		if p.Name != "libssl3" {
			continue
		}
		found = true
		require.Equal(t, "deb", p.Ecosystem)
		require.Equal(t, "openssl", p.SourceName)
		require.Equal(t, "amd64", p.Arch)
		require.NotNil(t, p.Distro)
		require.Equal(t, "debian", p.Distro.ID)
		require.Equal(t, "12", p.Distro.VersionID)
		require.Equal(t, "bookworm", p.Distro.Codename)
		require.NotEmpty(t, p.SyftID)
	}
	require.True(t, found, "libssl3 not catalogued")
}

// TestCatalog_StaleJobDirsRemovedAtStart: the scratch volume outlives a killed catalog container, so
// the job directories a previous run left behind are removed when the server starts; anything else
// in the scratch directory is left alone.
func TestCatalog_StaleJobDirsRemovedAtStart(t *testing.T) {
	scratch := t.TempDir()
	stale := filepath.Join(scratch, "job-0123456789abcdef")
	require.NoError(t, os.MkdirAll(filepath.Join(stale, "layers", "sha256"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(stale, "layers", "sha256", "blob"), make([]byte, 4096), 0o600))
	other := filepath.Join(scratch, "keep.txt")
	require.NoError(t, os.WriteFile(other, []byte("not a job"), 0o600))

	var calls atomic.Int32
	serve(t, &catalog.Server{ScratchDir: scratch, Run: okRunner(&calls)})

	require.NoDirExists(t, stale)
	require.FileExists(t, other)
}

// TestExecRunner_SignalNamedOnce: a worker ended by a signal reports the signal once, not
// "cataloguer killed by killed".
func TestExecRunner_SignalNamedOnce(t *testing.T) {
	script := filepath.Join(t.TempDir(), "worker.sh")
	require.NoError(t, os.WriteFile(script, []byte("#!/bin/sh\nkill -9 $$\n"), 0o700)) //nolint:gosec // G306: the test runs it

	_, err := catalog.ExecRunner(script)(ctx, sbom.CatalogRequest{Ref: "r@sha256:" + strings.Repeat("a", 64)}, t.TempDir())
	var we *catalog.WorkError
	require.ErrorAs(t, err, &we)
	require.Equal(t, sbom.KindFailed, we.Kind)
	require.Equal(t, "cataloguer worker ended by signal 9 (killed)", we.Msg)
}
