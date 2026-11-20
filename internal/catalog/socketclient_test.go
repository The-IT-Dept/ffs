package catalog_test

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/catalog"
	"github.com/the-it-dept/ffs/internal/sbom"
)

// socketDir is a short temporary directory: macOS caps unix socket paths at 104 bytes.
func socketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ffs")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// serveSocket runs s until the test ends and returns its socket once it answers.
func serveSocket(t *testing.T, s *catalog.Server) string {
	t.Helper()
	sock := filepath.Join(socketDir(t), "c.sock")
	sctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- s.ListenAndServe(sctx, sock) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
	})
	probe := &http.Client{Transport: &http.Transport{DialContext: func(dctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(dctx, "unix", sock)
	}}}
	require.Eventually(t, func() bool {
		resp, err := probe.Get("http://catalog/healthz") //nolint:noctx // test probe
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 5*time.Second, 10*time.Millisecond)
	return sock
}

func TestSocketClient_MapsResponses(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"ok", "big", "slow"} {
		require.NoError(t, os.MkdirAll(filepath.Join(root, d), 0o700))
	}
	sock := serveSocket(t, &catalog.Server{ScratchDir: t.TempDir(), LocalRoot: root,
		Run: func(rctx context.Context, req sbom.CatalogRequest, _ string) (*sbom.CatalogResponse, error) {
			switch filepath.Base(req.Path) {
			case "big":
				return nil, &catalog.WorkError{Kind: sbom.KindTooLarge, Msg: "big"}
			case "slow":
				select {
				case <-time.After(time.Second):
				case <-rctx.Done():
				}
				return nil, rctx.Err()
			}
			return &sbom.CatalogResponse{SyftJSON: json.RawMessage(`{"artifacts":[]}`)}, nil
		}})
	job := func(name string) sbom.CatalogRequest {
		return sbom.CatalogRequest{Source: sbom.CatalogSourceHostDir, Path: filepath.Join(root, name), MaxBytes: 1 << 20, TimeoutSeconds: 30}
	}
	workErr := func(t *testing.T, err error) *catalog.WorkError {
		t.Helper()
		var we *catalog.WorkError
		require.ErrorAs(t, err, &we)
		return we
	}

	c := catalog.NewSocketClient(sock, 10*time.Second)
	resp, err := c.Catalog(ctx, job("ok"))
	require.NoError(t, err)
	require.JSONEq(t, `{"artifacts":[]}`, string(resp.SyftJSON))

	_, err = c.Catalog(ctx, job("big"))
	require.Equal(t, &catalog.WorkError{Kind: sbom.KindTooLarge, Msg: "big"}, workErr(t, err))

	_, err = catalog.NewSocketClient(filepath.Join(socketDir(t), "absent.sock"), time.Second).Catalog(ctx, job("ok"))
	we := workErr(t, err)
	require.Equal(t, sbom.KindBusy, we.Kind)
	require.True(t, strings.HasPrefix(we.Msg, "cataloguer unavailable: "), we.Msg)

	// A cataloguer that goes down after reading the request.
	dropped := filepath.Join(socketDir(t), "drop.sock")
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "unix", dropped)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		if r, err := http.ReadRequest(bufio.NewReader(conn)); err == nil {
			_, _ = io.Copy(io.Discard, r.Body)
		}
		_ = conn.Close()
	}()
	_, err = catalog.NewSocketClient(dropped, 10*time.Second).Catalog(ctx, job("ok"))
	require.Equal(t, &catalog.WorkError{Kind: sbom.KindFailed, Msg: "cataloguer stopped while processing the job"}, workErr(t, err))

	_, err = catalog.NewSocketClient(sock, 50*time.Millisecond).Catalog(ctx, job("slow"))
	require.Equal(t, sbom.KindTimeout, workErr(t, err).Kind)
}
