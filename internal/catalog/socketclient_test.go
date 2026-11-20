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
	"github.com/the-it-dept/ffs/internal/model"
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

	dst := filepath.Join(t.TempDir(), "sbom.json")
	c := catalog.NewSocketClient(sock, 10*time.Second)
	resp, err := c.Catalog(ctx, job("ok"), dst)
	require.NoError(t, err)
	require.Equal(t, dst, resp.Path)
	got, err := os.ReadFile(dst) //nolint:gosec // the test's own file
	require.NoError(t, err)
	require.JSONEq(t, `{"artifacts":[]}`, string(got))
	require.EqualValues(t, len(got), resp.Size)

	_, err = c.Catalog(ctx, job("big"), dst)
	require.Equal(t, &catalog.WorkError{Kind: sbom.KindTooLarge, Msg: "big"}, workErr(t, err))
	require.NoFileExists(t, dst, "a failed job leaves no file")

	_, err = catalog.NewSocketClient(filepath.Join(socketDir(t), "absent.sock"), time.Second).Catalog(ctx, job("ok"), dst)
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
	_, err = catalog.NewSocketClient(dropped, 10*time.Second).Catalog(ctx, job("ok"), dst)
	require.Equal(t, &catalog.WorkError{Kind: sbom.KindFailed, Msg: "cataloguer stopped while processing the job"}, workErr(t, err))

	_, err = catalog.NewSocketClient(sock, 50*time.Millisecond).Catalog(ctx, job("slow"), dst)
	require.Equal(t, sbom.KindTimeout, workErr(t, err).Kind)
	require.NoFileExists(t, dst)
}

// rawSocket serves h on a unix socket until the test ends and returns the socket.
func rawSocket(t *testing.T, h http.HandlerFunc) string {
	t.Helper()
	sock := filepath.Join(socketDir(t), "r.sock")
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "unix", sock)
	require.NoError(t, err)
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}

func TestSocketClient_StreamsDocumentToFile(t *testing.T) {
	// The document is written byte for byte, whitespace and escapes included, whatever the member order.
	doc := `{ "artifacts" : [ {"name":"a\u00e9\"b","n":-1.5e+3,"ok":true,"x":null}, [] ],"source":{}}`
	body := `{"coverage":{"UnattributedELF":2,"Notes":["x"]},"extra":[1,{"a":"b"}],"syftJSON":` + doc + "}\n"
	sock := rawSocket(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) })
	dst := filepath.Join(t.TempDir(), "sbom.json")
	out, err := catalog.NewSocketClient(sock, 10*time.Second).Catalog(ctx, sbom.CatalogRequest{}, dst)
	require.NoError(t, err)
	got, err := os.ReadFile(dst) //nolint:gosec // the test's own file
	require.NoError(t, err)
	require.Equal(t, doc, string(got))
	require.EqualValues(t, len(doc), out.Size)
	require.Equal(t, model.Coverage{UnattributedELF: 2, Notes: []string{"x"}}, out.Coverage)
	fi, err := os.Stat(dst)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
}

func TestSocketClient_UnreadableResponses(t *testing.T) {
	for name, body := range map[string]string{
		"not an object":      `[1]`,
		"no document":        `{"coverage":{}}`,
		"two documents":      `{"syftJSON":{},"syftJSON":{}}`,
		"bad document":       `{"syftJSON":{"a" 1}}`,
		"trailing comma":     `{"syftJSON":{"a":[1,]}}`,
		"bad escape":         `{"syftJSON":"\x"}`,
		"control character":  "{\"syftJSON\":\"a\tb\"}",
		"bad number":         `{"syftJSON":-}`,
		"bad literal":        `{"syftJSON":nul}`,
		"bad coverage":       `{"syftJSON":{},"coverage":{"UnattributedELF":"x"}}`,
		"member after end":   `{"syftJSON":{} "coverage":{}}`,
		"huge coverage":      `{"syftJSON":{},"coverage":"` + strings.Repeat("x", 1<<20) + `"}`,
		"non-string members": `{1:2}`,
	} {
		t.Run(name, func(t *testing.T) {
			sock := rawSocket(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) })
			dst := filepath.Join(t.TempDir(), "sbom.json")
			_, err := catalog.NewSocketClient(sock, 10*time.Second).Catalog(ctx, sbom.CatalogRequest{}, dst)
			var we *catalog.WorkError
			require.ErrorAs(t, err, &we)
			require.Equal(t, &catalog.WorkError{Kind: sbom.KindFailed, Msg: "cataloguer returned an unreadable response"}, we)
			require.NoFileExists(t, dst)
		})
	}
	t.Run("truncated", func(t *testing.T) {
		sock := rawSocket(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "100")
			_, _ = io.WriteString(w, `{"syftJSON":{"artifacts":[`)
		})
		_, err := catalog.NewSocketClient(sock, 10*time.Second).Catalog(ctx, sbom.CatalogRequest{}, filepath.Join(t.TempDir(), "s.json"))
		var we *catalog.WorkError
		require.ErrorAs(t, err, &we)
		require.Equal(t, &catalog.WorkError{Kind: sbom.KindFailed, Msg: "cataloguer stopped while processing the job"}, we)
	})
	t.Run("scratch not writable", func(t *testing.T) {
		sock := rawSocket(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"syftJSON":{}}`) })
		_, err := catalog.NewSocketClient(sock, 10*time.Second).Catalog(ctx, sbom.CatalogRequest{},
			filepath.Join(t.TempDir(), "missing", "s.json"))
		var we *catalog.WorkError
		require.ErrorAs(t, err, &we)
		require.Equal(t, sbom.KindFailed, we.Kind)
		require.True(t, strings.HasPrefix(we.Msg, "writing the SBOM to scratch: "), we.Msg)
	})
}
