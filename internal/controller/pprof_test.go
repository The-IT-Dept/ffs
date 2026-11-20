package controller

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
)

func TestCheckPprofAddr(t *testing.T) {
	for _, ok := range []string{"127.0.0.1:6060", "127.0.0.1:0", "[::1]:6060", "127.0.0.2:6060"} {
		require.NoError(t, checkPprofAddr(ok), ok)
	}
	for _, bad := range []string{"", ":6060", "0.0.0.0:6060", "[::]:6060", "10.0.0.1:6060", "ffs.example:6060", "localhost:6060",
		"127.0.0.1", "127.0.0.1:"} {
		require.Error(t, checkPprofAddr(bad), bad)
	}
}

func TestStartPprof_ServesOnLoopbackOnly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, err := startPprof(ctx, "0.0.0.0:0", logr.Discard())
	require.Error(t, err)

	bound, stop, err := startPprofAddr(ctx, "127.0.0.1:0", logr.Discard())
	require.NoError(t, err)
	defer stop()
	ta, err := net.ResolveTCPAddr("tcp", bound)
	require.NoError(t, err)
	require.True(t, ta.IP.IsLoopback())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+bound+"/debug/pprof/heap?debug=1", nil)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, resp.Body.Close())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Contains(t, string(body), "HeapInuse")
}
