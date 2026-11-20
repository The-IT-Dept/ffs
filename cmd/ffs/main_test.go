package main

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVersionCommand(t *testing.T) {
	var out bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"version"})
	require.NoError(t, cmd.Execute())
	require.True(t, strings.HasPrefix(out.String(), "ffs dev (commit "), out.String())
	require.Contains(t, out.String(), runtime.Version())
}

func TestControllerCmd_Flags(t *testing.T) {
	cmd := newControllerCmd()
	for flag, def := range map[string]string{
		"config":                    "/etc/ffs/config.yaml",
		"leader-elect":              "true",
		"metrics-bind-address":      ":8443",
		"health-probe-bind-address": ":8081",
	} {
		f := cmd.Flags().Lookup(flag)
		require.NotNil(t, f, flag)
		require.Equal(t, def, f.DefValue, flag)
	}
	// the diagnostic pprof listener is hidden and off unless asked for
	pprof := cmd.Flags().Lookup("pprof-bind-address")
	require.NotNil(t, pprof)
	require.True(t, pprof.Hidden)
	require.Empty(t, pprof.DefValue)
}

func TestCatalogCmd_Flags(t *testing.T) {
	cmd := newCatalogCmd()
	for flag, def := range map[string]string{
		"socket":              "/run/ffs/catalog.sock",
		"scratch":             "/scratch",
		"scratch-limit":       "19327352832",
		"max-concurrent":      "2",
		"local-root":          "",
		"nice":                "0",
		"worker-memory-limit": "0",
	} {
		f := cmd.Flags().Lookup(flag)
		require.NotNil(t, f, flag)
		require.Equal(t, def, f.DefValue, flag)
	}
	require.Nil(t, cmd.Flags().Lookup("config"))

	worker, _, err := cmd.Find([]string{"worker"})
	require.NoError(t, err)
	require.Equal(t, "worker", worker.Name())
	require.True(t, worker.Hidden)
}

func TestCatalogCmd_NiceRange(t *testing.T) {
	for _, nice := range []string{"20", "-1"} {
		sock := filepath.Join(t.TempDir(), "c.sock")
		cmd := newCatalogCmd()
		cmd.SetArgs([]string{"--nice=" + nice, "--socket=" + sock, "--scratch=" + t.TempDir()})
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		err := cmd.ExecuteContext(context.Background())
		require.EqualError(t, err, "--nice must be between 0 and 19", nice)
		require.NoFileExists(t, sock, "rejected before listening")
	}
}

func TestAgentCmd_Flags(t *testing.T) {
	t.Setenv("NODE_NAME", "worker-1")
	cmd := newAgentCmd()
	for flag, def := range map[string]string{ //nolint:gosec // G101: flag defaults; the token path is not a credential
		"controller":      "",
		"ca-file":         "/etc/ffs-agent/ca/ca.crt",
		"token-file":      "/var/run/secrets/ffs-agent/token",
		"node-name":       "worker-1",
		"host-root":       "/host",
		"distribution":    "containerd",
		"content-store":   "",
		"scratch":         "/scratch/stage",
		"catalog-socket":  "/run/ffs/catalog.sock",
		"max-image-bytes": "1073741824",
		"heartbeat":       "/scratch/heartbeat",
		"extra-bin-dir":   "[]",
	} {
		f := cmd.Flags().Lookup(flag)
		require.NotNil(t, f, flag)
		require.Equal(t, def, f.DefValue, flag)
	}
	require.Equal(t, "stringArray", cmd.Flags().Lookup("extra-bin-dir").Value.Type(), "repeatable")

	check, _, err := cmd.Find([]string{"check"})
	require.NoError(t, err)
	require.Equal(t, "check", check.Name())
	require.True(t, check.Hidden)
	for flag, def := range map[string]string{"heartbeat": "/scratch/heartbeat", "max-age": "15m0s"} {
		f := check.Flags().Lookup(flag)
		require.NotNil(t, f, flag)
		require.Equal(t, def, f.DefValue, flag)
	}

	agentCmd, _, err := newRootCmd().Find([]string{"agent"})
	require.NoError(t, err)
	require.Equal(t, "agent", agentCmd.Name())
}

func TestAgentCmd_CheckExitsWithItsMessage(t *testing.T) {
	cmd := newRootCmd()
	p := filepath.Join(t.TempDir(), "heartbeat")
	cmd.SetArgs([]string{"agent", "check", "--heartbeat=" + p, "--max-age=15m"})
	require.EqualError(t, cmd.ExecuteContext(context.Background()), "no agent heartbeat at "+p)

	cmd = newRootCmd()
	cmd.SetArgs([]string{"agent", "--distribution=auto"})
	require.EqualError(t, cmd.ExecuteContext(context.Background()), `unknown distribution "auto": want containerd, k3s, rke2 or crio`)
}
