package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/feeds/grypedb"
	"github.com/the-it-dept/ffs/internal/feeds/grypedb/grypedbtest"
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
		"heartbeat":       "/run/ffs-agent/heartbeat",
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
	for flag, def := range map[string]string{"heartbeat": "/run/ffs-agent/heartbeat", "max-age": "15m0s"} {
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

// TestGrypeDBDiffCmd (#7): the hidden subcommand the controller re-executes diffs two builds and
// writes the changed package keys as JSON.
func TestGrypeDBDiffCmd(t *testing.T) {
	root := newRootCmd()
	cmd, _, err := root.Find([]string{grypedb.DiffCommand})
	require.NoError(t, err)
	require.Equal(t, grypedb.DiffCommand, cmd.Name())
	require.True(t, cmd.Hidden)
	var help bytes.Buffer
	root.SetOut(&help)
	root.SetArgs([]string{"--help"})
	require.NoError(t, root.Execute())
	require.NotContains(t, help.String(), grypedb.DiffCommand)

	built := time.Date(2026, 11, 18, 18, 19, 44, 0, time.UTC)
	oldDir := filepath.Join(t.TempDir(), "old")
	require.NoError(t, os.CopyFS(oldDir, os.DirFS(grypedbtest.BuildDB(t, built, "**/debian-12/cve-2022-38178.json"))))
	newDir := grypedbtest.BuildDB(t, built.Add(24*time.Hour))
	out := filepath.Join(t.TempDir(), "keys.json")
	root = newRootCmd()
	root.SetArgs([]string{grypedb.DiffCommand, "--old", oldDir, "--new", newDir, "--out", out})
	require.NoError(t, root.ExecuteContext(context.Background()))
	data, err := os.ReadFile(out) //nolint:gosec // G304: test output path
	require.NoError(t, err)
	var keys []grypedb.PackageKey
	require.NoError(t, json.Unmarshal(data, &keys))
	require.Contains(t, keys, grypedb.PackageKey{Ecosystem: "deb", Name: "firefox-esr"})

	root = newRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{grypedb.DiffCommand, "--old", oldDir})
	require.ErrorContains(t, root.ExecuteContext(context.Background()), "required flag")
}
