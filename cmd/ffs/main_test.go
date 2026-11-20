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
}

func TestCatalogCmd_Flags(t *testing.T) {
	cmd := newCatalogCmd()
	for flag, def := range map[string]string{
		"socket":         "/run/ffs/catalog.sock",
		"scratch":        "/scratch",
		"scratch-limit":  "19327352832",
		"max-concurrent": "2",
		"local-root":     "",
		"nice":           "0",
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
