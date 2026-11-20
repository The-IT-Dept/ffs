package main

import (
	"bytes"
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
		"socket":         "/run/ffs/catalog.sock",
		"scratch":        "/scratch",
		"scratch-limit":  "19327352832",
		"max-concurrent": "2",
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
