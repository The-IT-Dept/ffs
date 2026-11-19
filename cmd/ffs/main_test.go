package main

import (
	"bytes"
	"io"
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

func TestStubCommandsFail(t *testing.T) {
	for _, sub := range []string{"controller", "catalog"} {
		cmd := newRootCmd()
		cmd.SetArgs([]string{sub})
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		require.EqualError(t, cmd.Execute(), "not implemented", sub)
	}
}
