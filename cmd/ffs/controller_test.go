package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"sync"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

// lockedBuffer is a bytes.Buffer safe for the logger's concurrent writes.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

// lines decodes every JSON log line written so far.
func (l *lockedBuffer) lines(t *testing.T) []map[string]any {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []map[string]any
	sc := bufio.NewScanner(bytes.NewReader(l.b.Bytes()))
	for sc.Scan() {
		var m map[string]any
		require.NoError(t, json.Unmarshal(sc.Bytes(), &m), "not a JSON log line: %s", sc.Text())
		out = append(out, m)
	}
	return out
}

// TestControllerCmd_LogFlags: the zap options are flags of the controller command (F118).
func TestControllerCmd_LogFlags(t *testing.T) {
	cmd := newControllerCmd()
	for _, name := range []string{"zap-log-level", "zap-encoder", "zap-devel", "zap-stacktrace-level", "zap-time-encoding"} {
		require.NotNil(t, cmd.Flags().Lookup(name), name)
	}
	require.NoError(t, cmd.Flags().Parse([]string{"--zap-log-level=debug"}))
}

// TestSetLogger_KlogAndVerbosity: klog, which client-go and leader election use, writes through the controller's
// JSON logger, and --zap-log-level=debug turns on V(1) messages, which are off by default (F118).
func TestSetLogger_KlogAndVerbosity(t *testing.T) {
	logger := func(buf *lockedBuffer, args ...string) logr.Logger {
		t.Helper()
		o := zap.Options{DestWriter: buf}
		fs := flag.NewFlagSet("zap", flag.ContinueOnError)
		o.BindFlags(fs)
		require.NoError(t, fs.Parse(args))
		return zap.New(zap.UseFlagOptions(&o))
	}
	require.False(t, logger(&lockedBuffer{}).V(1).Enabled(), "V(1) is off by default")
	var verbose lockedBuffer
	logger(&verbose, "--zap-log-level=debug").V(1).Info("verbose line")
	lines := verbose.lines(t)
	require.Len(t, lines, 1)
	require.Equal(t, "verbose line", lines[0]["msg"])

	var buf lockedBuffer
	t.Cleanup(klog.ClearLogger)
	setLogger(logger(&buf))
	klog.InfoS("leader election line", "lease", "ffs/ffs.theitdept.au")
	klog.V(1).InfoS("klog's own verbosity still applies")
	klog.Flush()
	lines = buf.lines(t)
	require.Len(t, lines, 1)
	require.Equal(t, "leader election line", lines[0]["msg"])
	require.Equal(t, "ffs/ffs.theitdept.au", lines[0]["lease"], "klog's key-value pairs are JSON fields")
}
