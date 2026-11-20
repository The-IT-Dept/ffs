package store

import (
	"bytes"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestZstdEncoder_BoundedHistory guards the memory the shared encoder keeps between calls. By
// default it keeps a 16 MiB history per GOMAXPROCS once a run of writes has cycled through them all.
func TestZstdEncoder_BoundedHistory(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(16))
	src := bytes.Repeat([]byte(`{"name":"libssl3","version":"3.0.15-1~deb12u1","type":"deb"},`), 4<<10)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	e := mustZstdEncoder()
	for range 64 {
		out := e.EncodeAll(src, nil)
		dec, err := zdec.DecodeAll(out, nil)
		require.NoError(t, err)
		require.Equal(t, len(src), len(dec))
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(e)
	grew := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	require.Less(t, grew, int64(32<<20), "the encoder keeps %d MiB between calls", grew>>20)
}
