package osv

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestChoose uses bucket sizes measured on 2026-11-19: entries, all.zip bytes, central directory
// bytes (estimated at 80 bytes an entry) and the average record GET.
func TestChoose(t *testing.T) {
	probe := func(entries, zipBytes int64) zipProbe {
		dir := entries * 80
		return zipProbe{size: zipBytes, ranged: true, entries: entries, dirSize: dir, dirOffset: zipBytes - dir}
	}
	ubuntu := probe(74878, 821463306)
	npmZip := probe(232779, 221897251)
	debian := probe(74968, 82663478)
	for _, c := range []struct {
		name        string
		n           int
		recordBytes int64
		p           zipProbe
		want        transport
	}{
		{"Ubuntu, a 5-minute poll", 50, 575 << 10, ubuntu, rangedZip},
		{"Ubuntu, a burst", 5478, 575 << 10, ubuntu, rangedZip},
		{"Ubuntu, nearly everything", 70000, 575 << 10, ubuntu, wholeZip},
		{"Ubuntu, more entries than Range reads should take", 25000, 575 << 10, ubuntu, wholeZip},
		{"Ubuntu over the cap, nearly everything", 70000, 575 << 10, zipProbe{size: 2 << 30, ranged: true,
			entries: 74878, dirSize: 74878 * 80, dirOffset: 2<<30 - 74878*80}, rangedZip},
		{"npm, a poll", 50, 2800, npmZip, perRecord},
		{"npm, all MAL- records", 224611, 2800, npmZip, wholeZip},
		{"Debian, a poll", 50, 8900, debian, perRecord},
		{"Debian, a burst", 5000, 8900, debian, rangedZip},
		{"no Range support, under the cap", 50000, 8900, zipProbe{size: 82663478}, wholeZip},
		{"no Range support, over the cap", 70000, 575 << 10, zipProbe{size: 2 << 30}, perRecord},
		{"size unknown", 70000, 575 << 10, zipProbe{size: -1}, perRecord},
	} {
		require.Equal(t, c.want, choose(c.n, c.recordBytes, c.p), c.name)
	}
}

// zipBytes builds a zip of n entries "MAL-<i>.json".
func zipBytes(t *testing.T, n int) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := range n {
		w, err := zw.Create(fmt.Sprintf("MAL-%06d.json", i))
		require.NoError(t, err)
		_, err = fmt.Fprintf(w, `{"id":"MAL-%06d","details":%q}`, i, strings.Repeat("x", i%300))
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

// TestRemoteZip_Zip64 reads entries of a zip with more than 65,535 entries (as Ubuntu's all.zip has,
// so it ends in zip64 records) through Range requests only.
func TestRemoteZip_Zip64(t *testing.T) {
	const n = 70000
	data := zipBytes(t, n)
	local, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	require.NoError(t, err)
	var whole, requests atomic.Int32
	var sent atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Range") == "" {
			whole.Add(1)
		}
		w.Header().Set("x-goog-generation", "1")
		cw := &countingResponse{ResponseWriter: w}
		http.ServeContent(cw, r, "all.zip", time.Time{}, bytes.NewReader(data))
		sent.Add(cw.n)
	}))
	t.Cleanup(srv.Close)
	ctx := context.Background()

	p, err := probeZip(ctx, srv.Client(), srv.URL)
	require.NoError(t, err)
	require.True(t, p.ranged)
	require.Equal(t, int64(len(data)), p.size)
	require.Equal(t, int64(n), p.entries, "read from the zip64 end of central directory")
	require.Positive(t, p.dirSize)
	require.Equal(t, int64(len(data))-p.dirSize-56-20-22, p.dirOffset)

	z, err := openRemoteZip(ctx, srv.Client(), srv.URL, p)
	require.NoError(t, err)
	require.Len(t, z.zr.File, n)
	for _, i := range []int{0, 299, 65535, n - 1} {
		raw, err := z.read(z.zr.File[i])
		require.NoError(t, err)
		rc, err := local.File[i].Open()
		require.NoError(t, err)
		var want bytes.Buffer
		_, err = want.ReadFrom(rc)
		require.NoError(t, err)
		require.Equal(t, want.String(), string(raw))
	}
	require.Zero(t, whole.Load())
	require.Equal(t, int32(1+1+4*2), requests.Load(), "probe, directory, then header and data per entry")
	require.Less(t, sent.Load(), int64(len(data))/2)
}

// TestRemoteZip_ReplacedMidRead: a Range read that sees a different generation of all.zip fails
// instead of mixing two versions.
func TestRemoteZip_ReplacedMidRead(t *testing.T) {
	data := zipBytes(t, 3000) // larger than the probe's tail
	var gen atomic.Int32
	gen.Store(1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-goog-generation", fmt.Sprint(gen.Load()))
		http.ServeContent(w, r, "all.zip", time.Time{}, bytes.NewReader(data))
	}))
	t.Cleanup(srv.Close)
	ctx := context.Background()
	p, err := probeZip(ctx, srv.Client(), srv.URL)
	require.NoError(t, err)
	z, err := openRemoteZip(ctx, srv.Client(), srv.URL, p)
	require.NoError(t, err)
	gen.Store(2)
	_, err = z.read(z.zr.File[10])
	require.ErrorContains(t, err, "replaced during the read")
}

type countingResponse struct {
	http.ResponseWriter
	n int64
}

func (c *countingResponse) Write(p []byte) (int, error) {
	n, err := c.ResponseWriter.Write(p)
	c.n += int64(n)
	return n, err
}
