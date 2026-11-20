package osv

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"sync"

	"github.com/the-it-dept/ffs/internal/feeds"
)

// A poll reads the records it needs in one of three ways, whichever moves the fewest estimated
// bytes (choose):
//   - one GET per record, which transfers the record uncompressed. Most buckets have small records,
//     but Ubuntu's average about 500 KB, because one record lists every kernel flavour.
//   - Range reads of just those records' compressed entries in all.zip, after one read of its
//     central directory (a few MB). Ubuntu's records shrink about 45 times in the zip.
//   - all of all.zip, when most of the bucket is wanted. Only up to maxZipBytes.
const (
	// zipTailBytes is read first: enough for the end of central directory record with the longest
	// comment, and the zip64 locator and record before it.
	zipTailBytes = 64<<10 + 22 + 20 + 56
	// maxDirBytes bounds the central directory read for Range reads (Ubuntu's is about 6 MB).
	maxDirBytes = 64 << 20
	// requestOverhead is what one request costs on top of its body, in the estimates.
	requestOverhead = 1 << 10
	// defaultRecordBytes is a bucket's record size until one has been measured.
	defaultRecordBytes = 16 << 10
	// probeAbove is the estimated per-record cost above which all.zip is looked at.
	probeAbove = 1 << 20
	// maxRangedEntries bounds Range reads by time: each entry takes two requests (about 0.3 s each
	// from Sydney, 16 at a time), so 20,000 entries take about 12 minutes. Beyond it all.zip is read
	// whole when it is within maxZipBytes.
	maxRangedEntries = 20000
	// rangedConcurrency entries are read at once, and rangedChunk read before they are stored, to
	// bound memory.
	rangedConcurrency = 16
	rangedChunk       = 32
)

// transport is how a poll reads its records.
type transport uint8

const (
	perRecord transport = iota // one GET per record
	rangedZip                  // Range reads of the records' entries in all.zip
	wholeZip                   // all of all.zip
)

func (t transport) String() string {
	return [...]string{"per-record", "ranged-zip", "whole-zip"}[t]
}

// zipProbe is what one Range read of the end of a bucket's all.zip tells about it.
type zipProbe struct {
	size    int64  // bytes; -1 when unknown
	ranged  bool   // the server answers Range requests
	version string // x-goog-generation, else ETag: every Range read must see the same
	tail    []byte // the last len(tail) bytes, when ranged
	// From the end of central directory record; entries is 0 when it could not be read.
	entries, dirSize, dirOffset int64
}

// probeZip reads the end of the all.zip at url.
func probeZip(ctx context.Context, c *http.Client, url string) (zipProbe, error) {
	resp, err := feeds.Fetch(ctx, c, feeds.Request{URL: url, Range: fmt.Sprintf("bytes=-%d", zipTailBytes), MaxBytes: zipTailBytes})
	p := zipProbe{size: resp.Total, version: versionOf(resp)}
	switch {
	case resp.Status == http.StatusOK && (err == nil || errors.Is(err, feeds.ErrTooLarge)):
		// The server ignored the Range header: it can only serve all of all.zip.
		return p, nil
	case err != nil:
		return p, err
	case resp.Status != http.StatusPartialContent || p.size < int64(len(resp.Body)):
		return p, fmt.Errorf("osv: %s: unexpected answer %d to a Range read", url, resp.Status)
	}
	p.ranged, p.tail = true, resp.Body
	p.entries, p.dirSize, p.dirOffset = endOfDirectory(p.tail, p.size-int64(len(p.tail)), p.size)
	return p, nil
}

// versionOf identifies the object a response came from.
func versionOf(r feeds.Response) string {
	if r.Generation != "" {
		return r.Generation
	}
	return r.ETag
}

// choose returns the transport with the fewest estimated bytes for reading n records of a bucket
// whose records average recordBytes, given the probe of its all.zip. Range reads of more than
// maxRangedEntries give way to reading all.zip whole, when that is possible.
func choose(n int, recordBytes int64, p zipProbe) transport {
	best, cost := perRecord, int64(n)*(recordBytes+requestOverhead)
	if p.ranged && p.entries > 0 && p.dirSize <= maxDirBytes {
		perEntry := p.dirOffset/p.entries + 2*requestOverhead // local header read, then the data
		if c := p.dirSize + int64(n)*perEntry; c < cost {
			best, cost = rangedZip, c
		}
	}
	if whole := p.size > 0 && p.size <= maxZipBytes; whole && (p.size < cost || best == rangedZip && n > maxRangedEntries) {
		best = wholeZip
	}
	return best
}

// endOfDirectory finds the end of central directory record in tail, the bytes of a zip of size bytes
// from offset base on, and returns the number of entries and the size and offset of the central
// directory, from the zip64 record when the classic one is saturated. entries is 0 when there is no
// plausible record. The values only feed estimates: archive/zip reads the directory itself.
func endOfDirectory(tail []byte, base, size int64) (entries, dirSize, dirOffset int64) {
	const (
		eocdSig, locatorSig, eocd64Sig = 0x06054b50, 0x07064b50, 0x06064b50
		eocdLen, locatorLen, eocd64Len = 22, 20, 56
	)
	le16 := func(i int) int64 { return int64(binary.LittleEndian.Uint16(tail[i:])) }
	le32 := func(i int) int64 { return int64(binary.LittleEndian.Uint32(tail[i:])) }
	le64 := func(i int) int64 {
		v := binary.LittleEndian.Uint64(tail[i:])
		if v > 1<<62 {
			return -1
		}
		return int64(v)
	}
	for i := len(tail) - eocdLen; i >= 0; i-- {
		if le32(i) != eocdSig || i+eocdLen+int(le16(i+20)) > len(tail) {
			continue
		}
		entries, dirSize, dirOffset = le16(i+10), le32(i+12), le32(i+16)
		if entries == 0xFFFF || dirSize == 0xFFFFFFFF || dirOffset == 0xFFFFFFFF {
			j := i - locatorLen
			if j < 0 || le32(j) != locatorSig {
				return 0, 0, 0
			}
			rec := le64(j+8) - base
			if rec < 0 || rec+eocd64Len > int64(j) || le32(int(rec)) != eocd64Sig {
				return 0, 0, 0
			}
			entries, dirSize, dirOffset = le64(int(rec)+32), le64(int(rec)+40), le64(int(rec)+48)
		}
		if entries <= 0 || dirSize < 0 || dirOffset < 0 || dirOffset+dirSize > size {
			return 0, 0, 0
		}
		return entries, dirSize, dirOffset
	}
	return 0, 0, 0
}

// remoteZip reads entries of an all.zip with Range requests.
type remoteZip struct {
	r  *rangeReader
	zr *zip.Reader
}

// openRemoteZip reads the central directory of the probed all.zip: one Range read on top of the
// probe's tail.
func openRemoteZip(ctx context.Context, c *http.Client, url string, p zipProbe) (*remoteZip, error) {
	r := &rangeReader{ctx: ctx, c: c, url: url, size: p.size, version: p.version,
		base: p.size - int64(len(p.tail)), buf: p.tail, grow: true}
	zr, err := zip.NewReader(r, p.size)
	if err != nil && !errors.Is(err, zip.ErrInsecurePath) { // such entries are skipped by name
		return nil, fmt.Errorf("osv: %s: %w", url, err)
	}
	r.mu.Lock()
	r.grow = false
	r.mu.Unlock()
	return &remoteZip{r: r, zr: zr}, nil
}

// read returns the uncompressed content of zf, which must be at most maxRecordBytes: a Range read
// of its local header (archive/zip keeps the header's offset to itself), then one of its data.
func (z *remoteZip) read(zf *zip.File) ([]byte, error) {
	if zf.UncompressedSize64 > maxRecordBytes || zf.CompressedSize64 > 2*maxRecordBytes {
		return nil, feeds.ErrTooLarge
	}
	off, err := zf.DataOffset()
	if err != nil {
		return nil, fmt.Errorf("osv: all.zip %s: %w", zf.Name, err)
	}
	data := make([]byte, zf.CompressedSize64)
	if _, err := z.r.ReadAt(data, off); err != nil {
		return nil, fmt.Errorf("osv: all.zip %s: %w", zf.Name, err)
	}
	var raw []byte
	switch zf.Method {
	case zip.Store:
		raw = data
	case zip.Deflate:
		fr := flate.NewReader(bytes.NewReader(data))
		raw, err = io.ReadAll(io.LimitReader(fr, maxRecordBytes+1))
		_ = fr.Close()
		if err != nil {
			return nil, fmt.Errorf("osv: all.zip %s: %w", zf.Name, err)
		}
	default:
		return nil, fmt.Errorf("osv: all.zip %s: %w", zf.Name, zip.ErrAlgorithm)
	}
	if uint64(len(raw)) != zf.UncompressedSize64 || crc32.ChecksumIEEE(raw) != zf.CRC32 {
		return nil, fmt.Errorf("osv: all.zip %s: %w", zf.Name, zip.ErrChecksum)
	}
	return raw, nil
}

// rangeReader is an io.ReaderAt over a remote object, read with Range requests. It holds the
// object's end, [base, size), from the probe. While grow is set (the central directory is being
// read) a read below base extends that cached end down to it in one request; after that, reads
// outside it are fetched exactly and not kept. Every response must come from the probed version of
// the object. It is safe for concurrent use.
type rangeReader struct {
	ctx     context.Context
	c       *http.Client
	url     string
	size    int64
	version string

	mu   sync.Mutex
	base int64
	buf  []byte
	grow bool
}

func (r *rangeReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("osv: %s: negative offset", r.url)
	}
	if off >= r.size {
		return 0, io.EOF
	}
	end := min(off+int64(len(p)), r.size)
	var eof error
	if end-off < int64(len(p)) {
		eof = io.EOF
	}
	r.mu.Lock()
	if off >= r.base {
		n := copy(p, r.buf[off-r.base:])
		r.mu.Unlock()
		return n, eof
	}
	if r.grow { // only zip.NewReader reads now, from one goroutine
		defer r.mu.Unlock()
		if r.base-off > maxDirBytes {
			return 0, fmt.Errorf("%w: %s: central directory over %d bytes", feeds.ErrTooLarge, r.url, maxDirBytes)
		}
		data, err := r.fetch(off, r.base)
		if err != nil {
			return 0, err
		}
		r.buf, r.base = append(data, r.buf...), off
		return copy(p, r.buf), eof
	}
	r.mu.Unlock()
	data, err := r.fetch(off, end)
	if err != nil {
		return 0, err
	}
	return copy(p, data), eof
}

// fetch reads [from, to) of the object.
func (r *rangeReader) fetch(from, to int64) ([]byte, error) {
	resp, err := feeds.Fetch(r.ctx, r.c, feeds.Request{URL: r.url, Range: fmt.Sprintf("bytes=%d-%d", from, to-1), MaxBytes: to - from})
	if err != nil {
		return nil, err
	}
	if resp.Status != http.StatusPartialContent || int64(len(resp.Body)) != to-from {
		return nil, fmt.Errorf("osv: %s: Range read of bytes %d-%d answered %d with %d bytes", r.url, from, to-1, resp.Status, len(resp.Body))
	}
	if v := versionOf(resp); v != r.version {
		return nil, fmt.Errorf("osv: %s was replaced during the read", r.url)
	}
	return resp.Body, nil
}
