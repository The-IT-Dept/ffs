package osv

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/the-it-dept/ffs/internal/feeds"
)

const (
	csvChunkBytes = 256 << 10 // one Range read of modified_id.csv
	maxCSVBytes   = 64 << 20  // a whole modified_id.csv
)

// csvRow is one modified_id.csv line: a record's modified time and ID.
type csvRow struct {
	ts time.Time
	id string
}

// csvReader reads a bucket's modified_id.csv, which lists the newest records first, one 256 KiB
// Range read at a time, so a poll reads only down to its watermark.
type csvReader struct {
	c     *http.Client
	url   string
	off   int64
	carry []byte // the partial last line of the previous chunk
	gen   string // x-goog-generation of the first response
	read  bool   // the first response has been seen
	done  bool   // the end of the file has been reached
}

func newCSVReader(c *http.Client, url string) *csvReader { return &csvReader{c: c, url: url} }

// next returns the complete rows of the next chunk; none once done. An empty file (the server
// answers the first Range read with 416) is done with no rows.
func (r *csvReader) next(ctx context.Context) ([]csvRow, error) {
	if r.done {
		return nil, nil
	}
	if r.off >= maxCSVBytes {
		return nil, fmt.Errorf("%w: %s: over %d bytes read", feeds.ErrTooLarge, r.url, maxCSVBytes)
	}
	resp, err := feeds.Fetch(ctx, r.c, feeds.Request{
		URL:      r.url,
		Range:    fmt.Sprintf("bytes=%d-%d", r.off, r.off+csvChunkBytes-1),
		MaxBytes: csvChunkBytes,
	})
	if err != nil {
		return nil, err
	}
	if !r.read {
		r.read, r.gen = true, resp.Generation
	} else if resp.Generation != "" && r.gen != "" && resp.Generation != r.gen {
		return nil, fmt.Errorf("osv: %s was replaced during the read", r.url)
	}

	var data []byte
	switch resp.Status {
	case http.StatusRequestedRangeNotSatisfiable: // the previous chunk ended exactly at the end
		r.done, data = true, r.carry
	case http.StatusPartialContent:
		data = append(r.carry, resp.Body...)
		r.off += int64(len(resp.Body))
		r.done = len(resp.Body) < csvChunkBytes
	default: // 200: the server sent the whole (small) file
		if r.off > 0 {
			return nil, fmt.Errorf("osv: %s: Range ignored after the first read", r.url)
		}
		r.done, data = true, resp.Body
	}
	r.carry = nil
	if !r.done {
		i := bytes.LastIndexByte(data, '\n')
		if i < 0 {
			if len(data) > csvChunkBytes {
				return nil, fmt.Errorf("osv: %s: line over %d bytes", r.url, csvChunkBytes)
			}
			r.carry = data
			return nil, nil
		}
		r.carry = bytes.Clone(data[i+1:])
		data = data[:i+1]
	}
	return parseRows(data), nil
}

// parseRows parses "timestamp,id" lines, skipping lines without a valid RFC 3339 timestamp. A row
// with an empty ID is kept, so its timestamp still counts.
func parseRows(data []byte) []csvRow {
	var rows []csvRow
	for len(data) > 0 {
		var line []byte
		line, data, _ = bytes.Cut(data, []byte{'\n'})
		ts, id, ok := strings.Cut(string(bytes.TrimRight(line, "\r")), ",")
		if !ok {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			continue
		}
		rows = append(rows, csvRow{ts: t.UTC(), id: strings.TrimSpace(id)})
	}
	return rows
}

// listIDs reads a whole modified_id.csv and returns the IDs it lists, each with its newest
// modified time.
func listIDs(ctx context.Context, c *http.Client, url string) (map[string]time.Time, error) {
	resp, err := feeds.Fetch(ctx, c, feeds.Request{URL: url, MaxBytes: maxCSVBytes})
	if err != nil {
		return nil, err
	}
	rows := parseRows(resp.Body)
	ids := make(map[string]time.Time, len(rows))
	for _, row := range rows {
		if t, ok := ids[row.id]; row.id != "" && (!ok || row.ts.After(t)) {
			ids[row.id] = row.ts
		}
	}
	return ids, nil
}
