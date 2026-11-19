package feeds_test

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/feeds"
)

const testUA = "ffs-test/1.0"

func TestFetch_LimitsAndConditional(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/big", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("01234567890")) // 11 bytes
	})
	mux.HandleFunc("/etag", func(w http.ResponseWriter, r *http.Request) {
		if r.UserAgent() != testUA {
			http.Error(w, "missing user agent", http.StatusBadRequest)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("x-goog-generation", "1763489984000000")
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write([]byte("body"))
	})
	mux.HandleFunc("/missing", http.NotFound)
	mux.HandleFunc("/epss_scores-current.csv.gz", func(w http.ResponseWriter, _ *http.Request) {
		// set by hand: http.Redirect would rewrite the relative target to an absolute path
		w.Header().Set("Location", "epss_scores-2026-11-18.csv.gz")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/epss_scores-2026-11-18.csv.gz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("csv"))
	})
	mux.HandleFunc("/modified_id.csv", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") == "bytes=100-" {
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		}
		_, _ = w.Write([]byte("rows"))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := feeds.NewHTTPClient(testUA)

	_, err := feeds.Fetch(ctx, c, feeds.Request{URL: srv.URL + "/big", MaxBytes: 10})
	require.ErrorIs(t, err, feeds.ErrTooLarge)
	resp, err := feeds.Fetch(ctx, c, feeds.Request{URL: srv.URL + "/big", MaxBytes: 11})
	require.NoError(t, err)
	require.Equal(t, "01234567890", string(resp.Body))

	resp, err = feeds.Fetch(ctx, c, feeds.Request{URL: srv.URL + "/etag", MaxBytes: 1 << 10})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.Status)
	require.Equal(t, "body", string(resp.Body))
	require.Equal(t, `"v1"`, resp.ETag)
	require.Equal(t, "1763489984000000", resp.Generation)
	resp, err = feeds.Fetch(ctx, c, feeds.Request{URL: srv.URL + "/etag", ETag: resp.ETag, MaxBytes: 1 << 10})
	require.NoError(t, err)
	require.Equal(t, http.StatusNotModified, resp.Status)
	require.Empty(t, resp.Body)

	_, err = feeds.Fetch(ctx, c, feeds.Request{URL: srv.URL + "/missing", MaxBytes: 1 << 10})
	require.ErrorIs(t, err, feeds.ErrNotFound)

	resp, err = feeds.Fetch(ctx, c, feeds.Request{URL: srv.URL + "/epss_scores-current.csv.gz", MaxBytes: 1 << 10, NoRedirect: true})
	require.NoError(t, err)
	require.Equal(t, http.StatusFound, resp.Status)
	require.Equal(t, "epss_scores-2026-11-18.csv.gz", resp.Location)
	resp, err = feeds.Fetch(ctx, c, feeds.Request{URL: srv.URL + "/epss_scores-current.csv.gz", MaxBytes: 1 << 10})
	require.NoError(t, err)
	require.Equal(t, "csv", string(resp.Body), "redirects are followed without NoRedirect")

	resp, err = feeds.Fetch(ctx, c, feeds.Request{URL: srv.URL + "/modified_id.csv", Range: "bytes=100-", MaxBytes: 1 << 10})
	require.NoError(t, err)
	require.Equal(t, http.StatusRequestedRangeNotSatisfiable, resp.Status)
	require.Empty(t, resp.Body)
}

func TestFetch_DownloadLimitsAndCleansUp(t *testing.T) {
	payload := []byte(strings.Repeat("x", 20))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// flush between halves so the response is chunked and the limit is hit while streaming
		_, _ = w.Write(payload[:10])
		w.(http.Flusher).Flush()
		_, _ = w.Write(payload[10:])
	}))
	t.Cleanup(srv.Close)
	c := feeds.NewHTTPClient(testUA)
	dst := filepath.Join(t.TempDir(), "archive")

	_, err := feeds.Download(ctx, c, srv.URL, dst, 10, nil)
	require.ErrorIs(t, err, feeds.ErrTooLarge)
	require.NoFileExists(t, dst)
	require.NoFileExists(t, dst+".part")

	h := sha256.New()
	n, err := feeds.Download(ctx, c, srv.URL, dst, 20, h)
	require.NoError(t, err)
	require.Equal(t, int64(20), n)
	got, err := os.ReadFile(dst) //nolint:gosec // G304: test temp path
	require.NoError(t, err)
	require.Equal(t, payload, got)
	want := sha256.Sum256(payload)
	require.Equal(t, want[:], h.Sum(nil))
	require.NoFileExists(t, dst+".part")
}
