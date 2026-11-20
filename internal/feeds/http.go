package feeds

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
)

var (
	// ErrTooLarge means a response or archive exceeded its size limit.
	ErrTooLarge = errors.New("feeds: size limit exceeded")
	// ErrNotFound means the server answered 404.
	ErrNotFound = errors.New("feeds: not found")
	// ErrImplausible means a feed answered with a body that parses but cannot be right: empty,
	// reshaped, or far smaller than the last one accepted. The stored data is kept.
	ErrImplausible = errors.New("feeds: implausible response")
)

// CheckShrink returns an ErrImplausible error when a feed whose last accepted body had prev
// entries now has fewer than half as many. A prev of zero (nothing accepted yet) passes.
func CheckShrink(feed string, prev, now int) error {
	if prev > 0 && now < prev/2 {
		return fmt.Errorf("%w: %s has %d entries, down from %d; keeping the stored data", ErrImplausible, feed, now, prev)
	}
	return nil
}

// NewHTTPClient returns a client for feed downloads. It keeps the default transport's proxy
// settings (HTTP_PROXY, HTTPS_PROXY, NO_PROXY), requires TLS 1.2 or later, sends userAgent when a
// request has no User-Agent and has no overall timeout: the request context governs.
func NewHTTPClient(userAgent string) *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	if t.TLSClientConfig == nil {
		t.TLSClientConfig = &tls.Config{} //nolint:gosec // G402: MinVersion is set on the next line
	}
	t.TLSClientConfig.MinVersion = tls.VersionTLS12
	return &http.Client{Transport: &userAgentTransport{base: t, userAgent: userAgent}}
}

type userAgentTransport struct {
	base      http.RoundTripper
	userAgent string
}

func (u *userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if u.userAgent == "" || req.Header.Get("User-Agent") != "" {
		return u.base.RoundTrip(req)
	}
	req = req.Clone(req.Context())
	req.Header.Set("User-Agent", u.userAgent)
	return u.base.RoundTrip(req)
}

// Request is a size-limited GET.
type Request struct {
	URL        string
	ETag       string // sent as If-None-Match
	Range      string // sent as Range, e.g. "bytes=0-65535"
	MaxBytes   int64  // required body limit; a larger body fails with ErrTooLarge
	NoRedirect bool   // return a 3xx response as-is instead of following it
}

// Response is the outcome of Fetch. Body is set only for 2xx responses.
type Response struct {
	Status     int
	Body       []byte
	ETag       string
	Generation string // x-goog-generation
	Location   string
	// Total is the size of the whole resource: from Content-Range for a 206, else Content-Length;
	// -1 when the server did not say.
	Total int64
}

// Fetch performs r. A 2xx body is read whole, up to MaxBytes. 304, 416 and (with NoRedirect) 3xx
// responses return their status with a nil error; 404 returns ErrNotFound; any other status is an
// error.
func Fetch(ctx context.Context, c *http.Client, r Request) (Response, error) {
	if r.MaxBytes <= 0 {
		return Response{}, fmt.Errorf("feeds: GET %s: MaxBytes must be positive", r.URL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.URL, nil)
	if err != nil {
		return Response{}, err
	}
	if r.ETag != "" {
		req.Header.Set("If-None-Match", r.ETag)
	}
	if r.Range != "" {
		req.Header.Set("Range", r.Range)
	}
	if r.NoRedirect {
		nc := *c
		nc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		c = &nc
	}
	resp, err := c.Do(req)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	out := Response{
		Status:     resp.StatusCode,
		ETag:       resp.Header.Get("ETag"),
		Generation: resp.Header.Get("x-goog-generation"),
		Location:   resp.Header.Get("Location"),
		Total:      resp.ContentLength,
	}
	if resp.StatusCode == http.StatusPartialContent {
		out.Total = rangeTotal(resp.Header.Get("Content-Range"))
	}
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		out.Body, err = io.ReadAll(io.LimitReader(resp.Body, r.MaxBytes+1))
		if err != nil {
			return out, fmt.Errorf("feeds: GET %s: %w", r.URL, err)
		}
		if int64(len(out.Body)) > r.MaxBytes {
			return out, fmt.Errorf("%w: GET %s: body over %d bytes", ErrTooLarge, r.URL, r.MaxBytes)
		}
		return out, nil
	case resp.StatusCode == http.StatusNotModified, resp.StatusCode == http.StatusRequestedRangeNotSatisfiable:
		return out, nil
	case r.NoRedirect && resp.StatusCode >= 300 && resp.StatusCode < 400:
		return out, nil
	case resp.StatusCode == http.StatusNotFound:
		return out, fmt.Errorf("%w: GET %s", ErrNotFound, r.URL)
	default:
		return out, fmt.Errorf("feeds: GET %s: %s", r.URL, resp.Status)
	}
}

// rangeTotal returns the complete length of a "bytes first-last/complete" Content-Range, or -1.
func rangeTotal(v string) int64 {
	_, total, ok := strings.Cut(v, "/")
	if !ok || !strings.HasPrefix(v, "bytes ") {
		return -1
	}
	n, err := strconv.ParseInt(total, 10, 64)
	if err != nil || n < 0 {
		return -1
	}
	return n
}

// Download streams url into dst, writing dst+".part" first (hashed into h when h is non-nil) and
// renaming it on success. The .part file is removed on any error. It returns the bytes written.
func Download(ctx context.Context, c *http.Client, url, dst string, maxBytes int64, h hash.Hash) (n int64, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return 0, fmt.Errorf("%w: GET %s", ErrNotFound, url)
	case resp.StatusCode != http.StatusOK:
		return 0, fmt.Errorf("feeds: GET %s: %s", url, resp.Status)
	case resp.ContentLength > maxBytes:
		return 0, fmt.Errorf("%w: GET %s: %d bytes over the %d limit", ErrTooLarge, url, resp.ContentLength, maxBytes)
	}

	part := dst + ".part"
	f, err := os.OpenFile(part, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) //nolint:gosec // G304: dst is built by the calling feed under its data directory
	if err != nil {
		return 0, err
	}
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(part)
		}
	}()
	var w io.Writer = f
	if h != nil {
		w = io.MultiWriter(f, h)
	}
	if n, err = io.Copy(w, io.LimitReader(resp.Body, maxBytes+1)); err != nil {
		return n, fmt.Errorf("feeds: GET %s: %w", url, err)
	}
	if n > maxBytes {
		return n, fmt.Errorf("%w: GET %s: body over %d bytes", ErrTooLarge, url, maxBytes)
	}
	if err = f.Close(); err != nil {
		return n, err
	}
	if err = os.Rename(part, dst); err != nil {
		return n, err
	}
	return n, nil
}
