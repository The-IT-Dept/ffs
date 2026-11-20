package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/the-it-dept/ffs/internal/agentapi/wire"
	"github.com/the-it-dept/ffs/internal/version"
)

const (
	// clientTimeout bounds one request. It is longer than the controller may queue host preparation during a
	// DaemonSet rollout; the agent API server's write timeout is longer still.
	clientTimeout = 10 * time.Minute
	// maxErrorBody bounds the {"error": …} body of a non-2xx response.
	maxErrorBody = 64 << 10
	// maxResponseBody bounds a report response or the agent config.
	maxResponseBody = 4 << 20
	// maxRetryAfter caps the controller's Retry-After.
	maxRetryAfter = time.Hour
)

// StatusError is a non-2xx answer from the controller. Msg is the "error" of its JSON body; RetryAfter is its
// Retry-After header (0 when absent or unreadable).
type StatusError struct {
	Code       int
	Msg        string
	RetryAfter time.Duration
}

func (e *StatusError) Error() string {
	if e.Msg == "" {
		return fmt.Sprintf("controller answered %d", e.Code)
	}
	return fmt.Sprintf("controller answered %d: %s", e.Code, e.Msg)
}

// Client sends reports and SBOM results to the controller's agent API. It re-reads the CA bundle and the
// projected token before every request, so rotated files take effect without a restart. The token is never
// logged.
type Client struct {
	base      *url.URL
	caFile    string
	tokenFile string

	mu   sync.Mutex
	ca   []byte
	http *http.Client
}

// NewClient returns a client of the controller at controller (an https URL), trusting the CA bundle in caFile
// and authenticating with the token in tokenFile.
func NewClient(controller, caFile, tokenFile string) (*Client, error) {
	u, err := url.Parse(controller)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("controller URL must be https")
	}
	return &Client{base: u, caFile: caFile, tokenFile: tokenFile}, nil
}

// httpClient returns the client for the current CA bundle, rebuilding the transport when the bundle changed.
func (c *Client) httpClient() (*http.Client, error) {
	ca, err := os.ReadFile(c.caFile)
	if err != nil {
		return nil, fmt.Errorf("reading the controller CA: %w", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.http != nil && bytes.Equal(ca, c.ca) {
		return c.http, nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("the controller CA file %s holds no certificate", c.caFile)
	}
	if c.http != nil {
		c.http.CloseIdleConnections()
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	c.ca, c.http = ca, &http.Client{Transport: tr, Timeout: clientTimeout}
	return c.http, nil
}

func (c *Client) token() (string, error) {
	b, err := os.ReadFile(c.tokenFile)
	if err != nil {
		return "", fmt.Errorf("reading the agent token: %w", err)
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", fmt.Errorf("the agent token file %s is empty", c.tokenFile)
	}
	return tok, nil
}

// do sends one request and decodes a 2xx JSON answer into out (when non-nil).
func (c *Client) do(ctx context.Context, method, path string, body *splicedBody, out any) error {
	hc, err := c.httpClient()
	if err != nil {
		return err
	}
	tok, err := c.token()
	if err != nil {
		return err
	}
	var rd io.ReadCloser
	if body != nil {
		if rd, err = body.open(); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base.JoinPath(path).String(), rd)
	if err != nil {
		if rd != nil {
			_ = rd.Close()
		}
		return err
	}
	if body != nil {
		req.ContentLength = body.size()
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("User-Agent", version.UserAgent())
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, maxErrorBody)).Decode(&e)
		return &StatusError{Code: resp.StatusCode, Msg: e.Error, RetryAfter: retryAfter(resp.Header.Get("Retry-After"), time.Now())}
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBody))
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBody)).Decode(out); err != nil {
		return fmt.Errorf("decoding the controller's answer: %w", err)
	}
	return nil
}

// retryAfter reads a Retry-After header: delay-seconds or an HTTP date. It is 0 when absent or unreadable.
func retryAfter(h string, now time.Time) time.Duration {
	h = strings.TrimSpace(h)
	if h == "" {
		return 0
	}
	if secs, err := strconv.ParseInt(h, 10, 64); err == nil {
		if secs <= 0 {
			return 0
		}
		return time.Duration(min(secs, int64(maxRetryAfter/time.Second))) * time.Second
	}
	if t, err := http.ParseTime(h); err == nil && t.After(now) {
		return min(t.Sub(now), maxRetryAfter)
	}
	return 0
}

// sbomFile is a syft-json document spooled to a scratch file.
type sbomFile struct {
	path string
	size int64
}

// Report sends r to POST /agent/v1/report. When hostSBOM is set, r.Host's SBOM is streamed from that file in
// place of r.Host.SyftJSON; otherwise r.Host.SyftJSON is sent as it is.
func (c *Client) Report(ctx context.Context, r wire.Report, hostSBOM *sbomFile) (wire.ReportResponse, error) {
	body, err := encodeReport(r, hostSBOM)
	if err != nil {
		return wire.ReportResponse{}, err
	}
	return c.sendReport(ctx, &body)
}

// sendReport sends an encoded report (encodeReport) to POST /agent/v1/report.
func (c *Client) sendReport(ctx context.Context, body *splicedBody) (wire.ReportResponse, error) {
	var resp wire.ReportResponse
	err := c.do(ctx, http.MethodPost, wire.PathReport, body, &resp)
	return resp, err
}

// SBOM sends res to POST /agent/v1/sbom. When doc is set, the SBOM is streamed from that file in place of
// res.SyftJSON.
func (c *Client) SBOM(ctx context.Context, res wire.SBOMResult, doc *sbomFile) error {
	body, err := encodeSpliced(&res, &res.SyftJSON, doc)
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodPost, wire.PathSBOM, &body, nil)
}

// Config fetches GET /agent/v1/config.
func (c *Client) Config(ctx context.Context) (wire.AgentConfig, error) {
	var cfg wire.AgentConfig
	err := c.do(ctx, http.MethodGet, wire.PathConfig, nil, &cfg)
	return cfg, err
}

// splicedBody is a JSON document held as the encoding of its small fields around one large field, which is
// streamed from a scratch file: the collector never holds an SBOM in memory.
type splicedBody struct {
	prefix, suffix []byte
	doc            *sbomFile // nil: the document is prefix alone
}

func (b *splicedBody) size() int64 {
	n := int64(len(b.prefix) + len(b.suffix))
	if b.doc != nil {
		n += b.doc.size
	}
	return n
}

// open returns the body as a reader; closing it closes the file.
func (b *splicedBody) open() (io.ReadCloser, error) {
	if b.doc == nil {
		return io.NopCloser(bytes.NewReader(b.prefix)), nil
	}
	f, err := os.Open(b.doc.path)
	if err != nil {
		return nil, fmt.Errorf("opening the spooled SBOM: %w", err)
	}
	return &fileBody{Reader: io.MultiReader(bytes.NewReader(b.prefix), io.LimitReader(f, b.doc.size), bytes.NewReader(b.suffix)), f: f}, nil
}

// fileBody is a request body read partly from a file.
type fileBody struct {
	io.Reader
	f *os.File
}

func (b *fileBody) Close() error { return b.f.Close() }

// encodeReport encodes r with its host SBOM spliced in from hostSBOM, when set.
func encodeReport(r wire.Report, hostSBOM *sbomFile) (splicedBody, error) {
	if r.Host == nil || hostSBOM == nil {
		b, err := json.Marshal(r)
		return splicedBody{prefix: b}, err
	}
	h := *r.Host
	r.Host = &h
	return encodeSpliced(&r, &h.SyftJSON, hostSBOM)
}

// encodeSpliced encodes v. When doc is set, *raw (a field of v) is replaced by a unique placeholder and the
// encoding is split around it, so the document is streamed from doc in its place; *raw is restored before it
// returns. The document was checked to be JSON as it was spooled.
func encodeSpliced(v any, raw *json.RawMessage, doc *sbomFile) (splicedBody, error) {
	if doc == nil {
		b, err := json.Marshal(v)
		return splicedBody{prefix: b}, err
	}
	saved := *raw
	defer func() { *raw = saved }()
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	placeholder := []byte(`"ffs-splice-` + hex.EncodeToString(nonce) + `"`)
	*raw = placeholder
	b, err := json.Marshal(v)
	if err != nil {
		return splicedBody{}, err
	}
	i := bytes.Index(b, placeholder)
	if i < 0 {
		return splicedBody{}, errors.New("encoding the report: placeholder not found")
	}
	return splicedBody{prefix: b[:i], suffix: b[i+len(placeholder):], doc: doc}, nil
}
