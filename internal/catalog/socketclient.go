package catalog

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/sbom"
	"github.com/the-it-dept/ffs/internal/version"
)

const (
	socketCatalogURL = "http://catalog/v1/catalog"
	// maxSocketResponse bounds a successful response: the largest SBOM the controller accepts and room
	// for the coverage around it.
	maxSocketResponse = sbom.MaxSBOMBytes + 1<<20
	// maxSocketError bounds an error response.
	maxSocketError = 64 << 10
	// maxEnvelopeMember bounds each member of a successful response other than the syft-json document.
	maxEnvelopeMember = 1 << 20
	// maxEnvelopeKey bounds a member name of a successful response.
	maxEnvelopeKey = 1 << 10
	// spoolBuffer is the read and write buffer used to stream the syft-json document to its file.
	spoolBuffer = 64 << 10
	// msgSocketStopped is the failure of a job whose connection to the cataloguer was lost.
	msgSocketStopped = "cataloguer stopped while processing the job"
	// msgUnreadable is the failure of a job whose response is not a catalog response.
	msgUnreadable = "cataloguer returned an unreadable response"
)

// errMemberTooLarge is a response member over maxEnvelopeMember or maxEnvelopeKey.
var errMemberTooLarge = errors.New("response member too large")

// SocketClient sends catalog jobs to an `ffs catalog` server on its unix socket: the node agent's
// collector uses it to have the non-root cataloguer catalogue what it staged.
type SocketClient struct {
	http    *http.Client
	timeout time.Duration
}

// NewSocketClient returns a client of the cataloguer at socket whose jobs time out after timeout.
// Every job gets a fresh connection: one kept from before a cataloguer restart would fail
// mid-request and be counted against an innocent job.
func NewSocketClient(socket string, timeout time.Duration) *SocketClient {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
		DisableKeepAlives: true,
	}
	return &SocketClient{http: &http.Client{Transport: tr, Timeout: timeout}, timeout: timeout}
}

// SBOMFile is the syft-json document of a catalog job, written to a file, and its coverage.
type SBOMFile struct {
	Path     string // the file holding the document
	Size     int64  // the document's size in bytes
	Coverage model.Coverage
}

// Catalog runs one job and streams the syft-json document of its response, byte for byte, into the file
// dst (created 0600, or truncated), checking its syntax on the way. The document never sits in memory, so
// the collector's footprint does not grow with the SBOM. dst is removed when Catalog fails. A failure is a
// *WorkError:
//   - the cataloguer's error response keeps its kind and message;
//   - a response over the controller's SBOM limit is KindTooLarge;
//   - a response that is not a catalog response is KindFailed;
//   - a socket that cannot be dialled is KindBusy "cataloguer unavailable: <err>" (the job was not
//     attempted);
//   - a connection lost after the request was sent is KindFailed;
//   - no answer within the client timeout is KindTimeout.
//
// A document that cannot be written to dst is a *ScratchError instead: the scratch volume is full or not
// writable, which says nothing about the job. When ctx ends first, the error wraps ctx's error instead.
func (c *SocketClient) Catalog(ctx context.Context, req sbom.CatalogRequest, dst string) (out *SBOMFile, err error) {
	defer func() {
		if err != nil {
			_ = os.Remove(dst)
		}
	}()
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, socketCatalogURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("Content-Type", "application/json")
	hreq.Header.Set("User-Agent", version.UserAgent())
	resp, err := c.http.Do(hreq)
	if err != nil {
		return nil, c.transportError(ctx, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		var ce sbom.CatalogError
		_ = json.NewDecoder(io.LimitReader(resp.Body, maxSocketError)).Decode(&ce)
		if ce.Kind == "" {
			return nil, &WorkError{Kind: sbom.KindFailed, Msg: fmt.Sprintf("cataloguer answered %d", resp.StatusCode)}
		}
		return nil, &WorkError{Kind: ce.Kind, Msg: ce.Error}
	}
	lr := &io.LimitedReader{R: resp.Body, N: maxSocketResponse + 1}
	if out, err = spool(bufio.NewReaderSize(lr, spoolBuffer), dst); err == nil {
		return out, nil
	}
	var se *ScratchError
	switch {
	case errors.As(err, &se):
		return nil, se
	case lr.N <= 0:
		return nil, &WorkError{Kind: sbom.KindTooLarge,
			Msg: fmt.Sprintf("cataloguer response is larger than the %d byte limit", maxSocketResponse)}
	case errors.Is(err, errJSONSyntax), errors.Is(err, errMemberTooLarge):
		return nil, &WorkError{Kind: sbom.KindFailed, Msg: msgUnreadable}
	}
	return nil, c.transportError(ctx, err)
}

// ScratchError is a failure to create or write the caller's scratch file for the SBOM document (ENOSPC,
// EACCES, EROFS…): the collector could not keep the result, which is no fault of the job.
type ScratchError struct{ Err error }

func (e *ScratchError) Error() string { return "writing the SBOM to scratch: " + e.Err.Error() }

func (e *ScratchError) Unwrap() error { return e.Err }

// spool reads a catalog response, {"syftJSON": <document>, "coverage": {...}}, from r, writing the document to
// the file dst. Members other than the document are read into memory up to maxEnvelopeMember; unknown ones are
// checked and skipped. A response without a document is a syntax error.
func spool(r *bufio.Reader, dst string) (*SBOMFile, error) {
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) //nolint:gosec // G304: dst is the caller's scratch file
	if err != nil {
		return nil, &ScratchError{err}
	}
	closed := false
	defer func() {
		if !closed {
			_ = f.Close()
		}
	}()
	doc := bufio.NewWriterSize(f, spoolBuffer)
	out := &SBOMFile{Path: dst}
	c := &jsonCopier{r: r}
	if err := c.expect('{'); err != nil {
		return nil, err
	}
	b, err := c.skipSpace()
	if err != nil {
		return nil, err
	}
	seen := false
	for b != '}' {
		if b != '"' {
			return nil, fmt.Errorf("%w: response member name must be a string", errJSONSyntax)
		}
		key, err := c.key()
		if err != nil {
			return nil, err
		}
		if err := c.expect(':'); err != nil {
			return nil, err
		}
		switch key {
		case "syftJSON":
			if seen {
				return nil, fmt.Errorf("%w: two syftJSON members", errJSONSyntax)
			}
			seen = true
			if err := c.copyValue(doc); err != nil {
				if c.werr != nil {
					return nil, &ScratchError{c.werr}
				}
				return nil, err
			}
		case "coverage":
			buf := &cappedBuffer{max: maxEnvelopeMember}
			if err := c.copyValue(buf); err != nil {
				return nil, err
			}
			if err := json.Unmarshal(buf.b.Bytes(), &out.Coverage); err != nil {
				return nil, fmt.Errorf("%w: coverage: %w", errJSONSyntax, err)
			}
		default:
			if err := c.copyValue(nil); err != nil {
				return nil, err
			}
		}
		if b, err = c.skipSpace(); err != nil {
			return nil, err
		}
		switch b {
		case '}':
		case ',':
			if b, err = c.skipSpace(); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("%w: found %q after a response member", errJSONSyntax, b)
		}
	}
	if !seen {
		return nil, fmt.Errorf("%w: no syftJSON member", errJSONSyntax)
	}
	if err := doc.Flush(); err != nil {
		return nil, &ScratchError{err}
	}
	fi, err := f.Stat()
	if err != nil {
		return nil, &ScratchError{err}
	}
	closed = true
	if err := f.Close(); err != nil {
		return nil, &ScratchError{err}
	}
	out.Size = fi.Size()
	return out, nil
}

// copyValue copies the next value to w (nil: checks and discards it).
func (c *jsonCopier) copyValue(w io.ByteWriter) error {
	c.w, c.werr = w, nil
	defer func() { c.w = nil }()
	if err := c.value(); err != nil {
		return err
	}
	return c.werr
}

// key reads a member name whose opening quote was already read.
func (c *jsonCopier) key() (string, error) {
	buf := &cappedBuffer{max: maxEnvelopeKey}
	c.w, c.werr = buf, nil
	defer func() { c.w = nil }()
	if err := c.put('"'); err != nil {
		return "", err
	}
	if err := c.str(); err != nil {
		return "", err
	}
	var k string
	if err := json.Unmarshal(buf.b.Bytes(), &k); err != nil {
		return "", fmt.Errorf("%w: member name: %w", errJSONSyntax, err)
	}
	return k, nil
}

// cappedBuffer collects up to max bytes.
type cappedBuffer struct {
	b   bytes.Buffer
	max int
}

func (c *cappedBuffer) WriteByte(b byte) error {
	if c.b.Len() >= c.max {
		return errMemberTooLarge
	}
	return c.b.WriteByte(b)
}

// transportError classifies a job that got no complete response.
func (c *SocketClient) transportError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("cataloguer: %w", ctx.Err())
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "dial" {
		return &WorkError{Kind: sbom.KindBusy, Msg: "cataloguer unavailable: " + err.Error()}
	}
	var ue *url.Error
	var ne net.Error
	if (errors.As(err, &ue) && ue.Timeout()) || (errors.As(err, &ne) && ne.Timeout()) {
		return &WorkError{Kind: sbom.KindTimeout, Msg: "cataloguer did not answer within " + c.timeout.String()}
	}
	return &WorkError{Kind: sbom.KindFailed, Msg: msgSocketStopped}
}
