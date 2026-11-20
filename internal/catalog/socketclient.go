package catalog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

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
	// msgSocketStopped is the failure of a job whose connection to the cataloguer was lost.
	msgSocketStopped = "cataloguer stopped while processing the job"
)

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

// Catalog runs one job and returns its response, decoded from the body in one pass, so the caller
// holds the SBOM once. A failure is a *WorkError:
//   - the cataloguer's error response keeps its kind and message;
//   - a response over the controller's SBOM limit is KindTooLarge;
//   - a socket that cannot be dialled is KindBusy "cataloguer unavailable: <err>" (the job was not
//     attempted);
//   - a connection lost after the request was sent is KindFailed;
//   - no answer within the client timeout is KindTimeout.
//
// When ctx ends first, the error wraps ctx's error instead.
func (c *SocketClient) Catalog(ctx context.Context, req sbom.CatalogRequest) (*sbom.CatalogResponse, error) {
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
	var cr sbom.CatalogResponse
	lr := &io.LimitedReader{R: resp.Body, N: maxSocketResponse + 1}
	if err := json.NewDecoder(lr).Decode(&cr); err != nil {
		var syntax *json.SyntaxError
		var typ *json.UnmarshalTypeError
		switch {
		case lr.N <= 0:
			return nil, &WorkError{Kind: sbom.KindTooLarge,
				Msg: fmt.Sprintf("cataloguer response is larger than the %d byte limit", maxSocketResponse)}
		case errors.As(err, &syntax), errors.As(err, &typ):
			return nil, &WorkError{Kind: sbom.KindFailed, Msg: "cataloguer returned an unreadable response"}
		}
		return nil, c.transportError(ctx, err)
	}
	return &cr, nil
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
