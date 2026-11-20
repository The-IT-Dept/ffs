package sbom

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

	"github.com/google/go-containerregistry/pkg/authn"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/registry"
)

const (
	registrySource = "registry"
	catalogURL     = "http://catalog/v1/catalog"
	// catalogSlack is how long past the job timeout the client waits before giving up on the cataloguer.
	catalogSlack = 30 * time.Second
	// maxCatalogError bounds an error response body.
	maxCatalogError = 64 << 10
	// catalogReservation covers the manifest GETs one job makes: the cataloguer's size pre-check and
	// stereoscope's pull.
	catalogReservation = 2

	reasonStopped     = "cataloguer stopped while processing the image"
	reasonUnavailable = "registry not reachable from the cataloguer"
	reasonScratchFull = "image unpacked beyond the cataloguer scratch limit"
)

// errCatalogRefused marks a request the cataloguer refused as invalid (400): another owner's
// credentials would not change the answer.
var errCatalogRefused = errors.New("sbom: the cataloguer refused the request")

// catalogRegistry is the part of the registry client the catalog source uses.
type catalogRegistry interface {
	PullRepo(repo string) string
	Auth(ctx context.Context, repo string, cs registry.CredSet) (authn.AuthConfig, error)
	Reserve(ctx context.Context, repo string, n int) error
}

// CatalogSource catalogues an image by sending it to the cataloguer in the catalog container. The
// cataloguer pulls the image itself with the credentials passed per job.
type CatalogSource struct {
	reg  catalogRegistry
	cfg  config.CatalogConfig
	http *http.Client
}

// NewCatalogSource returns a source talking to the cataloguer on cfg.Socket.
func NewCatalogSource(reg *registry.Client, cfg config.CatalogConfig) *CatalogSource {
	socket := cfg.Socket
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
		// A fresh connection per job: a connection kept from before a cataloguer restart would fail
		// mid-request and be counted against an innocent image.
		DisableKeepAlives: true,
	}
	return &CatalogSource{reg: reg, cfg: cfg, http: &http.Client{Transport: tr, Timeout: cfg.Timeout + catalogSlack}}
}

// Name is the Source name recorded on results.
func (s *CatalogSource) Name() string { return registrySource }

// Acquire has the cataloguer pull and catalogue r's platform manifest. Packages are left for the
// caller to normalise from SyftJSON. The registry budget for the cataloguer's pulls is reserved just
// before the request is sent, so an attempt that fails before it (credentials that cannot be
// resolved) spends none.
func (s *CatalogSource) Acquire(ctx context.Context, r Request) (*Result, error) {
	a, err := s.reg.Auth(ctx, r.Repo, r.Creds)
	if err != nil {
		return nil, &AcquireError{Kind: FailTransient, Reason: "resolving pull credentials", Err: err}
	}
	body, err := json.Marshal(CatalogRequest{
		Ref:      s.reg.PullRepo(r.Repo) + "@" + r.Digest,
		Platform: r.Platform,
		Auth: CatalogAuth{
			Username:      a.Username,
			Password:      a.Password,
			RegistryToken: a.RegistryToken,
			IdentityToken: a.IdentityToken,
		},
		MaxBytes:       s.cfg.MaxImageBytes,
		TimeoutSeconds: int(s.cfg.Timeout.Seconds()),
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, catalogURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	if err := s.reg.Reserve(ctx, r.Repo, catalogReservation); err != nil {
		// A low budget means slower cataloguing, never a failure.
		return nil, &AcquireError{Kind: FailTransient, Reason: "waiting for the registry's rate budget", Err: err}
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, s.transportError(ctx, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusOK {
		var cr CatalogResponse
		body := &io.LimitedReader{R: resp.Body, N: MaxCatalogResponseBytes + 1}
		if err := json.NewDecoder(body).Decode(&cr); err != nil {
			if body.N <= 0 {
				return nil, &AcquireError{Kind: FailQuarantine,
					Reason: fmt.Sprintf("SBOM is larger than the %d byte limit", MaxSBOMBytes)}
			}
			return nil, &AcquireError{Kind: FailCounted, Reason: "cataloguer returned an unreadable response", Err: err}
		}
		if len(cr.SyftJSON) > MaxSBOMBytes {
			return nil, &AcquireError{Kind: FailQuarantine,
				Reason: fmt.Sprintf(reasonSBOMTooLarge, len(cr.SyftJSON), MaxSBOMBytes)}
		}
		if len(cr.SyftJSON) == 0 || string(cr.SyftJSON) == "null" {
			return nil, &AcquireError{Kind: FailCounted, Reason: "cataloguer returned no SBOM"}
		}
		return &Result{SyftJSON: cr.SyftJSON, Coverage: cr.Coverage, Source: registrySource}, nil
	}

	var ce CatalogError
	_ = json.NewDecoder(io.LimitReader(resp.Body, maxCatalogError)).Decode(&ce)
	return nil, s.statusError(r, resp.StatusCode, ce)
}

// transportError classifies a request that got no response.
func (s *CatalogSource) transportError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("cataloguer: %w", err)
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Op == "dial" {
		return &AcquireError{Kind: FailTransient, Reason: "cataloguer unavailable", Err: err}
	}
	var ue *url.Error
	if errors.As(err, &ue) && ue.Timeout() {
		return &AcquireError{Kind: FailCounted, Reason: "cataloguer timed out after " + s.cfg.Timeout.String(), Err: err}
	}
	return &AcquireError{Kind: FailCounted, Reason: reasonStopped, Err: err}
}

// cataloguerStopped reports a job that lost its connection to the cataloguer mid-request: the
// catalog container went down while processing it.
func cataloguerStopped(err error) bool {
	var ae *AcquireError
	return errors.As(err, &ae) && ae.Reason == reasonStopped
}

// scratchFull reports a job the cataloguer stopped for unpacking beyond its scratch limit. The limit
// is shared by the jobs running together, so with another job in flight either may have filled it.
func scratchFull(err error) bool {
	var ae *AcquireError
	return errors.As(err, &ae) && ae.Reason == reasonScratchFull
}

// statusError classifies a cataloguer error response.
func (s *CatalogSource) statusError(r Request, status int, ce CatalogError) error {
	switch status {
	case http.StatusUnauthorized:
		return &AcquireError{Kind: FailUnresolvable, Reason: fmt.Sprintf(registry.ReasonUnauthorized, r.Repo)}
	case http.StatusNotFound:
		return &AcquireError{Kind: FailUnresolvable, Reason: fmt.Sprintf(registry.ReasonNotFound, r.Repo+"@"+r.Digest)}
	case http.StatusRequestEntityTooLarge:
		return &AcquireError{Kind: FailQuarantine, Reason: ce.Error}
	case http.StatusTooManyRequests:
		return &AcquireError{Kind: FailTransient, Reason: "registry rate limited the cataloguer's pull"}
	case http.StatusBadGateway:
		return &AcquireError{Kind: FailTransient, Reason: reasonUnavailable, Err: errors.New(ce.Error)}
	case http.StatusServiceUnavailable:
		return &AcquireError{Kind: FailTransient, Reason: "cataloguer busy"}
	case http.StatusGatewayTimeout:
		return &AcquireError{Kind: FailCounted, Reason: "cataloguer timed out after " + s.cfg.Timeout.String()}
	case http.StatusInsufficientStorage:
		// Deterministic for an image that ran alone; the acquirer retries one that overlapped another
		// job alone first (scratchFull).
		return &AcquireError{Kind: FailQuarantine, Reason: reasonScratchFull}
	case http.StatusBadRequest:
		// The request can never succeed as it is (a reference or platform the cataloguer cannot use):
		// unresolvable, retried after UnresolvableRetry, never a strike toward quarantine.
		return &AcquireError{Kind: FailUnresolvable, Reason: "cataloguer rejected the request: " + ce.Error, Err: errCatalogRefused}
	default:
		msg := ce.Error
		if msg == "" {
			msg = fmt.Sprintf("status %d", status)
		}
		return &AcquireError{Kind: FailCounted, Reason: "cataloguer failed: " + msg}
	}
}
