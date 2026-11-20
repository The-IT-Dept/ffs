// Package catalog is the cataloguer that runs in the catalog container. A small HTTP server on a
// unix socket takes one job per request and runs Syft on it in a re-exec'd worker process, so an
// image that crashes, hangs or floods the scratch disk takes down only its own job.
package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
	_ "github.com/glebarez/go-sqlite" // the "sqlite" driver Syft's RPM cataloger needs; without it every image fails (see internal/store for why not modernc.org/sqlite)
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"

	"github.com/the-it-dept/ffs/internal/registry"
	"github.com/the-it-dept/ffs/internal/sbom"
)

// WorkError is a failed job. Kind is one of the sbom.Kind* constants.
type WorkError struct{ Kind, Msg string }

func (e *WorkError) Error() string { return e.Msg }

// Catalog pulls req.Ref and catalogues it with Syft, in process. It is the worker's body; the
// server runs it in a child process.
func Catalog(ctx context.Context, req sbom.CatalogRequest) (*sbom.CatalogResponse, error) {
	if !strings.Contains(req.Ref, "@sha256:") {
		return nil, &WorkError{Kind: sbom.KindBadRequest, Msg: fmt.Sprintf("ref %q is not pinned by a sha256 digest", req.Ref)}
	}
	platform, err := image.NewPlatform(req.Platform)
	if err != nil {
		return nil, &WorkError{Kind: sbom.KindBadRequest, Msg: err.Error()}
	}

	src, err := syft.GetSource(ctx, req.Ref, syft.DefaultGetSourceConfig().
		WithSources("registry").
		WithPlatform(platform).
		WithRegistryOptions(&image.RegistryOptions{Keychain: staticKeychain{req.Auth}}))
	if err != nil {
		return nil, workError(err)
	}
	defer func() { _ = src.Close() }()

	cfg := syft.DefaultCreateSBOMConfig().WithUnknownsConfig(cataloging.UnknownsConfig{
		RemoveWhenPackagesDefined:         true,
		IncludeExecutablesWithoutPackages: true,
	})
	// The grype CLI's settings, so matching sees what `grype sbom:` would: Go symbols for its
	// gosymbols qualifier, and packages without a version dropped.
	cfg.Packages.Golang = cfg.Packages.Golang.WithCaptureSymbols(cataloging.SymbolScopeAll)
	cfg.Compliance.MissingVersion = cataloging.ComplianceActionDrop

	doc, err := syft.CreateSBOM(ctx, src, cfg)
	if err != nil {
		return nil, workError(err)
	}
	if err := markRust(doc, src); err != nil {
		return nil, workError(err)
	}
	b, err := sbom.EncodeSyftJSON(doc)
	if err != nil {
		return nil, workError(err)
	}
	return &sbom.CatalogResponse{SyftJSON: b, Coverage: sbom.CoverageOf(doc)}, nil
}

// RunWorker reads one CatalogRequest from in, runs Catalog and writes a CatalogResponse, or a
// CatalogError and a non-nil error (the process then exits 1), to out.
func RunWorker(ctx context.Context, in io.Reader, out io.Writer) error {
	var req sbom.CatalogRequest
	var resp *sbom.CatalogResponse
	err := json.NewDecoder(in).Decode(&req)
	if err != nil {
		err = &WorkError{Kind: sbom.KindBadRequest, Msg: "invalid request: " + err.Error()}
	} else {
		resp, err = Catalog(ctx, req)
	}
	if err != nil {
		we := workError(err)
		if werr := json.NewEncoder(out).Encode(sbom.CatalogError{Kind: we.Kind, Error: we.Msg}); werr != nil {
			return errors.Join(we, werr)
		}
		return we
	}
	return json.NewEncoder(out).Encode(resp)
}

// workError classifies err: a WorkError keeps its kind, registry refusals map to their kinds, a
// registry that cannot be reached or answers with a server error is unavailable, and anything else
// is a failure. Only failures count toward quarantine, so the classification also reads errors that
// stereoscope flattened to text (it wraps registry errors with %+v, which drops their type).
func workError(err error) *WorkError {
	var we *WorkError
	if errors.As(err, &we) {
		return we
	}
	err = registry.Classify(err)
	var kind string
	switch {
	case errors.Is(err, registry.ErrUnauthorized):
		kind = sbom.KindUnauthorized
	case errors.Is(err, registry.ErrNotFound):
		kind = sbom.KindNotFound
	case errors.Is(err, registry.ErrRateLimited):
		kind = sbom.KindRateLimited
	case unavailable(err):
		kind = sbom.KindUnavailable
	default:
		kind = kindFromText(err.Error())
	}
	return &WorkError{Kind: kind, Msg: err.Error()}
}

// unavailable reports a typed network failure (DNS, refused or reset connection, timeout) or a
// registry server error (5xx).
func unavailable(err error) bool {
	var te *transport.Error
	if errors.As(err, &te) {
		return te.StatusCode >= http.StatusInternalServerError
	}
	var (
		dnsErr *net.DNSError
		opErr  *net.OpError
		netErr net.Error
	)
	return errors.As(err, &dnsErr) || errors.As(err, &opErr) || (errors.As(err, &netErr) && netErr.Timeout()) ||
		errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.EHOSTUNREACH)
}

// textKinds maps the text of a flattened registry or network error to its kind. Registry error codes
// come from the distribution spec; status lines are go-containerregistry's "unexpected status code".
var textKinds = []struct {
	kind    string
	markers []string
}{
	{sbom.KindRateLimited, []string{"TOOMANYREQUESTS", "unexpected status code 429"}},
	{sbom.KindUnauthorized, []string{"UNAUTHORIZED", "DENIED", "unexpected status code 401", "unexpected status code 403"}},
	{sbom.KindNotFound, []string{"MANIFEST_UNKNOWN", "NAME_UNKNOWN", "unexpected status code 404"}},
	{sbom.KindUnavailable, []string{"unexpected status code 5", "no such host", "server misbehaving", "connection refused",
		"connection reset by peer", "network is unreachable", "no route to host", "i/o timeout", "TLS handshake timeout"}},
}

func kindFromText(msg string) string {
	for _, tk := range textKinds {
		for _, m := range tk.markers {
			if strings.Contains(msg, m) {
				return tk.kind
			}
		}
	}
	return sbom.KindFailed
}

// staticKeychain resolves every registry to the job's credentials, or to anonymous when it has none,
// so stereoscope never falls back to the default (docker config) keychain.
type staticKeychain struct{ auth sbom.CatalogAuth }

func (k staticKeychain) Resolve(authn.Resource) (authn.Authenticator, error) {
	return authenticator(k.auth), nil
}

func authenticator(a sbom.CatalogAuth) authn.Authenticator {
	if a == (sbom.CatalogAuth{}) {
		return authn.Anonymous
	}
	return authn.FromConfig(authn.AuthConfig{
		Username:      a.Username,
		Password:      a.Password,
		RegistryToken: a.RegistryToken,
		IdentityToken: a.IdentityToken,
	})
}
