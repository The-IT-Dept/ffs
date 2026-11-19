package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

const maxReferrersBytes = 4 << 20

// Referrers lists the manifests whose subject is repo@digest through the OCI referrers API only; the
// sha256-<hex> tag schema is left to the caller. A registry without the API (404, 400, 405, 406, or a
// body that is not an index) yields nil, nil.
func (c *Client) Referrers(ctx context.Context, repo, digest string, cs CredSet) ([]v1.Descriptor, error) {
	descs, err := c.referrers(ctx, repo, digest, cs)
	return descs, Classify(err)
}

func (c *Client) referrers(ctx context.Context, repo, digest string, cs CredSet) ([]v1.Descriptor, error) {
	d, err := c.digestRef(repo, digest)
	if err != nil {
		return nil, err
	}
	r := d.Context()
	rt, err := c.rawTransport(ctx, r, cs)
	if err != nil {
		return nil, err
	}
	u := url.URL{Scheme: r.Scheme(), Host: r.RegistryStr(), Path: fmt.Sprintf("/v2/%s/referrers/%s", r.RepositoryStr(), d.DigestStr())}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", string(types.OCIImageIndex))
	resp, err := (&http.Client{Transport: rt}).Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusNotFound, http.StatusBadRequest, http.StatusMethodNotAllowed, http.StatusNotAcceptable:
		return nil, nil
	}
	if err := transport.CheckError(resp, http.StatusOK); err != nil {
		return nil, err
	}
	var idx v1.IndexManifest
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxReferrersBytes)).Decode(&idx); err != nil {
		return nil, nil //nolint:nilerr // a 200 that is not an index means the API is not really there
	}
	return idx.Manifests, nil
}
