package registry

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"k8s.io/client-go/kubernetes"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/version"
)

// Options configures a Client.
type Options struct {
	Kube      kubernetes.Interface // nil → anonymous (plus nothing else)
	Namespace string               // ffs install namespace; OperatorSecret lives here
	Config    config.RegistryConfig
	Transport http.RoundTripper // base transport; default remote.DefaultTransport
	UserAgent string            // "ffs/<version>"; default version.UserAgent()
	Now       func() time.Time
}

// Client talks to OCI registries for inventory, attestations, cataloguing and upgrades. Repos passed in
// are the original (normalised) repos; only the network location is rewritten through mirrors.
type Client struct {
	kube      kubernetes.Interface
	namespace string
	cfg       config.RegistryConfig
	mirrors   map[string]string
	userAgent string
	now       func() time.Time
	budget    *budgetTransport
	pageSize  int

	mu        sync.Mutex
	keychains map[string]cachedKeychain
}

// retryStatusCodes are ggcr's defaults without 429: a rate limit is recorded by the budget and
// surfaced as ErrRateLimited rather than retried in place.
var retryStatusCodes = []int{
	http.StatusRequestTimeout,
	http.StatusInternalServerError,
	http.StatusBadGateway,
	http.StatusServiceUnavailable,
	http.StatusGatewayTimeout,
	499, // nginx: client closed request
	522, // Cloudflare: connection timed out
}

const defaultPageSize = 1000

// New returns a Client.
func New(o Options) *Client {
	base := o.Transport
	if base == nil {
		base = remote.DefaultTransport
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	ua := o.UserAgent
	if ua == "" {
		ua = version.UserAgent()
	}
	mirrors := make(map[string]string, len(o.Config.Mirrors))
	for k, v := range o.Config.Mirrors {
		mirrors[normalizeHost(k)] = strings.TrimRight(v, "/")
	}
	return &Client{
		kube:      o.Kube,
		namespace: o.Namespace,
		cfg:       o.Config,
		mirrors:   mirrors,
		userAgent: ua,
		now:       now,
		budget:    newBudgetTransport(base, now),
		pageSize:  defaultPageSize,
		keychains: map[string]cachedKeychain{},
	}
}

// normalizeHost lower-cases a registry host, drops any scheme or trailing slash, and folds Docker Hub's
// aliases into "docker.io".
func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimPrefix(strings.TrimPrefix(h, "https://"), "http://")
	h = strings.TrimRight(h, "/")
	switch h {
	case "index.docker.io", "registry-1.docker.io":
		return "docker.io"
	}
	return h
}

// PullRepo returns the network location for repo: the mirror for its registry when one is configured,
// otherwise repo unchanged.
func (c *Client) PullRepo(repo string) string {
	if len(c.mirrors) == 0 {
		return repo
	}
	r, err := name.NewRepository(repo)
	if err != nil {
		return repo
	}
	m, ok := c.mirrors[normalizeHost(r.RegistryStr())]
	if !ok {
		return repo
	}
	return m + "/" + r.RepositoryStr()
}

// ResolveTag returns the digest repo:tag points at, using HEAD only.
func (c *Client) ResolveTag(ctx context.Context, repo, tag string, cs CredSet) (string, error) {
	d, err := c.resolveTag(ctx, repo, tag, cs)
	return d, Classify(err)
}

func (c *Client) resolveTag(ctx context.Context, repo, tag string, cs CredSet) (string, error) {
	ref, err := name.NewTag(c.PullRepo(repo) + ":" + tag)
	if err != nil {
		return "", err
	}
	opts, err := c.options(ctx, cs)
	if err != nil {
		return "", err
	}
	desc, err := remote.Head(ref, opts...)
	if err != nil {
		return "", err
	}
	return desc.Digest.String(), nil
}

// PlatformManifest resolves digest to the manifest for platform ("linux/arm64"). A platform manifest
// costs one HEAD; an index costs a HEAD and a GET.
func (c *Client) PlatformManifest(ctx context.Context, repo, digest, platform string, cs CredSet) (Manifest, error) {
	m, err := c.platformManifest(ctx, repo, digest, platform, cs)
	return m, Classify(err)
}

func (c *Client) platformManifest(ctx context.Context, repo, digest, platform string, cs CredSet) (Manifest, error) {
	want, err := v1.ParsePlatform(platform)
	if err != nil {
		return Manifest{}, err
	}
	ref, err := c.digestRef(repo, digest)
	if err != nil {
		return Manifest{}, err
	}
	opts, err := c.options(ctx, cs)
	if err != nil {
		return Manifest{}, err
	}
	desc, err := remote.Head(ref, opts...)
	if err != nil {
		return Manifest{}, err
	}
	if !desc.MediaType.IsIndex() {
		return Manifest{Digest: digest, Platform: platform}, nil
	}
	idx, err := remote.Index(ref, opts...)
	if err != nil {
		return Manifest{}, err
	}
	im, err := idx.IndexManifest()
	if err != nil {
		return Manifest{}, err
	}
	d, ok := pickPlatform(im.Manifests, *want)
	if !ok {
		return Manifest{}, fmt.Errorf("%w: %s in %s@%s", ErrNoPlatform, platform, repo, digest)
	}
	return Manifest{Digest: d.Digest.String(), IndexDigest: digest, Platform: platform, Annotations: im.Annotations}, nil
}

const (
	referenceTypeAnnotation = "vnd.docker.reference.type"
	attestationManifest     = "attestation-manifest"
)

// pickPlatform keeps the entries for want's OS and architecture (skipping attestation entries), then
// prefers an equal variant, then arm64 v8 or no variant, then arm v7, then the first entry.
func pickPlatform(descs []v1.Descriptor, want v1.Platform) (v1.Descriptor, bool) {
	var cands []v1.Descriptor
	for _, d := range descs {
		p := d.Platform
		if p == nil || (p.OS == "unknown" && p.Architecture == "unknown") || d.Annotations[referenceTypeAnnotation] == attestationManifest {
			continue
		}
		if p.OS == want.OS && p.Architecture == want.Architecture {
			cands = append(cands, d)
		}
	}
	if len(cands) == 0 {
		return v1.Descriptor{}, false
	}
	prefs := []func(v1.Platform) bool{
		func(p v1.Platform) bool { return p.Variant == want.Variant },
		func(p v1.Platform) bool { return p.Architecture == "arm64" && (p.Variant == "v8" || p.Variant == "") },
		func(p v1.Platform) bool { return p.Architecture == "arm" && p.Variant == "v7" },
	}
	for _, pref := range prefs {
		for _, d := range cands {
			if pref(*d.Platform) {
				return d, true
			}
		}
	}
	return cands[0], true
}

// ConfigDigest returns the config digest of a platform manifest (one manifest GET).
func (c *Client) ConfigDigest(ctx context.Context, repo, digest string, cs CredSet) (string, error) {
	d, err := c.configDigest(ctx, repo, digest, cs)
	return d, Classify(err)
}

func (c *Client) configDigest(ctx context.Context, repo, digest string, cs CredSet) (string, error) {
	ref, err := c.digestRef(repo, digest)
	if err != nil {
		return "", err
	}
	opts, err := c.options(ctx, cs)
	if err != nil {
		return "", err
	}
	desc, err := remote.Get(ref, opts...)
	if err != nil {
		return "", err
	}
	if desc.MediaType.IsIndex() {
		return "", fmt.Errorf("%s@%s is an image index, not a platform manifest", repo, digest)
	}
	m, err := v1.ParseManifest(bytes.NewReader(desc.Manifest))
	if err != nil {
		return "", err
	}
	if m.Config.Digest == (v1.Hash{}) {
		return "", fmt.Errorf("%s@%s has no config digest", repo, digest)
	}
	return m.Config.Digest.String(), nil
}

// Get fetches the manifest for ref, "repo:tag" or "repo@digest".
func (c *Client) Get(ctx context.Context, ref string, cs CredSet) (*remote.Descriptor, error) {
	d, err := c.get(ctx, ref, cs)
	return d, Classify(err)
}

func (c *Client) get(ctx context.Context, ref string, cs CredSet) (*remote.Descriptor, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, err
	}
	pull := c.PullRepo(r.Context().Name())
	if d, ok := r.(name.Digest); ok {
		r, err = name.NewDigest(pull + "@" + d.DigestStr())
	} else {
		r, err = name.NewTag(pull + ":" + r.Identifier())
	}
	if err != nil {
		return nil, err
	}
	opts, err := c.options(ctx, cs)
	if err != nil {
		return nil, err
	}
	return remote.Get(r, opts...)
}

// Image returns the image at repo@digest. Its manifest is fetched now; config and layers on use.
func (c *Client) Image(ctx context.Context, repo, digest string, cs CredSet) (v1.Image, error) {
	img, err := c.image(ctx, repo, digest, cs)
	return img, Classify(err)
}

func (c *Client) image(ctx context.Context, repo, digest string, cs CredSet) (v1.Image, error) {
	ref, err := c.digestRef(repo, digest)
	if err != nil {
		return nil, err
	}
	opts, err := c.options(ctx, cs)
	if err != nil {
		return nil, err
	}
	return remote.Image(ref, opts...)
}

// Auth returns the credentials cs resolves to for repo's pull location. They are for in-memory use
// only (the cataloguer's pull) and are never logged or stored.
func (c *Client) Auth(ctx context.Context, repo string, cs CredSet) (authn.AuthConfig, error) {
	a, err := c.auth(ctx, repo, cs)
	return a, Classify(err)
}

func (c *Client) auth(ctx context.Context, repo string, cs CredSet) (authn.AuthConfig, error) {
	r, err := name.NewRepository(c.PullRepo(repo))
	if err != nil {
		return authn.AuthConfig{}, err
	}
	kc, err := c.keychain(ctx, cs)
	if err != nil {
		return authn.AuthConfig{}, err
	}
	a, err := authn.Resolve(ctx, kc, r)
	if err != nil {
		return authn.AuthConfig{}, err
	}
	cfg, err := authn.Authorization(ctx, a)
	if err != nil {
		return authn.AuthConfig{}, err
	}
	return *cfg, nil
}

// Reserve takes n manifest-GET tokens from repo's registry budget for a pull made outside this client
// (the cataloguer). It waits like a manifest GET and fails only with ctx.Err().
func (c *Client) Reserve(ctx context.Context, repo string, n int) error {
	r, err := name.NewRepository(c.PullRepo(repo))
	if err != nil {
		return err
	}
	return c.budget.take(ctx, r.RegistryStr(), float64(n))
}

// Budgets reports every registry that has sent rate-limit headers or answered 429, sorted by host.
func (c *Client) Budgets() []BudgetState {
	return c.budget.states()
}

func (c *Client) digestRef(repo, digest string) (name.Digest, error) {
	return name.NewDigest(c.PullRepo(repo) + "@" + digest)
}

// options are the remote options every ggcr call uses: the caller's context, the CredSet's keychain,
// the ffs User-Agent and the budget transport.
func (c *Client) options(ctx context.Context, cs CredSet) ([]remote.Option, error) {
	kc, err := c.keychain(ctx, cs)
	if err != nil {
		return nil, err
	}
	return []remote.Option{
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(kc),
		remote.WithUserAgent(c.userAgent),
		remote.WithTransport(c.budget),
		remote.WithRetryStatusCodes(retryStatusCodes...),
	}, nil
}

// rawTransport is an authenticated transport for repo's registry, for the requests ggcr has no
// call for (tags/list paging, the referrers API).
func (c *Client) rawTransport(ctx context.Context, repo name.Repository, cs CredSet) (http.RoundTripper, error) {
	kc, err := c.keychain(ctx, cs)
	if err != nil {
		return nil, err
	}
	auth, err := authn.Resolve(ctx, kc, repo)
	if err != nil {
		return nil, err
	}
	rt := transport.NewUserAgent(transport.NewRetry(c.budget, transport.WithRetryStatusCodes(retryStatusCodes...)), c.userAgent)
	return transport.NewWithContext(ctx, repo.Registry, auth, rt, []string{repo.Scope(transport.PullScope)})
}
