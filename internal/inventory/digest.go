// Package inventory turns pod status into the image and workload inventory.
package inventory

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/registry"
)

// NodePlatform is the platform of the node a container runs on.
type NodePlatform struct{ OS, Arch, Variant string }

// Key returns OS/Arch; the variant is never part of the key.
func (p NodePlatform) Key() string { return p.OS + "/" + p.Arch }

// IndexResolver resolves tags and index digests; satisfied by *registry.Client.
type IndexResolver interface {
	ResolveTag(ctx context.Context, repo, tag string, cs registry.CredSet) (string, error)
	PlatformManifest(ctx context.Context, repo, digest, platform string, cs registry.CredSet) (registry.Manifest, error)
	ConfigDigest(ctx context.Context, repo, digest string, cs registry.CredSet) (string, error)
	// Head checks that ref ("repo@digest") exists and that cs may pull it, without a counted GET.
	Head(ctx context.Context, ref string, cs registry.CredSet) (*v1.Descriptor, error)
}

// ImageLookup reads recorded images; satisfied by *store.Store.
type ImageLookup interface {
	GetImage(ctx context.Context, digest string) (model.Image, bool, error)
	PlatformDigest(ctx context.Context, indexDigest, platform string) (string, bool, error)
}

// ContainerImage is one container's image as the kubelet reports it.
type ContainerImage struct {
	Image, ImageID string
	Node           NodePlatform
	Creds          registry.CredSet
}

const (
	ReasonSideLoadedNoTag    = "image ID is a node-local config digest and the container image has no tag to look up in a registry"
	ReasonSideLoadedMismatch = "image ID is a node-local config digest that does not match %s:%s in the registry" // repo, tag
	ReasonNoPlatform         = "index %s has no manifest for %s"                                                  // digest, platform
	ReasonUnparseable        = "image ID %q is not a digest reference"
	ReasonUnreachable        = "registry not reachable from ffs for %s: %s" // repo, problem
	UnresolvableRetry        = 6 * time.Hour
	// UnreachableRetry is the retry of an image whose registry ffs could not reach. It is shorter than
	// UnresolvableRetry: the cause is usually ffs's own egress, and fixing it should show soon.
	UnreachableRetry = time.Hour
	// unreachableAttempts and unreachableAfter bound how long a registry that cannot be reached keeps a
	// workload's image unknown: once both are passed, the image is recorded unresolvable.
	unreachableAttempts = 3
	unreachableAfter    = 5 * time.Minute
)

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func isBareDigest(s string) bool {
	return hex64.MatchString(s) || (strings.HasPrefix(s, "sha256:") && hex64.MatchString(s[7:]))
}

// NormalizeRepo returns the canonical "registry/path" form of an image reference, without tag or digest.
func NormalizeRepo(ref string) (string, error) {
	r, err := name.ParseReference(ref, name.WeakValidation)
	if err != nil {
		return "", err
	}
	reg := r.Context().RegistryStr()
	if reg == "index.docker.io" || reg == "registry-1.docker.io" {
		reg = "docker.io"
	}
	return reg + "/" + r.Context().RepositoryStr(), nil
}

// SplitRef splits a reference into its normalised repo and its tag or digest.
func SplitRef(ref string) (repo, tag, digest string, err error) {
	if isBareDigest(ref) {
		return "", "", "", fmt.Errorf("%q is a bare digest, not a reference", ref)
	}
	r, err := name.ParseReference(ref, name.WeakValidation)
	if err != nil {
		return "", "", "", err
	}
	if repo, err = NormalizeRepo(ref); err != nil {
		return "", "", "", err
	}
	switch v := r.(type) {
	case name.Digest:
		digest = v.DigestStr()
	case name.Tag:
		tag = v.TagStr()
	}
	return repo, tag, digest, nil
}

// ParseImageID parses a pod status imageID. bare is true for a node-local config digest, which carries no repo.
func ParseImageID(imageID string) (repo, digest string, bare bool, err error) {
	id := strings.TrimPrefix(strings.TrimPrefix(imageID, "docker-pullable://"), "docker://")
	if isBareDigest(id) {
		if !strings.HasPrefix(id, "sha256:") {
			id = "sha256:" + id
		}
		return "", id, true, nil
	}
	i := strings.LastIndex(id, "@")
	if i < 0 {
		return "", "", false, fmt.Errorf("image ID %q is not a digest reference", imageID)
	}
	digest = id[i+1:]
	if !strings.HasPrefix(digest, "sha256:") || !hex64.MatchString(digest[7:]) {
		return "", "", false, fmt.Errorf("image ID %q has an invalid digest", imageID)
	}
	if repo, err = NormalizeRepo(id[:i]); err != nil {
		return "", "", false, err
	}
	return repo, digest, false, nil
}

// Normalizer resolves container images to platform manifest digests.
type Normalizer struct {
	r   IndexResolver
	l   ImageLookup
	now func() time.Time

	mu       sync.Mutex
	failures map[string]failure // registry failures per repository, since the last success
}

// failure counts a repository's consecutive registry failures that were neither a refusal nor a
// rate limit.
type failure struct {
	count int
	first time.Time
}

func NewNormalizer(r IndexResolver, l ImageLookup, now func() time.Time) *Normalizer {
	return &Normalizer{r: r, l: l, now: now, failures: map[string]failure{}}
}

// Normalize returns the image row for a container. Permanent resolution failures come back as an
// unresolvable image; transient failures (rate limits, network) come back as errors for the caller to retry.
func (n *Normalizer) Normalize(ctx context.Context, in ContainerImage) (model.Image, error) {
	repoID, digest, bare, err := ParseImageID(in.ImageID)
	if err != nil {
		// An unparseable image ID is a permanent failure, recorded as an unresolvable image rather than retried.
		return n.unresolvable("unknown:"+in.ImageID, "", "", fmt.Sprintf(ReasonUnparseable, in.ImageID)), nil //nolint:nilerr // parse error is permanent: reported as unresolvable, not returned
	}
	repo := repoID
	imgRepo, tag, refDigest, refErr := SplitRef(in.Image)
	if refErr == nil {
		repo = imgRepo
	}
	key := in.Node.Key()

	stored, ok, err := n.l.GetImage(ctx, digest)
	if err != nil {
		return model.Image{}, err
	}
	if ok && (stored.Status != model.ImageUnresolvable || n.now().Before(stored.QuarantinedUntil)) {
		if repo != "" {
			stored.Repo = repo
		}
		return stored, nil
	}

	var m registry.Manifest
	ref := repo + "@" + digest // what a registry error is reported against
	if bare {
		candidate := refDigest
		if candidate == "" {
			if refErr != nil || tag == "" {
				// refErr only means the reference carries no usable tag: permanent, so unresolvable.
				return n.unresolvable(digest, repo, key, ReasonSideLoadedNoTag), nil //nolint:nilerr // unusable reference is permanent: reported as unresolvable, not returned
			}
			ref = repo + ":" + tag
			if candidate, err = n.r.ResolveTag(ctx, repo, tag, in.Creds); err != nil {
				return n.fail(ctx, err, digest, repo, ref, candidate, key)
			}
		}
		ref = repo + "@" + candidate
		if m, err = n.r.PlatformManifest(ctx, repo, candidate, key, in.Creds); err != nil {
			return n.fail(ctx, err, digest, repo, ref, candidate, key)
		}
		cfg, err := n.r.ConfigDigest(ctx, repo, m.Digest, in.Creds)
		if err != nil {
			return n.fail(ctx, err, digest, repo, ref, candidate, key)
		}
		n.reachable(repo)
		if cfg != digest {
			return n.unresolvable(digest, repo, key, fmt.Sprintf(ReasonSideLoadedMismatch, repo, tag)), nil
		}
		return resolved(m, repo, key), nil
	}

	if d, found, err := n.l.PlatformDigest(ctx, digest, key); err != nil {
		return model.Image{}, err
	} else if found {
		img, ok, err := n.l.GetImage(ctx, d)
		if err != nil {
			return model.Image{}, err
		}
		if !ok {
			return model.Image{Digest: d, IndexDigest: digest, Repo: repo, Platform: key, Status: model.ImagePending}, nil
		}
		// A platform manifest left unresolvable (the registry refused the cataloguer's pull, say) is
		// retried through the registry once its window has passed, like any unresolvable image.
		if img.Status != model.ImageUnresolvable || n.now().Before(img.QuarantinedUntil) {
			if repo != "" {
				img.Repo = repo
			}
			return img, nil
		}
	}
	if m, err = n.r.PlatformManifest(ctx, repo, digest, key, in.Creds); err != nil {
		return n.fail(ctx, err, digest, repo, ref, digest, key)
	}
	n.reachable(repo)
	return resolved(m, repo, key), nil
}

func resolved(m registry.Manifest, repo, key string) model.Image {
	return model.Image{Digest: m.Digest, IndexDigest: m.IndexDigest, Repo: repo, Platform: key,
		VersionAnnotation: m.Annotations[registry.AnnotationVersion], Status: model.ImagePending}
}

func (n *Normalizer) unresolvable(digest, repo, platform, reason string) model.Image {
	return model.Image{Digest: digest, Repo: repo, Platform: platform, Status: model.ImageUnresolvable,
		StatusReason: reason, QuarantinedUntil: n.now().Add(UnresolvableRetry)}
}

// fail maps a registry error to an unresolvable image, or returns it for the caller to retry. A
// refusal (unauthorized, not found, no such platform) is unresolvable at once. Any other failure
// short of a rate limit or shutdown (DNS, refused or timed-out connections, server errors) is
// retried, until the repository has failed unreachableAttempts times over unreachableAfter: the
// image is then unresolvable as not reachable, so a registry only the nodes can reach (a node-level
// mirror, an /etc/hosts name) shows as unresolvable rather than leaving the workload out.
func (n *Normalizer) fail(ctx context.Context, err error, digest, repo, ref, indexDigest, key string) (model.Image, error) {
	switch {
	case errors.Is(err, registry.ErrUnauthorized):
		n.reachable(repo)
		return n.unresolvable(digest, repo, key, fmt.Sprintf(registry.ReasonUnauthorized, repo)), nil
	case errors.Is(err, registry.ErrNotFound):
		n.reachable(repo)
		return n.unresolvable(digest, repo, key, fmt.Sprintf(registry.ReasonNotFound, ref)), nil
	case errors.Is(err, registry.ErrNoPlatform):
		n.reachable(repo)
		return n.unresolvable(digest, repo, key, fmt.Sprintf(ReasonNoPlatform, indexDigest, key)), nil
	case ctx.Err() != nil, errors.Is(err, registry.ErrRateLimited):
		return model.Image{}, err // shutdown, or a low budget: slower, never a failure
	}
	now := n.now()
	n.mu.Lock()
	f, ok := n.failures[repo]
	if !ok {
		f.first = now
	}
	f.count++
	n.failures[repo] = f
	n.mu.Unlock()
	if f.count < unreachableAttempts || now.Sub(f.first) < unreachableAfter {
		return model.Image{}, err
	}
	img := n.unresolvable(digest, repo, key, fmt.Sprintf(ReasonUnreachable, repo, unreachableCause(err)))
	img.QuarantinedUntil = now.Add(UnreachableRetry)
	return img, nil
}

// reachable records that repo's registry answered.
func (n *Normalizer) reachable(repo string) {
	n.mu.Lock()
	delete(n.failures, repo)
	n.mu.Unlock()
}

// unreachableCause names the kind of failure for the unresolvable reason.
func unreachableCause(err error) string {
	var (
		dnsErr *net.DNSError
		te     *transport.Error
		netErr net.Error
	)
	switch {
	case errors.As(err, &dnsErr):
		return "DNS lookup failed"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return "timed out"
	case errors.As(err, &te) && te.StatusCode >= 500:
		return fmt.Sprintf("server error %d", te.StatusCode)
	}
	return "request failed"
}
