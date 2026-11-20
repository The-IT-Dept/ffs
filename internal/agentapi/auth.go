// Package agentapi is the controller side of the node agent: the TLS endpoint agents report to, its
// TokenReview authentication, report ingestion, the work queue and the node-group reconciler.
package agentapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/the-it-dept/ffs/internal/agentapi/wire"
)

// TokenReview user extras that bind a projected service-account token to its pod and node.
const (
	extraNodeName = "authentication.kubernetes.io/node-name"
	extraPodName  = "authentication.kubernetes.io/pod-name"
	extraPodUID   = "authentication.kubernetes.io/pod-uid"
)

const (
	defaultAuthCacheTTL = 5 * time.Minute
	// maxAuthCache bounds the authenticated-token cache.
	maxAuthCache = 4096
)

// Identity is an authenticated agent: the node its pod runs on, the pod, and its service account.
type Identity struct{ Node, Pod, PodUID, ServiceAccount, Namespace string }

// ErrUnauthenticated is a token the controller does not accept from an agent.
var ErrUnauthenticated = errors.New("agentapi: unauthenticated")

// Authenticator checks an agent's bearer token. It returns an error wrapping ErrUnauthenticated for a token it
// rejects; any other error means it could not decide.
type Authenticator interface {
	Authenticate(ctx context.Context, bearer string) (Identity, error)
}

// AuthOptions names the agent's service account and tunes the cache.
type AuthOptions struct {
	Namespace, ServiceAccount string
	CacheTTL                  time.Duration // 0: 5m
	Now                       func() time.Time
}

type authEntry struct {
	id      Identity
	expires time.Time
}

// tokenReviewAuth authenticates with TokenReview and caches successes by the token's sha256, never the token.
type tokenReviewAuth struct {
	c    client.Client
	pods client.Reader
	o    AuthOptions

	mu    sync.Mutex
	cache map[string]authEntry
}

// NewTokenReviewAuthenticator returns an Authenticator that accepts a token TokenReview authenticates for the
// audience wire.Audience as the agent's service account, and resolves the agent's node from the token's
// node-name extra, or else from the pod its pod-name and pod-uid extras name (read through pods).
func NewTokenReviewAuthenticator(c client.Client, pods client.Reader, o AuthOptions) Authenticator {
	if o.CacheTTL <= 0 {
		o.CacheTTL = defaultAuthCacheTTL
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &tokenReviewAuth{c: c, pods: pods, o: o, cache: map[string]authEntry{}}
}

func (a *tokenReviewAuth) Authenticate(ctx context.Context, bearer string) (Identity, error) {
	if bearer == "" {
		return Identity{}, fmt.Errorf("%w: no token", ErrUnauthenticated)
	}
	sum := sha256.Sum256([]byte(bearer))
	key := hex.EncodeToString(sum[:])
	now := a.o.Now()
	a.mu.Lock()
	e, ok := a.cache[key]
	a.mu.Unlock()
	if ok && now.Before(e.expires) {
		return e.id, nil
	}

	tr := &authenticationv1.TokenReview{Spec: authenticationv1.TokenReviewSpec{Token: bearer, Audiences: []string{wire.Audience}}}
	if err := a.c.Create(ctx, tr); err != nil {
		return Identity{}, fmt.Errorf("token review: %w", err)
	}
	id, err := a.identity(ctx, tr.Status)
	if err != nil {
		return Identity{}, err
	}
	a.remember(key, id, now)
	return id, nil
}

// identity checks a TokenReview status and resolves the agent's node.
func (a *tokenReviewAuth) identity(ctx context.Context, st authenticationv1.TokenReviewStatus) (Identity, error) {
	switch {
	case st.Error != "":
		return Identity{}, fmt.Errorf("%w: %s", ErrUnauthenticated, st.Error)
	case !st.Authenticated:
		return Identity{}, fmt.Errorf("%w: token not authenticated", ErrUnauthenticated)
	case !slices.Contains(st.Audiences, wire.Audience):
		return Identity{}, fmt.Errorf("%w: token audience is not %s", ErrUnauthenticated, wire.Audience)
	case st.User.Username != "system:serviceaccount:"+a.o.Namespace+":"+a.o.ServiceAccount:
		return Identity{}, fmt.Errorf("%w: token is not for the agent service account", ErrUnauthenticated)
	}
	id := Identity{Pod: first(st.User.Extra[extraPodName]), PodUID: first(st.User.Extra[extraPodUID]),
		ServiceAccount: a.o.ServiceAccount, Namespace: a.o.Namespace}
	if id.Node = first(st.User.Extra[extraNodeName]); id.Node != "" {
		return id, nil
	}
	if id.Pod == "" || id.PodUID == "" {
		return Identity{}, fmt.Errorf("%w: token names no node and no pod", ErrUnauthenticated)
	}
	var pod corev1.Pod
	if err := a.pods.Get(ctx, client.ObjectKey{Namespace: a.o.Namespace, Name: id.Pod}, &pod); err != nil {
		if apierrors.IsNotFound(err) {
			return Identity{}, fmt.Errorf("%w: the token's pod is not running", ErrUnauthenticated)
		}
		return Identity{}, fmt.Errorf("reading the agent pod: %w", err)
	}
	if string(pod.UID) != id.PodUID || pod.Namespace != a.o.Namespace || pod.Spec.NodeName == "" {
		return Identity{}, fmt.Errorf("%w: the token's pod is not running", ErrUnauthenticated)
	}
	id.Node = pod.Spec.NodeName
	return id, nil
}

// remember caches an accepted token. A full cache drops expired entries, then everything if still full.
func (a *tokenReviewAuth) remember(key string, id Identity, now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.cache) >= maxAuthCache {
		for k, e := range a.cache {
			if !now.Before(e.expires) {
				delete(a.cache, k)
			}
		}
		if len(a.cache) >= maxAuthCache {
			clear(a.cache)
		}
	}
	a.cache[key] = authEntry{id: id, expires: now.Add(a.o.CacheTTL)}
}

func first(v authenticationv1.ExtraValue) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}
