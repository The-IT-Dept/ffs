// Package agentapi is the controller side of the node agent: the TLS endpoint agents report to, its
// TokenReview authentication, report ingestion, the work queue and the node-group reconciler.
package agentapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

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
	// rejectCacheTTL is how long a rejected token is answered from the cache, without a TokenReview.
	rejectCacheTTL = 30 * time.Second
	// maxAuthCache bounds the token cache, accepted and rejected entries together.
	maxAuthCache = 4096

	// authFailRate and authFailBurst are the token bucket of failed authentications per source IP: past
	// the burst, a source gets 429 until its bucket refills, and its tokens are not reviewed meanwhile.
	authFailRate  = 5 // per second
	authFailBurst = 20
	// maxAuthFailSources bounds the per-source buckets.
	maxAuthFailSources = 4096
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
	CacheTTL                  time.Duration // most an accepted token is cached, never past its exp; 0: 5m
	Now                       func() time.Time
}

// authEntry is a cached TokenReview outcome: the identity of an accepted token, or the rejection of one.
type authEntry struct {
	id      Identity
	err     error // non-nil: the token was rejected (wraps ErrUnauthenticated)
	expires time.Time
}

// tokenReviewAuth authenticates with TokenReview and caches outcomes by the token's sha256, never the token:
// an accepted token until the earlier of CacheTTL and its exp, a rejected one for rejectCacheTTL.
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
		return e.id, e.err
	}

	tr := &authenticationv1.TokenReview{Spec: authenticationv1.TokenReviewSpec{Token: bearer, Audiences: []string{wire.Audience}}}
	if err := a.c.Create(ctx, tr); err != nil {
		return Identity{}, fmt.Errorf("token review: %w", err)
	}
	id, err := a.identity(ctx, tr.Status)
	switch {
	case errors.Is(err, ErrUnauthenticated):
		a.remember(key, authEntry{err: err, expires: now.Add(rejectCacheTTL)}, now)
		return Identity{}, err
	case err != nil:
		return Identity{}, err // could not decide: not cached
	}
	expires := now.Add(a.o.CacheTTL)
	if exp, ok := tokenExpiry(bearer); ok && exp.Before(expires) {
		expires = exp
	}
	if now.Before(expires) {
		a.remember(key, authEntry{id: id, expires: expires}, now)
	}
	return id, nil
}

// tokenExpiry reads the exp claim of a JWT bearer token without verifying it: TokenReview has verified
// the token, and exp only shortens how long the outcome is cached. It is false for a token that is not a
// JWT or has no exp.
func tokenExpiry(bearer string) (time.Time, bool) {
	parts := strings.Split(bearer, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Exp *json.Number `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp == nil {
		return time.Time{}, false
	}
	secs, err := claims.Exp.Float64()
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(int64(secs), 0), true
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

// remember caches a TokenReview outcome. A full cache drops expired entries, then everything if still full.
func (a *tokenReviewAuth) remember(key string, e authEntry, now time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.cache) >= maxAuthCache {
		for k, old := range a.cache {
			if !now.Before(old.expires) {
				delete(a.cache, k)
			}
		}
		if len(a.cache) >= maxAuthCache {
			clear(a.cache)
		}
	}
	a.cache[key] = e
}

func first(v authenticationv1.ExtraValue) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

// failLimiter is a token bucket of failed authentications per source IP. It never limits a source that
// has not failed.
type failLimiter struct {
	mu   sync.Mutex
	byIP map[string]*rate.Limiter
}

func newFailLimiter() *failLimiter { return &failLimiter{byIP: map[string]*rate.Limiter{}} }

// limited reports whether ip has used up its failed authentications at now.
func (f *failLimiter) limited(ip string, now time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	l, ok := f.byIP[ip]
	return ok && l.TokensAt(now) < 1
}

// fail counts a failed authentication from ip at now. With too many sources, those whose bucket has refilled
// are forgotten, and every source when none has.
func (f *failLimiter) fail(ip string, now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	l, ok := f.byIP[ip]
	if !ok {
		if len(f.byIP) >= maxAuthFailSources {
			for k, old := range f.byIP {
				if old.TokensAt(now) >= authFailBurst {
					delete(f.byIP, k)
				}
			}
			if len(f.byIP) >= maxAuthFailSources {
				clear(f.byIP)
			}
		}
		l = rate.NewLimiter(authFailRate, authFailBurst)
		f.byIP[ip] = l
	}
	l.AllowN(now, 1)
}

// sourceIP is the request's remote IP, or its whole remote address when that has no port.
func sourceIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
