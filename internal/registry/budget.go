package registry

import (
	"context"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/the-it-dept/ffs/internal/output/metrics"
)

// BudgetState is a registry's manifest-GET budget as last reported by its rate-limit headers.
// Known is false for a registry that has never sent them (unlimited) and is only listed because it
// answered 429.
type BudgetState struct {
	Registry         string
	Known            bool
	Limit, Remaining float64
	Window           time.Duration
}

const (
	// lowPriorityShare of a known limit is kept back from manifest GETs made under LowPriority.
	lowPriorityShare = 0.2
	// unknownHold is how long a 429 without Retry-After holds a registry that never sent rate-limit headers.
	unknownHold = time.Minute
	// minWait stops float rounding from turning the wait loop into a spin.
	minWait = 10 * time.Millisecond
	// reserveHold is how long tokens taken by Reserve count as spent by GETs the registry may not have
	// seen yet: the cataloguer's pulls start within moments of the reservation.
	reserveHold = 2 * time.Minute
)

var manifestPath = regexp.MustCompile(`^/v2/.+/manifests/[^/]+$`)

type lowPriorityKey struct{}

// LowPriority marks ctx so that manifest GETs made under it wait while a registry's tokens are below
// 20% of its limit, leaving the rest of the budget for inventory resolution.
func LowPriority(ctx context.Context) context.Context {
	return context.WithValue(ctx, lowPriorityKey{}, true)
}

// IsLowPriority reports whether ctx was marked by LowPriority.
func IsLowPriority(ctx context.Context) bool {
	low, _ := ctx.Value(lowPriorityKey{}).(bool)
	return low
}

// ParseRateLimit parses a RateLimit-Limit or RateLimit-Remaining value such as "100;w=21600".
// The window defaults to one hour when no w= parameter is present.
func ParseRateLimit(v string) (n int, window time.Duration, ok bool) {
	if i := strings.IndexByte(v, ','); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ";")
	n, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || n < 0 {
		return 0, 0, false
	}
	window = time.Hour
	for _, p := range parts[1:] {
		k, val, found := strings.Cut(strings.TrimSpace(p), "=")
		if !found || strings.TrimSpace(k) != "w" {
			continue
		}
		s, err := strconv.Atoi(strings.TrimSpace(val))
		if err != nil || s <= 0 {
			return 0, 0, false
		}
		window = time.Duration(s) * time.Second
	}
	return n, window, true
}

// budgetTransport holds a token bucket per registry host, driven by the registry's own rate-limit
// headers. Only manifest GETs wait and consume; HEAD, tags/list, blobs, referrers and token-endpoint
// requests pass straight through. A registry that never sends the headers is unlimited.
//
// A response's RateLimit-Remaining sets the bucket, except while other tokens taken locally may not be
// counted by the registry yet (manifest GETs still in flight, and Reserve's tokens for reserveHold):
// the header is then no newer than the bucket, so it may only lower it, never give those tokens back.
type budgetTransport struct {
	base http.RoundTripper
	now  func() time.Time

	mu       sync.Mutex
	buckets  map[string]*bucket
	inFlight map[string]int       // manifest GETs that took a token and are not answered yet, per host
	reserved map[string]time.Time // per host, until when tokens Reserve took may be unseen by the registry
}

type bucket struct {
	known         bool
	limit, tokens float64
	window        time.Duration
	last          time.Time
	holdUntil     time.Time
}

func newBudgetTransport(base http.RoundTripper, now func() time.Time) *budgetTransport {
	return &budgetTransport{base: base, now: now, buckets: map[string]*bucket{}, inFlight: map[string]int{},
		reserved: map[string]time.Time{}}
}

func (t *budgetTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Host
	counted := req.Method == http.MethodGet && manifestPath.MatchString(req.URL.Path)
	if counted {
		if err := t.take(req.Context(), host, 1, func(time.Time) { t.inFlight[host]++ }); err != nil {
			if req.Body != nil {
				_ = req.Body.Close()
			}
			return nil, err
		}
	}
	resp, err := t.base.RoundTrip(req)
	t.mu.Lock()
	defer t.mu.Unlock()
	if counted {
		if t.inFlight[host]--; t.inFlight[host] <= 0 {
			delete(t.inFlight, host)
		}
	}
	if err == nil {
		t.observe(host, resp)
	}
	return resp, err
}

// reserveFor takes n tokens for requests made outside this transport and counts them as unseen by
// the registry for reserveHold. It fails only with ctx.Err().
func (t *budgetTransport) reserveFor(ctx context.Context, host string, n float64) error {
	return t.take(ctx, host, n, func(now time.Time) { t.reserved[host] = now.Add(reserveHold) })
}

// unseen reports whether host has tokens taken locally that the registry may not have counted yet;
// t.mu is held.
func (t *budgetTransport) unseen(host string, now time.Time) bool {
	if t.inFlight[host] > 0 {
		return true
	}
	until, ok := t.reserved[host]
	if ok && !now.Before(until) {
		delete(t.reserved, host)
		return false
	}
	return ok
}

// take blocks until n tokens are available for host, then consumes them and calls taken, both under
// t.mu, so no response is observed in between. It fails only with ctx.Err().
func (t *budgetTransport) take(ctx context.Context, host string, n float64, taken func(now time.Time)) error {
	low := IsLowPriority(ctx)
	for {
		t.mu.Lock()
		now := t.now()
		var wait time.Duration
		if b := t.buckets[host]; b != nil {
			wait = b.reserve(now, n, low)
		}
		if wait <= 0 {
			taken(now)
		}
		t.mu.Unlock()
		if wait <= 0 {
			return nil
		}
		timer := time.NewTimer(max(wait, minWait))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// observe updates host's bucket from the response's rate-limit headers and from a 429; t.mu is held.
func (t *budgetTransport) observe(host string, resp *http.Response) {
	limit, window, okLimit := ParseRateLimit(resp.Header.Get("RateLimit-Limit"))
	okLimit = okLimit && limit > 0
	remaining, _, okRemaining := ParseRateLimit(resp.Header.Get("RateLimit-Remaining"))
	limited := resp.StatusCode == http.StatusTooManyRequests
	if !okLimit && !okRemaining && !limited {
		return
	}
	now := t.now()
	b := t.buckets[host]
	if b == nil {
		if !okLimit && !limited {
			return
		}
		b = &bucket{last: now}
		t.buckets[host] = b
	}
	if okLimit {
		if !b.known {
			b.tokens = float64(limit)
		}
		b.known, b.limit, b.window = true, float64(limit), window
		b.refill(now)
	}
	if okRemaining && b.known {
		r := math.Min(float64(remaining), b.limit)
		if t.unseen(host, now) {
			b.refill(now)
			r = math.Min(r, b.tokens)
		}
		b.tokens, b.last = r, now
	}
	if limited {
		b.tokens, b.last = 0, now
		b.holdUntil = now.Add(b.retryAfter(resp.Header.Get("Retry-After"), now))
	}
	if b.known {
		metrics.RegistryBudgetRemaining.WithLabelValues(host).Set(math.Max(0, b.tokens))
	}
}

func (t *budgetTransport) states() []BudgetState {
	now := t.now()
	t.mu.Lock()
	out := make([]BudgetState, 0, len(t.buckets))
	for host, b := range t.buckets {
		if b.known {
			b.refill(now)
		}
		out = append(out, BudgetState{Registry: host, Known: b.known, Limit: b.limit, Remaining: math.Max(0, b.tokens), Window: b.window})
	}
	t.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Registry < out[j].Registry })
	return out
}

func (b *bucket) refill(now time.Time) {
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens = math.Min(b.limit, b.tokens+elapsed.Seconds()*b.limit/b.window.Seconds())
	}
	b.last = now
}

// reserve consumes n tokens and returns 0, or returns how long to wait before trying again. Under
// LowPriority the last 20% of the limit is kept back. A request larger than the limit waits for a
// full bucket rather than forever.
func (b *bucket) reserve(now time.Time, n float64, low bool) time.Duration {
	if now.Before(b.holdUntil) {
		return b.holdUntil.Sub(now)
	}
	if !b.known {
		return 0
	}
	b.refill(now)
	floor := 0.0
	if low {
		floor = lowPriorityShare * b.limit
	}
	need := math.Min(n+floor, b.limit)
	if b.tokens >= need {
		b.tokens -= n
		return 0
	}
	return time.Duration((need - b.tokens) * float64(b.window) / b.limit)
}

// retryAfter reads a Retry-After value in seconds or as an HTTP date; without one it waits for a
// single token to refill.
func (b *bucket) retryAfter(v string, now time.Time) time.Duration {
	if s, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && s >= 0 {
		return time.Duration(s) * time.Second
	}
	if at, err := http.ParseTime(v); err == nil {
		return max(at.Sub(now), 0)
	}
	if b.known {
		return time.Duration(float64(b.window) / b.limit)
	}
	return unknownHold
}
