package registry

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/registry/regtest"
)

func TestParseRateLimit(t *testing.T) {
	cases := []struct {
		in     string
		n      int
		window time.Duration
		ok     bool
	}{
		{"100;w=3600", 100, time.Hour, true},
		{"76;w=21600", 76, 6 * time.Hour, true},
		{"100", 100, time.Hour, true},
		{"0;w=60", 0, time.Minute, true},
		{"", 0, 0, false},
		{"abc;w=3600", 0, 0, false},
		{"100;w=0", 0, 0, false},
	}
	for _, tc := range cases {
		n, w, ok := ParseRateLimit(tc.in)
		require.Equal(t, tc.ok, ok, tc.in)
		require.Equal(t, tc.n, n, tc.in)
		require.Equal(t, tc.window, w, tc.in)
	}
}

// rateHeaders sets RateLimit-Limit on every manifest response and RateLimit-Remaining from remaining,
// which sees whether the request is a manifest GET.
func rateHeaders(limit string, remaining func(get bool) int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if manifestsRe.MatchString(r.URL.Path) {
				w.Header().Set("RateLimit-Limit", limit)
				w.Header().Set("RateLimit-Remaining", strconv.Itoa(remaining(r.Method == http.MethodGet)))
			}
			next.ServeHTTP(w, r)
		})
	}
}

func staticRemaining(n int) func(bool) int { return func(bool) int { return n } }

func TestBudget_ManifestGETConsumesHeadAndTagsFree(t *testing.T) {
	var gets atomic.Int64
	s := regtest.Start(t, regtest.WithMiddleware(rateHeaders("2;w=3600", func(get bool) int {
		if get {
			gets.Add(1)
		}
		return max(0, 2-int(gets.Load()))
	})))
	d1 := s.Push(t, "app:v1", randomImage(t))
	d2 := s.Push(t, "app:v2", randomImage(t))
	repo := s.Host + "/app"
	clk := newClock()
	c := New(Options{Now: clk.Now})

	_, err := c.Image(ctx, repo, d1, CredSet{})
	require.NoError(t, err)
	_, err = c.Image(ctx, repo, d2, CredSet{})
	require.NoError(t, err)
	_, err = c.Image(within(t, 100*time.Millisecond), repo, d1, CredSet{})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Equal(t, 2, s.Count("GET", manifestsRe), "the waiting GET never reached the registry")

	for range 5 {
		_, err = c.ResolveTag(within(t, 5*time.Second), repo, "v1", CredSet{})
		require.NoError(t, err)
	}
	tags, err := c.ListTags(within(t, 5*time.Second), repo, CredSet{})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"v1", "v2"}, tags)
	require.Contains(t, c.Budgets(), BudgetState{Registry: s.Host, Known: true, Limit: 2, Remaining: 0, Window: time.Hour})

	clk.Advance(30 * time.Minute) // 2 per hour refills one token in 30 minutes
	_, err = c.Image(within(t, 5*time.Second), repo, d1, CredSet{})
	require.NoError(t, err)

	// Reserve takes tokens without a request.
	s2 := regtest.Start(t, regtest.WithMiddleware(rateHeaders("2;w=3600", staticRemaining(2))))
	s2.Push(t, "app:v1", randomImage(t))
	c2 := New(Options{Now: clk.Now})
	_, err = c2.ResolveTag(ctx, s2.Host+"/app", "v1", CredSet{})
	require.NoError(t, err)
	all := regexp.MustCompile(`.`)
	before := s2.Count("", all)
	require.NoError(t, c2.Reserve(ctx, s2.Host+"/app", 1))
	require.Equal(t, 1.0, c2.Budgets()[0].Remaining)
	require.Equal(t, before, s2.Count("", all))

	// LowPriority keeps the last 20% of the limit back.
	s3 := regtest.Start(t, regtest.WithMiddleware(rateHeaders("10;w=3600", staticRemaining(1))))
	d3 := s3.Push(t, "app:v1", randomImage(t))
	c3 := New(Options{Now: clk.Now})
	_, err = c3.ResolveTag(ctx, s3.Host+"/app", "v1", CredSet{})
	require.NoError(t, err)
	_, err = c3.Image(LowPriority(within(t, 100*time.Millisecond)), s3.Host+"/app", d3, CredSet{})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	_, err = c3.Image(within(t, 5*time.Second), s3.Host+"/app", d3, CredSet{})
	require.NoError(t, err)
}

// tooMany answers manifest GETs with 429 while on is set, with the given extra headers.
func tooMany(on *atomic.Bool, headers map[string]string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if on.Load() && r.Method == http.MethodGet && manifestsRe.MatchString(r.URL.Path) {
				for k, v := range headers {
					w.Header().Set(k, v)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = io.WriteString(w, `{"errors":[{"code":"TOOMANYREQUESTS","message":"rate limit exceeded"}]}`)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func TestBudget_429SetsExhaustedAndClassifies(t *testing.T) {
	var on atomic.Bool
	s := regtest.Start(t, regtest.WithMiddleware(tooMany(&on, map[string]string{"Retry-After": "120"})))
	d := s.Push(t, "app:v1", randomImage(t))
	repo := s.Host + "/app"
	clk := newClock()
	c := New(Options{Now: clk.Now})

	on.Store(true)
	_, err := c.Image(within(t, 5*time.Second), repo, d, CredSet{})
	require.ErrorIs(t, err, ErrRateLimited)
	require.Equal(t, 1, s.Count("GET", manifestsRe), "429 is not retried in place")
	on.Store(false)

	_, err = c.Image(within(t, 100*time.Millisecond), repo, d, CredSet{})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	clk.Advance(119 * time.Second)
	_, err = c.Image(within(t, 100*time.Millisecond), repo, d, CredSet{})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Equal(t, 1, s.Count("GET", manifestsRe))
	clk.Advance(time.Second)
	_, err = c.Image(within(t, 5*time.Second), repo, d, CredSet{})
	require.NoError(t, err)

	// A budgeted registry's 429 without Retry-After empties the bucket and holds for one token's refill.
	var on2 atomic.Bool
	s2 := regtest.Start(t, regtest.WithMiddleware(tooMany(&on2, map[string]string{"RateLimit-Limit": "10;w=3600"})))
	d2 := s2.Push(t, "app:v1", randomImage(t))
	c2 := New(Options{Now: clk.Now})
	on2.Store(true)
	_, err = c2.Image(within(t, 5*time.Second), s2.Host+"/app", d2, CredSet{})
	require.ErrorIs(t, err, ErrRateLimited)
	on2.Store(false)
	require.Equal(t, []BudgetState{{Registry: s2.Host, Known: true, Limit: 10, Remaining: 0, Window: time.Hour}}, c2.Budgets())
	_, err = c2.Image(within(t, 100*time.Millisecond), s2.Host+"/app", d2, CredSet{})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	clk.Advance(6 * time.Minute)
	_, err = c2.Image(within(t, 5*time.Second), s2.Host+"/app", d2, CredSet{})
	require.NoError(t, err)
}

// roundTripFunc is an http.RoundTripper made of a function.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestBudget_RemainingNeverGivesBackUnseenTokens (F53): a response's RateLimit-Remaining is no newer
// than the tokens taken locally that the registry has not counted yet (a manifest GET still in flight,
// a recent Reserve for the cataloguer's pulls), so while there are any it may lower the bucket but
// never give those tokens back.
func TestBudget_RemainingNeverGivesBackUnseenTokens(t *testing.T) {
	const host = "registry.example.com"
	var remaining atomic.Int32
	remaining.Store(10)
	release := make(chan struct{})
	base := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/v2/app/manifests/slow" {
			<-release
		}
		h := http.Header{}
		h.Set("RateLimit-Limit", "10;w=3600")
		h.Set("RateLimit-Remaining", strconv.Itoa(int(remaining.Load())))
		return &http.Response{StatusCode: http.StatusOK, Header: h, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})
	clk := newClock()
	tr := newBudgetTransport(base, clk.Now)
	call := func(method, path string) {
		t.Helper()
		req, err := http.NewRequestWithContext(within(t, 5*time.Second), method, "https://"+host+path, nil)
		require.NoError(t, err)
		resp, err := tr.RoundTrip(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
	}
	tokens := func() float64 {
		t.Helper()
		for _, s := range tr.states() {
			if s.Registry == host {
				return s.Remaining
			}
		}
		t.Fatal("no budget for " + host)
		return 0
	}

	call(http.MethodHead, "/v2/app/manifests/v1") // learns the budget without spending it
	require.Equal(t, 10.0, tokens())

	slow := make(chan struct{})
	go func() {
		defer close(slow)
		call(http.MethodGet, "/v2/app/manifests/slow")
	}()
	require.Eventually(t, func() bool { return tokens() == 9 }, 5*time.Second, time.Millisecond)

	// The registry has counted this GET but not the slow one: 9 left by its count, 8 by ours.
	remaining.Store(9)
	call(http.MethodGet, "/v2/app/manifests/fast")
	require.Equal(t, 8.0, tokens(), "the slow GET's token is not given back")
	// A lower count is taken: another client of the registry spent some.
	remaining.Store(5)
	call(http.MethodHead, "/v2/app/manifests/v1")
	require.Equal(t, 5.0, tokens())

	// Once nothing is unseen, the registry's count is the budget again, higher or lower.
	remaining.Store(7)
	close(release)
	<-slow
	require.Equal(t, 7.0, tokens())

	// Reserve's tokens stay spent while the cataloguer's pulls may not have reached the registry.
	require.NoError(t, tr.reserveFor(ctx, host, 2))
	require.Equal(t, 5.0, tokens())
	call(http.MethodHead, "/v2/app/manifests/v1")
	require.Equal(t, 5.0, tokens(), "a count from before the pulls does not refund the reservation")
	clk.Advance(reserveHold)
	remaining.Store(6)
	call(http.MethodHead, "/v2/app/manifests/v1")
	require.Equal(t, 6.0, tokens())
}
