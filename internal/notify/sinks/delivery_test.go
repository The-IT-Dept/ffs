package sinks

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/notify"
	"github.com/the-it-dept/ffs/internal/version"
)

// testPoster talks to srv without the SSRF checks, which would refuse its loopback address.
func testPoster(srv *httptest.Server) *Poster {
	c := srv.Client()
	c.Timeout = postTimeout
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Poster{direct: c, proxied: c}
}

func deliveryErr(t *testing.T, err error) *notify.DeliveryError {
	t.Helper()
	var de *notify.DeliveryError
	require.True(t, errors.As(err, &de), "%v", err)
	return de
}

func TestPoster_StatusClassification(t *testing.T) {
	httpDate := time.Now().Add(90 * time.Second).UTC().Format(http.TimeFormat)
	cases := []struct {
		status     int
		retryAfter string
		check      func(t *testing.T, err error)
	}{
		{200, "", func(t *testing.T, err error) { assert.NoError(t, err) }},
		{202, "", func(t *testing.T, err error) { assert.NoError(t, err) }},
		{204, "", func(t *testing.T, err error) { assert.NoError(t, err) }},
		{410, "", func(t *testing.T, err error) { assert.True(t, deliveryErr(t, err).Gone) }},
		{429, "30", func(t *testing.T, err error) {
			de := deliveryErr(t, err)
			assert.Equal(t, 30*time.Second, de.RetryAfter)
			assert.False(t, de.Permanent)
		}},
		{503, httpDate, func(t *testing.T, err error) {
			de := deliveryErr(t, err)
			assert.InDelta(t, 90*time.Second, de.RetryAfter, float64(5*time.Second))
			assert.False(t, de.Permanent)
		}},
		{408, "", func(t *testing.T, err error) { assert.False(t, deliveryErr(t, err).Permanent) }},
		{500, "", func(t *testing.T, err error) { assert.False(t, deliveryErr(t, err).Permanent) }},
		{400, "", func(t *testing.T, err error) { assert.True(t, deliveryErr(t, err).Permanent) }},
		{401, "", func(t *testing.T, err error) { assert.True(t, deliveryErr(t, err).Permanent) }},
		{403, "", func(t *testing.T, err error) { assert.True(t, deliveryErr(t, err).Permanent) }},
		{404, "", func(t *testing.T, err error) { assert.True(t, deliveryErr(t, err).Permanent) }},
		{413, "", func(t *testing.T, err error) { assert.True(t, deliveryErr(t, err).Permanent) }},
		{302, "", func(t *testing.T, err error) { assert.True(t, deliveryErr(t, err).Permanent) }},
	}
	for _, c := range cases {
		var hits atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			if c.retryAfter != "" {
				w.Header().Set("Retry-After", c.retryAfter)
			}
			if c.status == 302 {
				w.Header().Set("Location", "http://127.0.0.1:1/elsewhere")
			}
			w.WriteHeader(c.status)
			_, _ = w.Write([]byte(strings.Repeat("e", 500)))
		}))
		err := testPoster(srv).Post(context.Background(), srv.URL+"/secret/path", "application/json", []byte(`{}`), nil)
		c.check(t, err)
		if err != nil {
			de := deliveryErr(t, err)
			assert.Equal(t, c.status, de.Status)
			assert.NotContains(t, de.Msg, "/secret/path")
			assert.LessOrEqual(t, len(de.Msg), 300)
		}
		assert.EqualValues(t, 1, hits.Load(), "status %d: redirects must not be followed", c.status)
		srv.Close()
	}
}

func TestPoster_TimeoutIs15s(t *testing.T) {
	p := NewPoster(false)
	assert.Equal(t, 15*time.Second, p.direct.Timeout)
	assert.Equal(t, 15*time.Second, p.proxied.Timeout)

	var ua string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ua = r.Header.Get("User-Agent") }))
	defer srv.Close()
	require.NoError(t, testPoster(srv).Post(context.Background(), srv.URL, "text/plain", nil, nil))
	assert.Equal(t, version.UserAgent(), ua)
}

func TestPoster_ErrorsNeverContainURL(t *testing.T) {
	err := NewPoster(false).Post(context.Background(), "https://hooks.example.invalid/services/T0/B0/SECRETTOKEN", "application/json", []byte("{}"), nil)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "SECRETTOKEN")
	assert.NotContains(t, err.Error(), "services")

	// A failed connection (refused) must not leak it either.
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL + "/SECRETTOKEN"
	srv.Close()
	err = testPoster(srv).Post(context.Background(), url, "application/json", nil, nil)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "SECRETTOKEN")
}

func TestPoster_RefusesLoopbackDial(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	err := NewPoster(true).Post(context.Background(), srv.URL, "application/json", nil, nil)
	require.Error(t, err)
	assert.True(t, deliveryErr(t, err).Permanent)
	assert.Zero(t, hits.Load())
}

func TestPoster_DialGuardRefusesLoopback(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	p := NewPoster(true)
	p.lookup = nil // skip the resolver check: the dial guard alone must refuse
	require.Error(t, p.Post(context.Background(), srv.URL, "application/json", nil, nil))
	assert.Zero(t, hits.Load())
}

// TestPoster_IdleConnections pins F90: both transports drop connections idle for 90s, and
// CloseIdleConnections, which the engine calls on a sink it replaces, closes a kept-alive
// connection at once.
func TestPoster_IdleConnections(t *testing.T) {
	p := NewPoster(false)
	for _, c := range []*http.Client{p.direct, p.proxied} {
		tr, ok := c.Transport.(*http.Transport)
		require.True(t, ok)
		assert.Equal(t, 90*time.Second, tr.IdleConnTimeout)
	}

	idle, closed := make(chan struct{}, 1), make(chan struct{}, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	signal := func(c chan struct{}) {
		select {
		case c <- struct{}{}:
		default:
		}
	}
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		switch s {
		case http.StateIdle:
			signal(idle)
		case http.StateClosed:
			signal(closed)
		}
	}
	srv.Start()
	defer srv.Close()
	tp := testPoster(srv)
	require.NoError(t, tp.Post(context.Background(), srv.URL, "text/plain", nil, nil))
	select {
	case <-idle:
	case <-time.After(5 * time.Second):
		require.Fail(t, "the connection was not kept alive")
	}
	tp.CloseIdleConnections()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		require.Fail(t, "the idle connection is still open")
	}
}
