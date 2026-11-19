package sinks

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/the-it-dept/ffs/internal/notify"
	"github.com/the-it-dept/ffs/internal/version"
)

const (
	postTimeout  = 15 * time.Second
	maxBodyShown = 200 // bytes of a response body kept in an error
)

// Poster posts alert bodies to an endpoint. Its direct client refuses to dial addresses the SSRF
// guard forbids; its proxied client is used when the environment configures a proxy for the URL.
type Poster struct {
	direct, proxied *http.Client
	allowPrivate    bool
	// lookup resolves the destination host before sending; nil skips the check (tests only).
	lookup func(ctx context.Context, host string) ([]netip.Addr, error)
}

// NewPoster returns a Poster. allowPrivate lets it reach private and carrier-grade NAT addresses.
func NewPoster(allowPrivate bool) *Poster {
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			a, err := netip.ParseAddr(host)
			if err != nil {
				return err
			}
			return CheckAddr(a, allowPrivate)
		},
	}
	redirect := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Poster{
		direct: &http.Client{Timeout: postTimeout, CheckRedirect: redirect,
			Transport: &http.Transport{DialContext: dialer.DialContext, TLSHandshakeTimeout: 10 * time.Second}},
		proxied: &http.Client{Timeout: postTimeout, CheckRedirect: redirect,
			Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, TLSHandshakeTimeout: 10 * time.Second}},
		allowPrivate: allowPrivate,
		lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
	}
}

// Post sends body to rawURL. It returns nil on a 2xx response and otherwise a *notify.DeliveryError
// whose message never contains the URL path or query.
func (p *Poster) Post(ctx context.Context, rawURL, contentType string, body []byte, hdr http.Header) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, strings.NewReader(string(body)))
	if err != nil {
		return &notify.DeliveryError{Permanent: true, Msg: "invalid endpoint URL"}
	}
	host := req.URL.Hostname()
	for k, vs := range hdr {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", version.UserAgent())

	client := p.direct
	if proxy, _ := http.ProxyFromEnvironment(req); proxy != nil {
		client = p.proxied
	}
	if p.lookup != nil {
		addrs, err := p.lookup(ctx, host)
		if err != nil {
			return transportError(host, err)
		}
		for _, a := range addrs {
			if err := CheckAddr(a, p.allowPrivate); err != nil {
				return &notify.DeliveryError{Permanent: true, Msg: fmt.Sprintf("%s: %v", host, err)}
			}
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return transportError(host, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyShown))
	return classify(host, resp, string(snippet), time.Now())
}

// classify turns a non-2xx response into a DeliveryError.
func classify(host string, resp *http.Response, snippet string, now time.Time) *notify.DeliveryError {
	snippet = strings.Join(strings.Fields(strings.ToValidUTF8(snippet, "")), " ")
	msg := fmt.Sprintf("%s: HTTP %d", host, resp.StatusCode)
	if snippet != "" {
		msg += ": " + snippet
	}
	e := &notify.DeliveryError{Status: resp.StatusCode, Msg: msg}
	switch s := resp.StatusCode; {
	case s == http.StatusGone:
		e.Gone, e.Permanent = true, true
	case s == http.StatusTooManyRequests, s == http.StatusRequestTimeout, s >= 500:
		e.RetryAfter = parseRetryAfter(resp.Header.Get("Retry-After"), now)
	default: // other 4xx, and 3xx: redirects are not followed
		e.Permanent = true
	}
	return e
}

// parseRetryAfter reads delta-seconds or an HTTP-date; it returns 0 when absent or unparseable.
func parseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil {
		return time.Duration(max(n, 0)) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		return max(t.Sub(now), 0)
	}
	return 0
}

// transportError reports a failure to connect without the URL that *url.Error carries.
func transportError(host string, err error) *notify.DeliveryError {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		err = fmt.Errorf("lookup: %s", dns.Err)
	}
	return &notify.DeliveryError{Msg: fmt.Sprintf("%s: %v", host, err)}
}
