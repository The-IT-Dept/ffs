// Package sinks delivers notify messages to Slack, Discord, Microsoft Teams and signed webhooks.
package sinks

import (
	"fmt"
	"net/url"
	"time"

	"github.com/the-it-dept/ffs/internal/notify"
)

// Sink is a destination for notification messages.
type Sink = notify.Sink

// idleCloser is a sink that keeps idle connections, which the engine closes when it replaces or drops
// the sink. Every sink is one: a sink that stopped forwarding CloseIdleConnections would keep the
// connections of a replaced endpoint open.
type idleCloser interface {
	Sink
	CloseIdleConnections()
}

var (
	_ idleCloser = (*slack)(nil)
	_ idleCloser = (*discord)(nil)
	_ idleCloser = (*teams)(nil)
	_ idleCloser = (*webhook)(nil)
)

// New builds the sink for an AlertTarget of type typ. The URL must be absolute https (http only
// with AllowPrivate); webhooks also need a valid signing secret. Errors never contain the URL.
func New(typ string, cfg notify.SinkConfig) (Sink, error) {
	return newWithPoster(typ, cfg, newPoster(cfg.AllowPrivate, cfg.Blocked))
}

func newWithPoster(typ string, cfg notify.SinkConfig, p *Poster) (Sink, error) {
	if err := checkURL(cfg.URL, cfg.AllowPrivate); err != nil {
		return nil, err
	}
	switch typ {
	case "slack":
		return &slack{url: cfg.URL, poster: p}, nil
	case "discord":
		return &discord{url: cfg.URL, poster: p}, nil
	case "teams":
		return &teams{url: cfg.URL, poster: p}, nil
	case "webhook":
		if cfg.SigningSecret == "" {
			return nil, fmt.Errorf("a webhook target needs a signing secret")
		}
		if _, err := Sign(cfg.SigningSecret, "", time.Time{}, nil); err != nil {
			return nil, err
		}
		return &webhook{url: cfg.URL, secret: cfg.SigningSecret, cluster: cfg.Cluster, poster: p}, nil
	}
	return nil, fmt.Errorf("unknown target type %q", typ)
}

// checkURL validates the endpoint without echoing it.
func checkURL(raw string, allowPrivate bool) error {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Hostname() == "" {
		return fmt.Errorf("the endpoint is not an absolute URL")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !allowPrivate {
			return fmt.Errorf("the endpoint must use https unless allowPrivate is set")
		}
	default:
		return fmt.Errorf("the endpoint must use https")
	}
	return nil
}
