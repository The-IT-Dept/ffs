package upgrade

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// ErrNoRelease is returned by LatestPatch when the release server has no stable release for a minor.
var ErrNoRelease = errors.New("upgrade: no stable release for that minor")

const (
	defaultReleaseURL = "https://dl.k8s.io/release"
	releaseTimeout    = 15 * time.Second
	releaseMaxBytes   = 64
)

var releaseVersion = regexp.MustCompile(`^v(\d+\.\d+\.\d+)$`)

// LatestPatch returns the newest stable patch release of Kubernetes major.minor ("1.35.10"), read
// from {baseURL}/stable-{major}.{minor}.txt. A 404 wraps ErrNoRelease. A nil client uses a default
// one; an empty baseURL is the official release server.
func LatestPatch(ctx context.Context, c *http.Client, baseURL string, major, minor int) (string, error) {
	if c == nil {
		c = &http.Client{}
	}
	if baseURL == "" {
		baseURL = defaultReleaseURL
	}
	ctx, cancel := context.WithTimeout(ctx, releaseTimeout)
	defer cancel()
	url := fmt.Sprintf("%s/stable-%d.%d.txt", strings.TrimRight(baseURL, "/"), major, minor)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("upgrade: release request: %w", err)
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("upgrade: fetching %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return "", fmt.Errorf("%w: %d.%d", ErrNoRelease, major, minor)
	case resp.StatusCode != http.StatusOK:
		return "", fmt.Errorf("upgrade: fetching %s: status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, releaseMaxBytes))
	if err != nil {
		return "", fmt.Errorf("upgrade: reading %s: %w", url, err)
	}
	m := releaseVersion.FindStringSubmatch(strings.TrimSpace(string(body)))
	if m == nil {
		return "", fmt.Errorf("upgrade: %s: unexpected release %q", url, strings.TrimSpace(string(body)))
	}
	return m[1], nil
}
