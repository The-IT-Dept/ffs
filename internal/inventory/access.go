package inventory

import (
	"sync"
	"time"

	"github.com/the-it-dept/ffs/internal/registry"
)

// accessCache remembers which credentials the registry confirmed may pull a digest, and when. It
// lets template-only owners reuse a confirmation for TagTTL instead of asking the registry on every
// flush, without ever reusing another workload's.
type accessCache struct {
	ttl time.Duration

	mu sync.Mutex
	m  map[accessKey]time.Time
}

type accessKey struct{ creds, repo, digest string }

// maxAccessEntries is the size past which expired confirmations are dropped.
const maxAccessEntries = 4096

func newAccessCache(ttl time.Duration) *accessCache {
	return &accessCache{ttl: ttl, m: map[accessKey]time.Time{}}
}

func (c *accessCache) confirmed(cs registry.CredSet, repo, digest string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	at, ok := c.m[accessKey{cs.Key(), repo, digest}]
	return ok && now.Sub(at) < c.ttl
}

func (c *accessCache) confirm(cs registry.CredSet, repo, digest string, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[accessKey{cs.Key(), repo, digest}] = now
	if len(c.m) <= maxAccessEntries {
		return
	}
	for k, at := range c.m {
		if now.Sub(at) >= c.ttl {
			delete(c.m, k)
		}
	}
}
