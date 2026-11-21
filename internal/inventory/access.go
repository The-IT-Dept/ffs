package inventory

import (
	"sync"
	"time"

	"github.com/the-it-dept/ffs/internal/model"
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

const (
	// missTTL is how long a reference whose registry lookup ended unresolvable is not looked up again
	// for the same credentials; it doubles with each further miss, up to maxMissTTL.
	missTTL    = time.Hour
	maxMissTTL = 6 * time.Hour
	// maxMissEntries is the size past which misses not refreshed within maxMissTTL are dropped.
	maxMissEntries = 4096
)

// missCache remembers the registry lookups of a reference that ended unresolvable (refused, not
// found, or not reachable), per credentials and platform, with the unresolvable image they gave and
// whether the registry refused. The owners that name such a reference reuse it instead of asking the
// registry on every flush.
type missCache struct {
	mu sync.Mutex
	m  map[missKey]miss
}

type missKey struct{ creds, ref, platform string }

type miss struct {
	img model.Image
	// refused: the registry answered unauthorized or not found. Otherwise it was not reachable, which
	// says nothing about an image an owner already had.
	refused bool
	at      time.Time     // when the lookup missed
	ttl     time.Duration // how long it holds
	until   time.Time     // at + ttl
}

func newMissCache() *missCache { return &missCache{m: map[missKey]miss{}} }

func missKeyOf(cs registry.CredSet, ref string, platform NodePlatform) missKey {
	return missKey{cs.Key(), ref, platform.Key()}
}

// get returns the miss under k when it still holds at now.
func (c *missCache) get(k missKey, now time.Time) (miss, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[k]
	if !ok || !now.Before(e.until) {
		return miss{}, false
	}
	return e, true
}

// add records a miss at now, refused or not: for missTTL the first time, twice the last hold after a
// miss that held before, at most maxMissTTL. It returns img quarantined at least until the miss ends,
// so the stored row does not show a retry before the next lookup.
func (c *missCache) add(k missKey, img model.Image, refused bool, now time.Time) model.Image {
	c.mu.Lock()
	defer c.mu.Unlock()
	ttl := missTTL
	if e, ok := c.m[k]; ok {
		ttl = min(2*e.ttl, maxMissTTL)
	}
	until := now.Add(ttl)
	if img.QuarantinedUntil.Before(until) {
		img.QuarantinedUntil = until
	}
	c.m[k] = miss{img: img, refused: refused, at: now, ttl: ttl, until: until}
	if len(c.m) > maxMissEntries {
		for key, e := range c.m {
			if now.Sub(e.at) >= maxMissTTL+e.ttl {
				delete(c.m, key)
			}
		}
	}
	return img
}

// clear forgets k after a lookup that succeeded.
func (c *missCache) clear(k missKey) {
	c.mu.Lock()
	delete(c.m, k)
	c.mu.Unlock()
}
