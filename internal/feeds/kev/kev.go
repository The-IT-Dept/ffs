// Package kev reads the CISA Known Exploited Vulnerabilities catalogue (spec §6.4). A CVE in the
// catalogue gets its KEVAdded date on the stored advisory, which makes its findings urgent
// (spec §6.6). Only advisories already in use by a match are touched.
package kev

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/feeds"
	"github.com/the-it-dept/ffs/internal/store"
	"github.com/the-it-dept/ffs/internal/version"
)

// DefaultURL is the catalogue URL used when Config.URL is empty.
const DefaultURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

const (
	maxBytes  = 32 << 20
	metaETag  = "etag"
	metaCount = "count" // entries in the last catalogue accepted
	cacheRel  = "feeds/kev.json"
)

// Handler consumes the IDs of advisories whose KEV status changed; wiring passes
// engine.OnAdvisoriesEnriched. Until it returns nil the IDs stay pending and the next Sync offers
// them again.
type Handler func(ctx context.Context, ids []string) error

// Options configures a Feed.
type Options struct {
	Config  config.FeedConfig
	Store   *store.Store
	HTTP    *http.Client // nil = feeds.NewHTTPClient(version.UserAgent())
	Handler Handler
	DataDir string           // the catalogue is cached at DataDir/feeds/kev.json
	Now     func() time.Time // nil = time.Now
}

// Feed is the KEV feed. It implements feeds.Feed.
type Feed struct{ o Options }

// New returns the KEV feed.
func New(o Options) *Feed {
	if o.Config.URL == "" {
		o.Config.URL = DefaultURL
	}
	if o.HTTP == nil {
		o.HTTP = feeds.NewHTTPClient(version.UserAgent())
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Feed{o: o}
}

// Name implements feeds.Feed.
func (f *Feed) Name() string { return feeds.NameKEV }

// Interval implements feeds.Feed.
func (f *Feed) Interval() time.Duration { return f.o.Config.Interval }

// StaleAfter implements feeds.Feed.
func (f *Feed) StaleAfter() time.Duration { return f.o.Config.StaleAfter }

type catalogue struct {
	Vulnerabilities []struct {
		CVEID     string `json:"cveID"`
		DateAdded string `json:"dateAdded"`
	} `json:"vulnerabilities"`
}

// Sync fetches the catalogue with a conditional GET, then compares it with every advisory in use,
// whether or not the catalogue changed: an advisory first matched today is scored from the cached
// catalogue. Changed advisories (set or cleared) are handed to the handler with any left pending.
func (f *Feed) Sync(ctx context.Context) error {
	st, err := f.o.Store.FeedState(ctx, feeds.NameKEV)
	if err != nil {
		return err
	}
	cache := filepath.Join(f.o.DataDir, cacheRel)
	dates, err := f.catalogue(ctx, &st, cache)
	if err != nil {
		return err
	}

	inUse, err := f.o.Store.AdvisoryIDsInUse(ctx)
	if err != nil {
		return err
	}
	have, err := f.o.Store.Advisories(ctx, inUse)
	if err != nil {
		return err
	}
	set := map[string]bool{}
	for _, id := range feeds.Pending(st) {
		set[id] = true
	}
	for _, id := range inUse {
		want, listed := dates[id]
		cur := have[id].KEVAdded
		if listed == (cur != nil) && (!listed || cur.Equal(want)) {
			continue
		}
		var v *time.Time
		if listed {
			v = &want
		}
		if err := f.o.Store.SetAdvisoryKEV(ctx, id, v); err != nil {
			// Earlier IDs are already updated in the store; keep them pending for the next run.
			return errors.Join(err, f.savePending(ctx, st, set))
		}
		set[id] = true
	}

	pending := slices.Sorted(maps.Keys(set))
	if err := f.savePending(ctx, st, set); err != nil {
		return err
	}
	if len(pending) == 0 {
		return nil
	}
	if err := f.o.Handler(ctx, pending); err != nil {
		return fmt.Errorf("kev: handler: %w", err)
	}
	feeds.SetPending(&st, nil)
	return f.o.Store.PutFeedState(ctx, st)
}

// savePending stores set as the feed's pending IDs.
func (f *Feed) savePending(ctx context.Context, st store.FeedState, set map[string]bool) error {
	feeds.SetPending(&st, slices.Sorted(maps.Keys(set)))
	return f.o.Store.PutFeedState(ctx, st)
}

// catalogue returns the CVE ID to date-added map, fetching it unless the server reports the cached
// copy current. On a fetch it updates st's ETag; the caller stores st.
func (f *Feed) catalogue(ctx context.Context, st *store.FeedState, cache string) (map[string]time.Time, error) {
	etag := st.Meta[metaETag]
	if etag != "" {
		if _, err := os.Stat(cache); err != nil {
			etag = "" // no cached copy to fall back on
		}
	}
	resp, err := feeds.Fetch(ctx, f.o.HTTP, feeds.Request{URL: f.o.Config.URL, ETag: etag, MaxBytes: maxBytes})
	if err != nil {
		return nil, err
	}
	switch resp.Status {
	case http.StatusNotModified:
		raw, err := os.ReadFile(cache) //nolint:gosec // G304: the path is under the configured data directory
		if err != nil {
			return nil, fmt.Errorf("kev: cached catalogue: %w", err)
		}
		return parse(raw)
	case http.StatusOK:
		dates, err := parse(resp.Body)
		if err != nil {
			return nil, err
		}
		// An empty or broken catalogue would clear every KEV flag and de-escalate urgent findings.
		prev, _ := strconv.Atoi(st.Meta[metaCount])
		if err := feeds.CheckShrink("the KEV catalogue", prev, len(dates)); err != nil {
			return nil, err
		}
		if err := feeds.WriteFile(cache, resp.Body); err != nil {
			return nil, err
		}
		if st.Meta == nil {
			st.Meta = map[string]string{}
		}
		if resp.ETag == "" {
			delete(st.Meta, metaETag)
		} else {
			st.Meta[metaETag] = resp.ETag
		}
		st.Meta[metaCount] = strconv.Itoa(len(dates))
		return dates, nil
	default:
		return nil, fmt.Errorf("kev: GET %s: unexpected status %d", f.o.Config.URL, resp.Status)
	}
}

// parse returns the catalogue's CVE ID to date-added map. A catalogue with no entries, or whose
// entries are mostly unreadable (a reshaped body), is ErrImplausible.
func parse(raw []byte) (map[string]time.Time, error) {
	var c catalogue
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("kev: catalogue: %w", err)
	}
	out := make(map[string]time.Time, len(c.Vulnerabilities))
	for _, v := range c.Vulnerabilities {
		d, err := time.Parse(time.DateOnly, v.DateAdded)
		if v.CVEID == "" || err != nil {
			continue
		}
		out[v.CVEID] = d
	}
	if len(out) == 0 || len(out) < len(c.Vulnerabilities)/2 {
		return nil, fmt.Errorf("%w: the KEV catalogue has %d readable entries of %d", feeds.ErrImplausible, len(out), len(c.Vulnerabilities))
	}
	return out, nil
}
