// Package eol reads the endoflife.date product lifecycles (spec §6.4) into the store.
package eol

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/feeds"
	"github.com/the-it-dept/ffs/internal/store"
)

const (
	maxBytes = 32 << 20 // the live body is about 3 MB
	metaETag = "etag"
	dateFmt  = "2006-01-02"
)

// Feed is the endoflife.date feed. It implements feeds.Feed.
type Feed struct {
	cfg      config.FeedConfig
	st       *store.Store
	client   *http.Client
	onUpdate func(ctx context.Context) error
}

// New returns the feed. onUpdate runs after every successful Sync, including a 304; it may be nil.
func New(cfg config.FeedConfig, st *store.Store, client *http.Client, onUpdate func(ctx context.Context) error) *Feed {
	return &Feed{cfg: cfg, st: st, client: client, onUpdate: onUpdate}
}

// Name returns feeds.NameEOL.
func (f *Feed) Name() string { return feeds.NameEOL }

// Interval is how often the feed syncs.
func (f *Feed) Interval() time.Duration { return f.cfg.Interval }

// StaleAfter is how long without a success makes the feed stale.
func (f *Feed) StaleAfter() time.Duration { return f.cfg.StaleAfter }

type payload struct {
	Result []struct {
		Name     string `json:"name"`
		Releases []struct {
			Name        string  `json:"name"`
			Codename    *string `json:"codename"`
			ReleaseDate *string `json:"releaseDate"`
			IsEOL       bool    `json:"isEol"`
			EOLFrom     *string `json:"eolFrom"`
			Latest      *struct {
				Name string  `json:"name"`
				Date *string `json:"date"`
			} `json:"latest"`
		} `json:"releases"`
	} `json:"result"`
}

// Sync fetches the full product list, replaces the stored cycles and reloads the evaluator.
func (f *Feed) Sync(ctx context.Context) error {
	state, err := f.st.FeedState(ctx, feeds.NameEOL)
	if err != nil {
		return err
	}
	resp, err := feeds.Fetch(ctx, f.client, feeds.Request{
		URL:      strings.TrimSuffix(f.cfg.URL, "/") + "/products/full",
		ETag:     state.Meta[metaETag],
		MaxBytes: maxBytes,
	})
	if err != nil {
		return err
	}
	if resp.Status == http.StatusOK {
		cycles, err := parse(resp.Body)
		if err != nil {
			return err
		}
		// ReplaceEOL drops every stored cycle: an empty or broken list would wipe EOL status.
		stored, err := f.st.ListEOL(ctx)
		if err != nil {
			return err
		}
		if err := feeds.CheckShrink("the endoflife.date product list", len(stored), len(cycles)); err != nil {
			return err
		}
		if err := f.st.ReplaceEOL(ctx, cycles); err != nil {
			return err
		}
		// Re-read: the Runner may have written the state since.
		if state, err = f.st.FeedState(ctx, feeds.NameEOL); err != nil {
			return err
		}
		if state.Meta == nil {
			state.Meta = map[string]string{}
		}
		state.Meta[metaETag] = resp.ETag
		if err := f.st.PutFeedState(ctx, state); err != nil {
			return err
		}
	} else if resp.Status != http.StatusNotModified {
		return fmt.Errorf("eol: unexpected status %d", resp.Status)
	}
	if f.onUpdate != nil {
		return f.onUpdate(ctx)
	}
	return nil
}

// parse returns the cycles of every product, skipping releases with no product or cycle name. A
// list with no cycles, or with more unnamed releases than named ones (a reshaped body), is
// ErrImplausible.
func parse(body []byte) ([]store.EOLCycle, error) {
	var p payload
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("eol: decode products: %w", err)
	}
	var (
		out     []store.EOLCycle
		unnamed int
	)
	for _, prod := range p.Result {
		for _, r := range prod.Releases {
			if prod.Name == "" || r.Name == "" {
				unnamed++
				continue
			}
			c := store.EOLCycle{Product: prod.Name, Cycle: r.Name, IsEOL: r.IsEOL}
			if r.Codename != nil {
				c.Codename = *r.Codename
			}
			var err error
			if c.ReleaseDate, err = date(r.ReleaseDate); err != nil {
				return nil, fmt.Errorf("eol: %s %s releaseDate: %w", prod.Name, r.Name, err)
			}
			if r.EOLFrom != nil {
				d, err := date(r.EOLFrom)
				if err != nil {
					return nil, fmt.Errorf("eol: %s %s eolFrom: %w", prod.Name, r.Name, err)
				}
				c.EOLDate = &d
			}
			if r.Latest != nil {
				c.Latest = r.Latest.Name
				if c.LatestDate, err = date(r.Latest.Date); err != nil {
					return nil, fmt.Errorf("eol: %s %s latest date: %w", prod.Name, r.Name, err)
				}
			}
			out = append(out, c)
		}
	}
	if len(out) == 0 || unnamed > len(out) {
		return nil, fmt.Errorf("%w: the endoflife.date product list has %d products, %d named release cycles and %d unnamed",
			feeds.ErrImplausible, len(p.Result), len(out), unnamed)
	}
	return out, nil
}

func date(s *string) (time.Time, error) {
	if s == nil || *s == "" {
		return time.Time{}, nil
	}
	return time.Parse(dateFmt, *s)
}
