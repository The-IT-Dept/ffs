// Package feeds schedules the vulnerability-intelligence feeds, records their freshness in the
// store and provides the size-limited HTTP helpers the feeds fetch with.
package feeds

import (
	"context"
	"time"
)

// Feed is one scheduled data source. Sync persists its own watermark and metadata through the
// store; the Runner records only the attempt, success and error times around it.
type Feed interface {
	Name() string
	Interval() time.Duration
	StaleAfter() time.Duration
	Sync(ctx context.Context) error
}

// Feed names, as returned by Feed.Name() and used as store.FeedState keys.
const (
	NameGrypeDB = "grypedb"
	NameOSV     = "osv"
	NameCVEList = "cvelist"
	NameKEV     = "kev"
	NameEPSS    = "epss"
	NameEOL     = "eol"
)
