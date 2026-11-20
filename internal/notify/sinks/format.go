package sinks

import (
	"fmt"
	"strings"
	"time"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/notify"
)

const (
	maxItems  = 20 // advisories shown per message
	maxOwners = 10 // workloads shown per advisory
	maxPkgs   = 10 // packages shown per advisory
	maxLinks  = 3
)

var priorities = []model.Priority{model.PriorityUrgent, model.PriorityHigh, model.PriorityMedium, model.PriorityLow}

// ownerLine is "<namespace>/<Kind>/<name>", or "<Kind>/<name>" for a cluster-level subject.
func ownerLine(o model.OwnerRef) string {
	if o.Namespace == "" {
		return o.Kind + "/" + o.Name
	}
	return o.Namespace + "/" + o.Kind + "/" + o.Name
}

// pkgLine is "<name> <installed> → <fixed>", or "<name> <installed> (no fix yet)".
func pkgLine(p model.FindingPackage) string {
	if len(p.Fixed) == 0 {
		return fmt.Sprintf("%s %s (no fix yet)", p.Name, p.Installed)
	}
	return fmt.Sprintf("%s %s → %s", p.Name, p.Installed, p.Fixed[0])
}

// netCounts renders counts as "2 high, 1 medium", urgent first, zeros omitted; "none" when empty.
func netCounts(c map[model.Priority]int) string {
	var parts []string
	for _, p := range priorities {
		if n := c[p]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, p))
		}
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

func suggestionLine(s *model.Suggestion) string {
	return fmt.Sprintf("Suggested: %s:%s → %s (%s), fixes %s, introduces %s",
		s.Repo, s.FromTag, s.ToTag, s.Tier, netCounts(s.Fixes), netCounts(s.Introduces))
}

func fmtTime(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") }

// timesLine is "Published …, seen by ffs …", or "" when neither time is known.
func timesLine(it notify.Item) string {
	switch {
	case !it.Published.IsZero() && !it.Observed.IsZero():
		return fmt.Sprintf("Published %s, seen by ffs %s", fmtTime(it.Published), fmtTime(it.Observed))
	case !it.Published.IsZero():
		return "Published " + fmtTime(it.Published)
	case !it.Observed.IsZero():
		return "Seen by ffs " + fmtTime(it.Observed)
	}
	return ""
}

// heading names an item: its advisory ID and title, or the title alone for a Go standard library group.
func heading(it notify.Item) string {
	switch {
	case it.AdvisoryID == "":
		return it.Title
	case it.Title == "":
		return it.AdvisoryID
	}
	return it.AdvisoryID + " — " + it.Title
}

// itemLines are the plain detail lines of an item, without its workloads and links.
func itemLines(it notify.Item) []string {
	lines := []string{fmt.Sprintf("Priority: %s (%s)", it.Priority, it.Event)}
	if len(it.Reasons) > 0 {
		lines = append(lines, strings.Join(it.Reasons, "; "))
	}
	if len(it.NodeGroups) > 0 {
		lines = append(lines, "Node groups: "+strings.Join(it.NodeGroups, ", "))
	}
	for i, p := range it.Packages {
		if i == maxPkgs {
			lines = append(lines, more(len(it.Packages)-maxPkgs, "package", "packages"))
			break
		}
		lines = append(lines, pkgLine(p))
	}
	if s := it.Suggestion; s != nil && s.Tier != model.TierNone {
		lines = append(lines, suggestionLine(s))
	}
	if l := timesLine(it); l != "" {
		lines = append(lines, l)
	}
	if it.Provisional {
		lines = append(lines, notify.ProvisionalNote)
	}
	return lines
}

// ownerLines lists up to maxOwners workloads, and how many more there are.
func ownerLines(it notify.Item) (shown []string, extra int) {
	for i, o := range it.Owners {
		if i == maxOwners {
			return shown, len(it.Owners) - maxOwners
		}
		shown = append(shown, ownerLine(o))
	}
	return shown, 0
}

func more(n int, one, many string) string {
	if n == 1 {
		return "and 1 more " + one
	}
	return fmt.Sprintf("and %d more %s", n, many)
}

// extraLines are the message-level lines before the items: the summary of a baseline or digest, the
// feed health of a digest, or the stale feeds of a feed-stale alert.
func extraLines(m notify.Message) []string {
	var lines []string
	if m.Summary != nil {
		lines = append(lines, fmt.Sprintf("%s: %s", workloads(m.Summary.Workloads), netCounts(m.Summary.Counts)))
	}
	switch m.Kind {
	case notify.KindDigest:
		if stale := staleFeeds(m); len(stale) > 0 {
			lines = append(lines, "Stale feeds: "+strings.Join(stale, ", "))
		} else if len(m.Feeds) > 0 {
			lines = append(lines, "Feeds: all current")
		}
	case notify.KindFeedStale:
		for _, f := range m.Feeds {
			if !f.Stale {
				continue
			}
			l := f.Name + ": "
			if f.LastSuccess.IsZero() {
				l += "never synced"
			} else {
				l += "last success " + fmtTime(f.LastSuccess)
			}
			l += fmt.Sprintf(", stale after %s", f.StaleAfter)
			if f.LastError != "" {
				l += ", last error: " + f.LastError
			}
			lines = append(lines, l)
		}
	}
	return lines
}

func staleFeeds(m notify.Message) []string {
	var out []string
	for _, f := range m.Feeds {
		if f.Stale {
			out = append(out, f.Name)
		}
	}
	return out
}

func workloads(n int) string {
	if n == 1 {
		return "1 workload"
	}
	return fmt.Sprintf("%d workloads", n)
}

// truncate shortens s to at most n runes, ending in an ellipsis when it cut.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}

// capItems is the part of items a message lists, and how many were left out.
func capItems(items []notify.Item) ([]notify.Item, int) {
	if len(items) <= maxItems {
		return items, 0
	}
	return items[:maxItems], len(items) - maxItems
}

// firstLinks collects up to maxLinks distinct links from items.
func firstLinks(items []notify.Item, extra ...string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(l string) {
		if l != "" && !seen[l] && len(out) < maxLinks {
			seen[l] = true
			out = append(out, l)
		}
	}
	for _, l := range extra {
		add(l)
	}
	for _, it := range items {
		for _, l := range it.Links {
			add(l)
		}
	}
	return out
}
