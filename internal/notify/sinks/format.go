package sinks

import (
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/notify"
	"github.com/the-it-dept/ffs/internal/upgrade"
)

const (
	maxItems  = 20 // advisories shown per message
	maxOwners = 10 // workloads shown per advisory
	maxPkgs   = 10 // packages shown per advisory
	maxLinks  = 3
)

var priorities = []model.Priority{model.PriorityUrgent, model.PriorityHigh, model.PriorityMedium, model.PriorityLow}

// An escaper makes text from feeds, images and advisories safe to put into a message's markup.
type escaper func(string) string

// plain leaves text as it is, for sinks that escape whole lines themselves (Slack).
func plain(s string) string { return s }

// mdInline escapes the characters that start markdown emphasis, code, spoilers, links, quotes,
// mentions and HTML wherever they are.
var mdInline = strings.NewReplacer(`\`, `\\`, "*", `\*`, "_", `\_`, "~", `\~`, "`", "\\`", "|", `\|`,
	"[", `\[`, "]", `\]`, "<", `\<`, ">", `\>`, "@", `\@`)

// escapeMarkdown escapes s for Discord and Teams markdown, so that text from feeds, images and
// advisories shows as written: no emphasis, code, spoilers, links, mentions (@everyone) or HTML,
// and no headings, quotes or lists at the start of a line.
func escapeMarkdown(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = escapeMarkdownLine(l)
	}
	return strings.Join(lines, "\n")
}

func escapeMarkdownLine(l string) string {
	rest := strings.TrimLeft(l, " \t")
	indent, lead := l[:len(l)-len(rest)], ""
	digits := len(rest) - len(strings.TrimLeft(rest, "0123456789"))
	switch {
	case strings.HasPrefix(rest, "#"), strings.HasPrefix(rest, "-"), strings.HasPrefix(rest, "+"):
		lead, rest = `\`+rest[:1], rest[1:]
	case digits > 0 && len(rest) > digits && (rest[digits] == '.' || rest[digits] == ')') &&
		(len(rest) == digits+1 || rest[digits+1] == ' ' || rest[digits+1] == '\t'):
		lead, rest = rest[:digits]+`\`+rest[digits:digits+1], rest[digits+1:] // "1. " starts a list
	}
	return indent + lead + mdInline.Replace(rest)
}

// ownerLine is "<namespace>/<Kind>/<name>", or "<Kind>/<name>" for a cluster-level subject.
func ownerLine(o model.OwnerRef) string {
	if o.Namespace == "" {
		return o.Kind + "/" + o.Name
	}
	return o.Namespace + "/" + o.Kind + "/" + o.Name
}

// pkgLine is "<name> <installed> → <fixed>", or "<name> <installed> (no fix yet)".
func pkgLine(p model.FindingPackage, esc escaper) string {
	if len(p.Fixed) == 0 {
		return fmt.Sprintf("%s %s (no fix yet)", esc(p.Name), esc(p.Installed))
	}
	return fmt.Sprintf("%s %s → %s", esc(p.Name), esc(p.Installed), esc(p.Fixed[0]))
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

// suggestionLine is "Suggested: upgrade to nginx:1.30.7 (minor), fixes …, introduces …". The
// target is upgrade.Target, so a refresh reads "nginx:1.30.6 (new digest)" (no tier: Target says
// it) and a digest-only reference has no empty "from" side.
func suggestionLine(s *model.Suggestion, esc escaper) string {
	tier := " (" + string(s.Tier) + ")"
	if s.Tier == model.TierRefresh {
		tier = ""
	}
	return fmt.Sprintf("Suggested: upgrade to %s%s, fixes %s, introduces %s",
		esc(upgrade.Target(*s)), tier, netCounts(s.Fixes), netCounts(s.Introduces))
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
func heading(it notify.Item, esc escaper) string {
	switch {
	case it.AdvisoryID == "":
		return esc(it.Title)
	case it.Title == "":
		return esc(it.AdvisoryID)
	}
	return esc(it.AdvisoryID) + " — " + esc(it.Title)
}

// escapeAll applies esc to each of ss.
func escapeAll(ss []string, esc escaper) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = esc(s)
	}
	return out
}

// itemLines are the detail lines of an item, without its workloads and links, with the text from
// feeds, images and advisories escaped by esc.
func itemLines(it notify.Item, esc escaper) []string {
	lines := []string{fmt.Sprintf("Priority: %s (%s)", it.Priority, it.Event)}
	if len(it.Reasons) > 0 {
		lines = append(lines, strings.Join(escapeAll(it.Reasons, esc), "; "))
	}
	if len(it.NodeGroups) > 0 {
		lines = append(lines, "Node groups: "+strings.Join(escapeAll(it.NodeGroups, esc), ", "))
	}
	shown := it.Packages[:min(len(it.Packages), maxPkgs)]
	for _, p := range shown {
		lines = append(lines, pkgLine(p, esc))
	}
	if extra := len(it.Packages) - len(shown) + it.TruncatedPackages; extra > 0 {
		lines = append(lines, more(extra, "package", "packages"))
	}
	if s := it.Suggestion; s != nil && s.Tier != model.TierNone {
		lines = append(lines, suggestionLine(s, esc))
	}
	if l := timesLine(it); l != "" {
		lines = append(lines, l)
	}
	if it.Provisional {
		lines = append(lines, notify.ProvisionalNote)
	}
	return lines
}

// ownerLines lists up to maxOwners workloads, and how many more there are, counting those the
// message itself left out.
func ownerLines(it notify.Item, esc escaper) (shown []string, extra int) {
	for _, o := range it.Owners[:min(len(it.Owners), maxOwners)] {
		shown = append(shown, esc(ownerLine(o)))
	}
	return shown, len(it.Owners) - len(shown) + it.TruncatedOwners
}

func more(n int, one, many string) string {
	if n == 1 {
		return "and 1 more " + one
	}
	return fmt.Sprintf("and %d more %s", n, many)
}

// extraLines are the message-level lines before the items: the summary of a baseline or digest, the
// feed health of a digest, or the stale feeds of a feed-stale alert.
func extraLines(m notify.Message, esc escaper) []string {
	var lines []string
	switch s := m.Summary; {
	case s == nil:
	case s.Legacy(): // queued by v0.0.1, which did not count findings
		lines = append(lines, fmt.Sprintf("%s: %s", workloads(s.Workloads), netCounts(s.Counts)))
	default:
		lines = append(lines, fmt.Sprintf("%s in %s: %s", findings(s.Findings), workloads(s.Workloads), netCounts(s.Counts)))
	}
	switch m.Kind {
	case notify.KindDigest:
		if stale := staleFeeds(m); len(stale) > 0 {
			lines = append(lines, "Stale feeds: "+strings.Join(escapeAll(stale, esc), ", "))
		} else if len(m.Feeds) > 0 {
			lines = append(lines, "Feeds: all current")
		}
	case notify.KindFeedStale:
		for _, f := range m.Feeds {
			if !f.Stale {
				continue
			}
			l := esc(f.Name) + ": "
			if f.LastSuccess.IsZero() {
				l += "never synced"
			} else {
				l += "last success " + fmtTime(f.LastSuccess)
			}
			l += fmt.Sprintf(", stale after %s", f.StaleAfter)
			if f.LastError != "" {
				l += ", last error: " + esc(f.LastError)
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

func workloads(n int) string { return count(n, "workload", "workloads") }

func findings(n int) string { return count(n, "finding", "findings") }

// count renders "1 workload" or "3 workloads".
func count(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
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

// capItems is the part of m's items a chat message lists, and how many were left out, counting
// those the message itself left out.
func capItems(m notify.Message) ([]notify.Item, int) {
	items := m.Items[:min(len(m.Items), maxItems)]
	return items, len(m.Items) - len(items) + m.Truncated
}

// webLink reports whether l is an absolute http(s) URL without spaces, the only links a message
// carries.
func webLink(l string) bool {
	u, err := url.Parse(l)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" &&
		!strings.ContainsFunc(l, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) })
}

// firstLinks collects up to maxLinks distinct web links from items.
func firstLinks(items []notify.Item, extra ...string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(l string) {
		if webLink(l) && !seen[l] && len(out) < maxLinks {
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
