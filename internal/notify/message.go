package notify

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/the-it-dept/ffs/internal/findings"
	"github.com/the-it-dept/ffs/internal/model"
)

// Kind is the kind of notification message.
type Kind string

const (
	KindImmediate Kind = "immediate"
	KindDigest    Kind = "digest"
	KindBaseline  Kind = "baseline"
	KindFeedStale Kind = "feedStale"
)

// Event is what happened to the findings in an Item.
type Event string

const (
	EventDetected     Event = "detected"
	EventEscalated    Event = "escalated"
	EventReopened     Event = "reopened"
	EventResolved     Event = "resolved"
	EventFixAvailable Event = "fixAvailable"
	// EventUpgradeAvailable lists, in a digest only, a finding already reported whose suggested
	// upgrade arrived after it was sent (spec §6.10 message content; §6.6 UpgradeAvailable).
	EventUpgradeAvailable Event = "upgradeAvailable"
)

// ProvisionalNote is shown on an item whose findings are provisional (spec §6.5).
const ProvisionalNote = "Provisional: the distro fix state is pending."

// Message is one notification to one target. The engine builds Title; sinks use it verbatim. ID is
// stable across retries and restarts, so receivers can de-duplicate on it.
type Message struct {
	ID                         string
	Kind                       Kind
	Cluster, TargetName, Title string
	Items                      []Item
	Summary                    *Summary
	Feeds                      []FeedStatus
	DashboardURL               string
	At                         time.Time
}

// Item is one advisory (or one Go standard library version) and the workloads it affects.
type Item struct {
	Event             Event
	AdvisoryID, Title string
	Grouped           []string // advisory IDs folded into one Go standard library item
	Priority          model.Priority
	Reasons           []string
	Owners            []model.OwnerRef
	Packages          []model.FindingPackage
	FixedIn           []string
	Suggestion        *model.Suggestion
	Published         time.Time
	Observed          time.Time
	Links             []string
	Provisional       bool
	// NodeGroups names the node groups a Nodes finding affects: sorted labels, at most
	// maxNodeGroupNames, then "+N more".
	NodeGroups []string

	nodeGroupCount int // node groups in all, before NodeGroups is capped
}

// Summary counts what a baseline or digest covers.
type Summary struct {
	Workloads int
	Counts    map[model.Priority]int
}

// FeedStatus is the freshness of one feed.
type FeedStatus struct {
	Name        string
	LastSuccess time.Time
	StaleAfter  time.Duration
	Stale       bool
	LastError   string
}

// Sink delivers messages to one endpoint.
type Sink interface {
	Type() string
	Send(ctx context.Context, m Message) error
}

// DeliveryError is a failed send. Gone (HTTP 410) disables the target; Permanent fails the delivery
// without retrying; otherwise it is retried, no sooner than RetryAfter when that is set. Msg never
// contains the endpoint URL.
type DeliveryError struct {
	Status     int
	RetryAfter time.Duration
	Permanent  bool
	Gone       bool
	Msg        string
}

func (e *DeliveryError) Error() string { return e.Msg }

// messageID is the message and delivery ID: stable for the same target, kind and key.
func messageID(uid string, kind Kind, key string) string {
	sum := sha256.Sum256([]byte(uid + "|" + string(kind) + "|" + key))
	return "ffs_" + hex.EncodeToString(sum[:])[:32]
}

// plural renders "1 workload" or "3 workloads".
func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func workloads(n int) string { return plural(n, "workload", "workloads") }

// immediateTitle titles an immediate message about subject (an advisory ID or a Go standard
// library version). An item whose only owner is the Nodes owner counts the node groups it affects.
func immediateTitle(ev Event, subject string, it Item) string {
	n := workloads(len(it.Owners))
	if it.nodeGroupCount > 0 && !slices.ContainsFunc(it.Owners, func(o model.OwnerRef) bool { return !isNodes(o) }) {
		n = plural(it.nodeGroupCount, "node group", "node groups")
	}
	switch ev {
	case EventEscalated:
		return fmt.Sprintf("Escalated to %s: %s affects %s", it.Priority, subject, n)
	case EventReopened:
		return fmt.Sprintf("Reopened (%s): %s affects %s", it.Priority, subject, n)
	case EventResolved:
		return fmt.Sprintf("Resolved: %s no longer affects %s", subject, n)
	default:
		return fmt.Sprintf("New %s finding: %s affects %s", it.Priority, subject, n)
	}
}

func baselineTitle(n, urgent, high int) string {
	return fmt.Sprintf("ffs is watching %s: %d urgent, %d high", workloads(n), urgent, high)
}

// digestTitle counts the digest's sections; upgrades are named only when there are some.
func digestTitle(cluster string, added, escalated, fixes, resolved, upgrades int) string {
	t := fmt.Sprintf("ffs digest for %s: %d new, %d escalated, %s, %d resolved",
		cluster, added, escalated, plural(fixes, "fix available", "fixes available"), resolved)
	if upgrades > 0 {
		t += ", " + plural(upgrades, "upgrade available", "upgrades available")
	}
	return t
}

func feedStaleTitle(name string, lastSuccess time.Time) string {
	if lastSuccess.IsZero() {
		return fmt.Sprintf("Feed %s has never synced successfully", name)
	}
	return fmt.Sprintf("Feed %s has not synced successfully since %s", name, lastSuccess.UTC().Format("2006-01-02 15:04 UTC"))
}

// view is a finding as of the transition being reported: the stored finding when it still exists,
// with the transition's owner, advisory, state, priority and provisional flag.
func view(f model.Finding, stored bool, t model.Transition) model.Finding {
	if !stored {
		f = model.Finding{Fingerprint: t.Fingerprint}
	}
	f.Owner, f.AdvisoryID, f.State, f.Priority, f.Provisional = t.Owner, t.AdvisoryID, t.ToState, t.ToPriority, t.Provisional
	return f
}

// group is one Item and the fingerprints folded into it.
type group struct {
	key     string // advisory ID, or "go-stdlib@<installed>"; part of the immediate message ID
	subject string // what the immediate title names
	item    Item
	fps     []string
}

// itemBuilder turns findings into Items, with titles and links from the stored advisories, and the
// node groups of Nodes findings from nodeGroups (group digest → label).
type itemBuilder struct {
	advisories   map[string]model.Advisory
	dashboardURL string
	nodeGroups   map[string]string
}

// groups builds the items of one event: Go standard library findings fold into one item per Go
// version, the rest give one item per advisory. Items sort by priority, highest first, then ID.
func (b itemBuilder) groups(ev Event, fs []model.Finding) []group {
	stdlib, rest := findings.GroupStdlib(fs)
	out := make([]group, 0, len(stdlib))
	for _, g := range stdlib {
		var members []model.Finding
		for _, f := range fs {
			if f.GoStdlib && len(f.Packages) > 0 && f.Packages[0].Installed == g.Installed {
				members = append(members, f)
			}
		}
		it := stdlibItem(ev, g, members)
		it.NodeGroups, it.nodeGroupCount = nodeGroupNames(members, b.nodeGroups)
		out = append(out, group{
			key:     "go-stdlib@" + g.Installed,
			subject: "Go " + strings.TrimPrefix(g.Installed, "go") + " standard library",
			item:    it,
			fps:     fingerprints(members),
		})
	}
	for _, members := range byAdvisory(rest) {
		id := members[0].AdvisoryID
		out = append(out, group{key: id, subject: id, item: b.advisoryItem(ev, id, members), fps: fingerprints(members)})
	}
	slices.SortStableFunc(out, func(x, y group) int { return compareItems(x.item, y.item) })
	return out
}

// advisoryItem builds the item of one advisory over its findings.
func (b itemBuilder) advisoryItem(ev Event, id string, fs []model.Finding) Item {
	it := Item{Event: ev, AdvisoryID: id}
	fill(&it, fs)
	it.NodeGroups, it.nodeGroupCount = nodeGroupNames(fs, b.nodeGroups)
	if a, ok := b.advisories[id]; ok {
		it.Title = a.Title
		it.Links = slices.Clone(a.Links)
		if !a.Published.IsZero() {
			it.Published = a.Published
		}
		if !a.Observed.IsZero() {
			it.Observed = a.Observed
		}
	}
	if b.dashboardURL != "" {
		it.Links = append(it.Links, strings.TrimRight(b.dashboardURL, "/")+"/vulnerabilities/"+url.PathEscape(id))
	}
	return it
}

// baselineItems builds one item per advisory of a baseline's open findings, highest priority first,
// then the most workloads and advisory ID, and keeps the first baselineItems.
func (b itemBuilder) baselineItems(open []model.Finding) []Item {
	var items []Item
	for _, fs := range byAdvisory(open) {
		items = append(items, b.advisoryItem("", fs[0].AdvisoryID, fs))
	}
	slices.SortFunc(items, func(a, b Item) int {
		return cmp.Or(cmp.Compare(b.Priority, a.Priority), cmp.Compare(len(b.Owners), len(a.Owners)), strings.Compare(a.AdvisoryID, b.AdvisoryID))
	})
	return items[:min(len(items), baselineItems)]
}

// stdlibItem builds the item of one Go standard library version (spec §6.5): the group's title,
// advisories and highest priority, and its single fixing Go version.
func stdlibItem(ev Event, g findings.StdlibGroup, fs []model.Finding) Item {
	it := Item{Event: ev, Title: g.Title(), Grouped: g.AdvisoryIDs}
	fill(&it, fs)
	it.Priority = g.Highest
	it.FixedIn = nil
	if g.FixedIn != "" {
		it.FixedIn = []string{g.FixedIn}
	}
	// Each finding lists its own fixed version; the group's is the one that fixes them all.
	pkgs := it.Packages[:0]
	for _, p := range it.Packages {
		if p.Installed == g.Installed {
			p.Fixed = it.FixedIn
			pkgs = append(pkgs, p)
		}
	}
	it.Packages = pkgs
	return it
}

// fill sets the owner, package, priority, reason and suggestion fields of it from fs.
func fill(it *Item, fs []model.Finding) {
	fs = slices.Clone(fs)
	slices.SortFunc(fs, func(a, b model.Finding) int {
		return cmp.Or(strings.Compare(a.Owner.Key(), b.Owner.Key()), strings.Compare(a.Fingerprint, b.Fingerprint))
	})
	type pkgKey struct{ name, eco, installed, path string }
	seenOwner := map[string]bool{}
	seenPkg := map[pkgKey]bool{}
	for _, f := range fs {
		it.Priority = max(it.Priority, f.Priority)
		it.Provisional = it.Provisional || f.Provisional
		if k := f.Owner.Key(); !seenOwner[k] {
			seenOwner[k] = true
			it.Owners = append(it.Owners, f.Owner)
		}
		for _, p := range f.Packages {
			if k := (pkgKey{p.Name, p.Ecosystem, p.Installed, p.Path}); !seenPkg[k] {
				seenPkg[k] = true
				it.Packages = append(it.Packages, p)
			}
		}
		it.Published = earliest(it.Published, f.Published)
		it.Observed = earliest(it.Observed, f.Observed)
	}
	for _, f := range fs {
		if f.Priority != it.Priority {
			continue
		}
		for _, r := range f.Reasons {
			if !slices.Contains(it.Reasons, r) {
				it.Reasons = append(it.Reasons, r)
			}
		}
		if it.Suggestion == nil && f.Suggestion != nil {
			it.Suggestion = f.Suggestion
		}
	}
	for _, p := range it.Packages {
		if len(p.Fixed) > 0 && !slices.Contains(it.FixedIn, p.Fixed[0]) {
			it.FixedIn = append(it.FixedIn, p.Fixed[0])
		}
	}
}

// byAdvisory splits fs per advisory, in first-seen order.
func byAdvisory(fs []model.Finding) [][]model.Finding {
	idx := map[string]int{}
	var out [][]model.Finding
	for _, f := range fs {
		i, ok := idx[f.AdvisoryID]
		if !ok {
			i = len(out)
			idx[f.AdvisoryID] = i
			out = append(out, nil)
		}
		out[i] = append(out[i], f)
	}
	return out
}

// compareItems orders by priority, highest first, then advisory ID (title for Go stdlib items).
func compareItems(a, b Item) int {
	return cmp.Or(cmp.Compare(b.Priority, a.Priority), strings.Compare(cmp.Or(a.AdvisoryID, a.Title), cmp.Or(b.AdvisoryID, b.Title)))
}

func fingerprints(fs []model.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Fingerprint
	}
	return out
}

// earliest returns the earlier of two times, ignoring zero ones.
func earliest(a, b time.Time) time.Time {
	if a.IsZero() || (!b.IsZero() && b.Before(a)) {
		return b
	}
	return a
}
