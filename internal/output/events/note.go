package events

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	corev1 "k8s.io/api/core/v1"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/upgrade"
)

// Event reasons, in the order they are emitted for one owner.
const (
	ReasonDetected         = "VulnerabilitiesDetected"
	ReasonEscalated        = "VulnerabilitiesEscalated"
	ReasonResolved         = "VulnerabilitiesResolved"
	ReasonUpgradeAvailable = "UpgradeAvailable"
	ReasonFeedStale        = "FeedStale"
)

var reasonOrder = []string{ReasonDetected, ReasonEscalated, ReasonResolved, ReasonUpgradeAvailable}

// classify returns the reason a transition is reported under, and the priority checked against
// the configured minimum. ok is false for transitions that are never reported.
func classify(t model.Transition) (reason string, p model.Priority, ok bool) {
	switch {
	case t.Trigger == model.TriggerUpgradeAvailable && t.ToState == model.StateOpen:
		return ReasonUpgradeAvailable, t.ToPriority, true
	case t.ToState == model.StateOpen && t.FromState != model.StateOpen:
		return ReasonDetected, t.ToPriority, true
	case t.FromState == model.StateOpen && t.ToState == model.StateOpen && t.ToPriority > t.FromPriority:
		return ReasonEscalated, t.ToPriority, true
	case t.FromState == model.StateOpen && t.ToState == model.StateResolved:
		return ReasonResolved, t.FromPriority, true
	}
	return "", model.PriorityNone, false
}

// regarding returns the object an owner's events are recorded against and the note prefix. ok is
// false when the owner has no Kubernetes object to attach to.
func regarding(o model.OwnerRef, self *corev1.ObjectReference) (ref *corev1.ObjectReference, prefix string, ok bool) {
	switch {
	case o.ClusterLevel() && o.Kind == model.OwnerKindCluster:
		return self, "Kubernetes: ", self != nil
	case o.ClusterLevel() && o.Kind == model.OwnerKindNodes:
		return self, "Nodes: ", self != nil
	case o.ClusterLevel():
		return self, "Container runtime " + o.Name + ": ", self != nil
	}
	api, known := o.ObjectAPIVersion()
	if !known {
		return nil, "", false
	}
	return &corev1.ObjectReference{APIVersion: api, Kind: o.Kind, Namespace: o.Namespace, Name: o.Name, UID: typesUID(o.UID)}, "", true
}

// item is one advisory in a note.
type item struct {
	id       string
	priority model.Priority
	text     string
}

// buildItem renders the note entry for a transition under its reason. f is the finding for the
// transition's fingerprint, or nil when it is gone.
func buildItem(reason string, t model.Transition, f *model.Finding) item {
	it := item{id: t.AdvisoryID, priority: t.ToPriority, text: t.AdvisoryID}
	switch reason {
	case ReasonDetected:
		parts := []string{t.ToPriority.String()}
		if t.Provisional {
			parts = append(parts, "provisional")
		}
		if f != nil && len(f.Packages) > 0 {
			p := f.Packages[0]
			if len(p.Fixed) > 0 {
				parts = append(parts, fmt.Sprintf("%s %s -> %s", p.Name, p.Installed, p.Fixed[0]))
			} else {
				parts = append(parts, p.Name+" "+p.Installed, "no fix yet")
			}
		}
		it.text = fmt.Sprintf("%s (%s)", t.AdvisoryID, strings.Join(parts, ", "))
	case ReasonEscalated:
		it.text = fmt.Sprintf("%s (%s -> %s)", t.AdvisoryID, t.FromPriority, t.ToPriority)
	case ReasonResolved:
		it.priority = t.FromPriority
	case ReasonUpgradeAvailable:
		if f != nil && f.Suggestion != nil {
			if target := upgrade.Target(*f.Suggestion); target != "" {
				// "nginx:1.30.6 (new digest)" reads "nginx:1.30.6, new digest" inside the item's parentheses
				if t, ok := strings.CutSuffix(target, ")"); ok {
					if head, rest, found := strings.Cut(t, " ("); found {
						target = head + ", " + rest
					}
				}
				it.text = fmt.Sprintf("%s (upgrade to %s)", t.AdvisoryID, target)
			}
		}
	}
	return it
}

func notePrefix(reason string, n int) string {
	switch reason {
	case ReasonDetected:
		return fmt.Sprintf("%d new: ", n)
	case ReasonEscalated:
		return fmt.Sprintf("%d escalated: ", n)
	case ReasonResolved:
		return fmt.Sprintf("%d resolved: ", n)
	}
	return fmt.Sprintf("%d with an upgrade available: ", n)
}

// buildNote returns the event type and note for the items of one reason. Items are ordered by
// priority descending, then advisory ID; listing stops, with " and N more", before the note would
// pass MaxNoteBytes. The first item is always listed, cut short with "..." when it alone would pass
// the cap. The returned note includes ownerPrefix, which counts against the budget.
func buildNote(reason, ownerPrefix string, items []item) (eventType, note string) {
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].priority != items[j].priority {
			return items[i].priority > items[j].priority
		}
		return items[i].id < items[j].id
	})
	eventType = "Normal"
	if reason != ReasonResolved && items[0].priority >= model.PriorityHigh {
		eventType = "Warning"
	}
	var b strings.Builder
	b.WriteString(ownerPrefix)
	b.WriteString(notePrefix(reason, len(items)))
	listed := 0
	for i, it := range items {
		add := it.text
		if i > 0 {
			add = ", " + add
		}
		tail := len(moreText(len(items) - (i + 1)))
		if b.Len()+len(add)+tail > MaxNoteBytes {
			if i == 0 {
				b.WriteString(cut(add, MaxNoteBytes-b.Len()-tail-len(ellipsis)) + ellipsis)
				listed++
			}
			break
		}
		b.WriteString(add)
		listed++
	}
	b.WriteString(moreText(len(items) - listed))
	return eventType, cut(b.String(), MaxNoteBytes)
}

const ellipsis = "..."

// moreText is the note's " and N more" for n unlisted items, "" for none.
func moreText(n int) string {
	if n <= 0 {
		return ""
	}
	return fmt.Sprintf(" and %d more", n)
}

// cut returns s cut to at most n bytes, at a UTF-8 character boundary.
func cut(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
