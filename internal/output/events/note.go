package events

import (
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"github.com/the-it-dept/ffs/internal/model"
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
	case o.ClusterLevel():
		return self, "Container runtime " + o.Name + ": ", self != nil
	}
	api, known := model.APIVersionForKind(o.Kind)
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
			it.text = fmt.Sprintf("%s (upgrade %s -> %s)", t.AdvisoryID, f.Suggestion.FromTag, f.Suggestion.ToTag)
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
// pass MaxNoteBytes. The returned note includes ownerPrefix, which counts against the budget.
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
	prefix := notePrefix(reason, len(items))
	var b strings.Builder
	b.WriteString(ownerPrefix)
	b.WriteString(prefix)
	listed := 0
	for i, it := range items {
		add := it.text
		if i > 0 {
			add = ", " + add
		}
		more := len(items) - (i + 1)
		tail := 0
		if more > 0 {
			tail = len(fmt.Sprintf(" and %d more", more))
		}
		if b.Len()+len(add)+tail > MaxNoteBytes {
			break
		}
		b.WriteString(add)
		listed++
	}
	if listed < len(items) {
		fmt.Fprintf(&b, " and %d more", len(items)-listed)
	}
	return eventType, b.String()
}
