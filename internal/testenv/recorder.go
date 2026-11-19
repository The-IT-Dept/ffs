package testenv

import (
	"fmt"
	"slices"
	"sync"

	"k8s.io/apimachinery/pkg/runtime"
)

// RecordedEvent is one event a Recorder received, with its note already formatted.
type RecordedEvent struct {
	Regarding                  runtime.Object
	Type, Reason, Action, Note string
}

// Recorder is an events.EventRecorder that keeps every event in memory for tests. It is safe for
// concurrent use; read Events through Snapshot while anything may still record.
type Recorder struct {
	mu     sync.Mutex
	Events []RecordedEvent
}

// Eventf records an event. Note is fmt.Sprintf(note, args...); related is ignored.
func (r *Recorder) Eventf(regarding, _ runtime.Object, eventtype, reason, action, note string, args ...interface{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Events = append(r.Events, RecordedEvent{Regarding: regarding, Type: eventtype, Reason: reason, Action: action,
		Note: fmt.Sprintf(note, args...)})
}

// Snapshot returns a copy of the events recorded so far.
func (r *Recorder) Snapshot() []RecordedEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.Events)
}
