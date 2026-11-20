package live

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/the-it-dept/ffs/internal/web/apigen"
)

// retryMillis is how long a browser waits before reconnecting a dropped stream.
const retryMillis = 3000

// ServeHTTP answers GET /api/v1/stream with server-sent events. Each coalesced change is one
// "changed" event whose id is its sequence; an idle stream gets a comment every Heartbeat. A
// Last-Event-ID from this hub that the ring still covers replays the events after it; any other
// gets one "all" event, so the browser refreshes everything. Above MaxStreams the answer is a 503
// problem.
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// The heartbeat ticker is created before any lock is taken: the clock must never be called with
	// the hub's lock held (a fake clock runs the flush under its own lock).
	ticker := h.o.Clock.NewTicker(h.o.Heartbeat)
	defer ticker.Stop()

	sub := &subscriber{ch: make(chan Event, subscriberBuffer), gone: make(chan struct{})}
	h.mu.Lock()
	if h.closed || len(h.subs) >= h.o.MaxStreams {
		closed := h.closed
		h.mu.Unlock()
		detail := "too many open streams; retry shortly"
		if closed {
			detail = "the server is shutting down; retry shortly"
		}
		h.refuse(w, r, detail)
		return
	}
	first := h.catchUpLocked(r.Header.Get("Last-Event-ID"))
	h.subs[sub] = struct{}{}
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		h.dropLocked(sub)
		h.mu.Unlock()
	}()

	hd := w.Header()
	hd.Set("Content-Type", "text/event-stream")
	hd.Set("X-Accel-Buffering", "no")
	rc := http.NewResponseController(w)
	// send writes and flushes one block under a write deadline, so a client that stops reading
	// releases the stream (and lets Close end it) instead of pinning it. The deadline is the
	// connection's, on the wall clock.
	send := func(write func() error) bool {
		if err := rc.SetWriteDeadline(time.Now().Add(h.o.WriteTimeout)); err != nil && !errors.Is(err, http.ErrNotSupported) {
			return false
		}
		return write() == nil && rc.Flush() == nil
	}
	if !send(func() error {
		if _, err := fmt.Fprintf(w, "retry: %d\n\n", retryMillis); err != nil {
			return err
		}
		for _, ev := range first {
			if err := writeEvent(w, ev); err != nil {
				return err
			}
		}
		return nil
	}) {
		return
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case <-h.done:
			return
		case <-sub.gone:
			return
		case ev := <-sub.ch:
			if !send(func() error { return writeEvent(w, ev) }) {
				return
			}
		case <-ticker.C():
			if !send(func() error { _, err := io.WriteString(w, ": ping\n\n"); return err }) {
				return
			}
		}
	}
}

// catchUpLocked is what a stream connecting with lastID is sent first: nothing without an id, the
// events after a known id, or one "all" event for an id this hub cannot replay from. mu must be
// held.
func (h *Hub) catchUpLocked(lastID string) []Event {
	if lastID == "" {
		return nil
	}
	if n, ok := h.knownLocked(lastID); ok {
		var out []Event
		for _, ev := range h.ring {
			if seq, _ := h.seqOf(ev.Seq); seq > n {
				out = append(out, ev)
			}
		}
		return out
	}
	return []Event{{Seq: h.seqID(h.seq), Kinds: []Kind{KindAll}, Scopes: []string{"*"}}}
}

// knownLocked parses a Last-Event-ID: it is known when it carries this hub's epoch and its number
// is the latest or one the ring can continue from (oldest-1 ≤ n ≤ latest). mu must be held.
func (h *Hub) knownLocked(id string) (uint64, bool) {
	n, ok := h.seqOf(id)
	if !ok || n > h.seq {
		return 0, false
	}
	if len(h.ring) == 0 {
		return n, n == h.seq
	}
	oldest, _ := h.seqOf(h.ring[0].Seq)
	return n, n+1 >= oldest
}

// seqOf is the sequence number of an id of this hub's epoch.
func (h *Hub) seqOf(id string) (uint64, bool) {
	epoch, num, ok := strings.Cut(id, "-")
	if !ok || epoch != h.epoch {
		return 0, false
	}
	n, err := strconv.ParseUint(num, 10, 64)
	return n, err == nil
}

// writeEvent writes one event block.
func writeEvent(w io.Writer, ev Event) error {
	data, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "id: %s\nevent: changed\ndata: %s\n\n", ev.ID(), data)
	return err
}

// refuse answers a stream the hub cannot take with a 503 too_many_streams problem.
func (h *Hub) refuse(w http.ResponseWriter, r *http.Request, detail string) {
	instance := r.URL.Path
	body, err := json.Marshal(apigen.Problem{
		Cluster: h.o.Cluster, GeneratedAt: h.o.Now().UTC(), Type: "about:blank", Title: http.StatusText(http.StatusServiceUnavailable),
		Status: http.StatusServiceUnavailable, Detail: &detail, Instance: &instance, Code: apigen.ProblemCodeTooManyStreams,
	})
	if err != nil {
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write(body)
}
