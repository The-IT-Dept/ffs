// Package webhookrx receives ffs webhook alerts: CloudEvents bodies signed per Standard Webhooks v1.
// It records every delivery with whether its signature verified, for the end-to-end suite and
// hack/webhook-receiver.
package webhookrx

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Tolerance is how far a delivery's webhook-timestamp may be from the receiver's clock.
const Tolerance = 5 * time.Minute

// maxBody bounds a delivery body.
const maxBody = 16 << 20

// Delivery is one received webhook request.
type Delivery struct {
	ID, Type  string    // webhook-id header; the CloudEvents type of the body
	Timestamp time.Time // webhook-timestamp header; zero when absent or malformed
	Body      []byte    // what was read of the body
	Verified  bool      // the signature verified against the receiver's secret
	Received  time.Time
	// ReadErr is why the body could not be read in full (too large, or the connection failed), "" when it was. Such
	// a delivery is recorded unverified and answered 400.
	ReadErr string
}

// Verify checks a Standard Webhooks v1 signature: sigHeader holds space-separated "v1,<base64>"
// entries, one of which must be the HMAC-SHA256 of id + "." + timestamp + "." + body under the
// secret ("whsec_<base64>"), and timestamp (Unix seconds) must be within Tolerance of now.
func Verify(secret, id, timestamp string, body []byte, sigHeader string, now time.Time) error {
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	if err != nil {
		return fmt.Errorf("signing secret is not base64: %w", err)
	}
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("webhook-timestamp %q is not Unix seconds", timestamp)
	}
	if d := now.Sub(time.Unix(ts, 0)); d > Tolerance || d < -Tolerance {
		return fmt.Errorf("webhook-timestamp %s is outside the %s tolerance", time.Unix(ts, 0).UTC().Format(time.RFC3339), Tolerance)
	}
	mac := hmac.New(sha256.New, key)
	_, _ = io.WriteString(mac, id+"."+timestamp+".")
	_, _ = mac.Write(body)
	want := mac.Sum(nil)
	for _, entry := range strings.Fields(sigHeader) {
		version, sig, ok := strings.Cut(entry, ",")
		if !ok || version != "v1" {
			continue
		}
		got, err := base64.StdEncoding.DecodeString(sig)
		if err == nil && hmac.Equal(got, want) {
			return nil
		}
	}
	return errors.New("no v1 signature matches")
}

// Receiver is an http.Handler that records webhook deliveries.
type Receiver struct {
	secret string

	// OnDelivery, when set before serving, is called with each recorded delivery.
	OnDelivery func(Delivery)

	mu      sync.Mutex
	got     []Delivery
	changed chan struct{} // closed and replaced on every new delivery
}

// New returns a Receiver that verifies signatures with secret ("whsec_<base64>").
func New(secret string) *Receiver {
	return &Receiver{secret: secret, changed: make(chan struct{})}
}

// ServeHTTP records the delivery and answers 204 when its signature verifies, 401 otherwise, and 400 when its body
// cannot be read, which is recorded too, so a failed delivery shows in the record rather than vanishing.
func (r *Receiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	body, readErr := io.ReadAll(http.MaxBytesReader(w, req.Body, maxBody))
	now := time.Now()
	d := Delivery{ID: req.Header.Get("webhook-id"), Type: eventType(body), Body: body, Received: now}
	ts := req.Header.Get("webhook-timestamp")
	if sec, err := strconv.ParseInt(ts, 10, 64); err == nil {
		d.Timestamp = time.Unix(sec, 0)
	}
	if readErr != nil {
		d.ReadErr = readErr.Error()
	} else {
		d.Verified = Verify(r.secret, d.ID, ts, body, req.Header.Get("webhook-signature"), now) == nil
	}

	r.mu.Lock()
	r.got = append(r.got, d)
	close(r.changed)
	r.changed = make(chan struct{})
	r.mu.Unlock()
	if r.OnDelivery != nil {
		r.OnDelivery(d)
	}

	switch {
	case d.ReadErr != "":
		http.Error(w, "unreadable body", http.StatusBadRequest)
	case d.Verified:
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusUnauthorized)
	}
}

// Deliveries returns every delivery so far, oldest first.
func (r *Receiver) Deliveries() []Delivery {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.got)
}

// Wait returns the first delivery, already received or still to come, for which match is true. It
// returns ctx's error if none arrives before ctx is done.
func (r *Receiver) Wait(ctx context.Context, match func(Delivery) bool) (Delivery, error) {
	seen := 0
	for {
		r.mu.Lock()
		got, changed := slices.Clone(r.got[seen:]), r.changed
		seen = len(r.got)
		r.mu.Unlock()
		for _, d := range got {
			if match(d) {
				return d, nil
			}
		}
		select {
		case <-ctx.Done():
			return Delivery{}, ctx.Err()
		case <-changed:
		}
	}
}

// eventType returns the "type" field of a JSON body, or "" when there is none.
func eventType(body []byte) string {
	var ev struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(body, &ev) != nil {
		return ""
	}
	return ev.Type
}
