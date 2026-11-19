package sinks

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/notify"
)

var update = flag.Bool("update", false, "rewrite golden files")

const secret = testSecret

type captured struct {
	req  *http.Request
	body []byte
}

func capture(t *testing.T) (*httptest.Server, func() []captured) {
	t.Helper()
	var mu sync.Mutex
	var got []captured
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, captured{r, b})
		mu.Unlock()
	}))
	t.Cleanup(srv.Close)
	return srv, func() []captured { mu.Lock(); defer mu.Unlock(); return append([]captured(nil), got...) }
}

func mediaType(h string) string { m, _, _ := mime.ParseMediaType(h); return m }

func TestWebhook_SignatureMatchesStandardWebhooksVector(t *testing.T) {
	sig, err := Sign("whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw", "msg_p5jXN8AQM9LWM0D4loKWxJek", time.Unix(1614265330, 0), []byte(`{"test": 2432232314}`))
	require.NoError(t, err)
	assert.Equal(t, "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=", sig)
	_, err = Sign("whsec_c2hvcnQ=", "id", time.Unix(0, 0), nil)
	assert.Error(t, err)
	_, err = Sign("whsec_!!!", "id", time.Unix(0, 0), nil)
	assert.Error(t, err)
}

func send(t *testing.T, m notify.Message) captured {
	t.Helper()
	srv, got := capture(t)
	s, err := newWithPoster("webhook", notify.SinkConfig{URL: srv.URL, SigningSecret: secret, Cluster: "prod", AllowPrivate: true}, testPoster(srv))
	require.NoError(t, err)
	require.NoError(t, s.Send(context.Background(), m))
	require.Len(t, got(), 1)
	return got()[0]
}

func TestWebhook_CloudEventEnvelope(t *testing.T) {
	m := immediate(2)
	c := send(t, m)
	assert.Equal(t, "application/cloudevents+json", mediaType(c.req.Header.Get("Content-Type")))
	assert.Equal(t, m.ID, c.req.Header.Get("webhook-id"))
	var ce map[string]any
	require.NoError(t, json.Unmarshal(c.body, &ce))
	assert.Equal(t, m.ID, ce["id"])
	assert.Equal(t, "1.0", ce["specversion"])
	assert.Equal(t, "/ffs/prod", ce["source"])
	assert.Equal(t, "au.theitdept.ffs.finding.detected.v1", ce["type"])
	assert.Equal(t, "application/json", ce["datacontenttype"])
	assert.Equal(t, "CVE-2026-0001", ce["subject"])
	assert.Equal(t, "2026-11-19T03:04:05Z", ce["time"])

	ts := c.req.Header.Get("webhook-timestamp")
	n, err := strconv.ParseInt(ts, 10, 64)
	require.NoError(t, err)
	want, err := Sign(secret, m.ID, time.Unix(n, 0), c.body)
	require.NoError(t, err)
	assert.Equal(t, want, c.req.Header.Get("webhook-signature"))

	assertGoldenJSON(t, "testdata/webhook_immediate.json", ce["data"])
}

func assertGoldenJSON(t *testing.T, path string, v any) {
	t.Helper()
	got, err := json.MarshalIndent(v, "", "  ")
	require.NoError(t, err)
	got = append(got, '\n')
	if *update {
		require.NoError(t, os.WriteFile(path, got, 0o600))
	}
	want, err := os.ReadFile(path) //nolint:gosec // G304: path is a fixed testdata file
	require.NoError(t, err)
	assert.JSONEq(t, string(want), string(got))
}

func TestWebhook_EventTypes(t *testing.T) {
	ev := func(e notify.Event) notify.Message {
		return notify.Message{Kind: notify.KindImmediate, Items: []notify.Item{{Event: e}}}
	}
	for want, m := range map[string]notify.Message{
		"au.theitdept.ffs.finding.detected.v1":  ev(notify.EventDetected),
		"au.theitdept.ffs.finding.escalated.v1": ev(notify.EventEscalated),
		"au.theitdept.ffs.finding.resolved.v1":  ev(notify.EventResolved),
		"au.theitdept.ffs.digest.v1":            {Kind: notify.KindDigest},
		"au.theitdept.ffs.feed.stale.v1":        {Kind: notify.KindFeedStale},
	} {
		assert.Equal(t, want, EventType(m))
	}
	assert.Equal(t, "au.theitdept.ffs.finding.detected.v1", EventType(ev(notify.EventReopened)))
	assert.Equal(t, "au.theitdept.ffs.digest.v1", EventType(notify.Message{Kind: notify.KindBaseline}))
}

func TestWebhook_DigestPayload(t *testing.T) {
	m := digest(1)
	m.Feeds = []notify.FeedStatus{{Name: "osv", StaleAfter: time.Hour, Stale: true}}
	c := send(t, m)
	var ce struct {
		Subject string
		Data    struct {
			Summary struct {
				Workloads int
				Counts    map[string]int
			}
			Feeds []map[string]any
		}
	}
	require.NoError(t, json.Unmarshal(c.body, &ce))
	assert.Empty(t, ce.Subject)
	assert.Equal(t, 7, ce.Data.Summary.Workloads)
	assert.Equal(t, map[string]int{"urgent": 1, "high": 0, "medium": 0, "low": 3}, ce.Data.Summary.Counts)
	assert.EqualValues(t, 3600, ce.Data.Feeds[0]["staleAfterSeconds"])
	assert.Equal(t, true, ce.Data.Feeds[0]["stale"])
	_ = model.PriorityLow
}

func TestWebhook_SameIDAcrossRetries(t *testing.T) {
	srv, got := capture(t)
	s, err := newWithPoster("webhook", notify.SinkConfig{URL: srv.URL, SigningSecret: secret, Cluster: "prod", AllowPrivate: true}, testPoster(srv))
	require.NoError(t, err)
	m := immediate(1)
	require.NoError(t, s.Send(context.Background(), m))
	time.Sleep(1100 * time.Millisecond)
	require.NoError(t, s.Send(context.Background(), m))
	g := got()
	require.Len(t, g, 2)
	assert.Equal(t, g[0].req.Header.Get("webhook-id"), g[1].req.Header.Get("webhook-id"))
	var a, b map[string]any
	require.NoError(t, json.Unmarshal(g[0].body, &a))
	require.NoError(t, json.Unmarshal(g[1].body, &b))
	assert.Equal(t, a["id"], b["id"])
	assert.NotEqual(t, g[0].req.Header.Get("webhook-timestamp"), g[1].req.Header.Get("webhook-timestamp"))
}
