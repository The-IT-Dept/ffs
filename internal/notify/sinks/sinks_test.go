package sinks

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/notify"
)

// Test-only signing keys: the Standard Webhooks documentation key, and one too short to accept.
const (
	testSecret  = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw" //nolint:gosec // G101: public documentation test vector
	shortSecret = "whsec_c2hvcnQ="                         //nolint:gosec // G101: public documentation test vector
)

var t0 = time.Date(2026, 11, 19, 3, 4, 5, 0, time.UTC)

func owners(n int) []model.OwnerRef {
	out := make([]model.OwnerRef, n)
	for i := range out {
		out[i] = model.OwnerRef{Kind: "Deployment", Namespace: "ns", Name: fmt.Sprintf("app-%03d", i)}
	}
	return out
}

func item(id string, n int) notify.Item {
	return notify.Item{
		Event: notify.EventDetected, AdvisoryID: id, Title: "Remote code execution in <script>&", Priority: model.PriorityUrgent,
		Reasons: []string{"in the CISA KEV catalogue", "internet exposed"}, Owners: owners(n),
		Packages:   []model.FindingPackage{{Name: "openssl", Ecosystem: "deb", Installed: "3.0.1", Fixed: []string{"3.0.2"}, Path: "/usr/lib"}, {Name: "zlib", Installed: "1.2"}},
		FixedIn:    []string{"3.0.2"},
		Suggestion: &model.Suggestion{Repo: "docker.io/x/app", FromTag: "1.0", ToTag: "1.1", Tier: model.TierPatch, Fixes: map[model.Priority]int{model.PriorityHigh: 2, model.PriorityMedium: 1}},
		Published:  t0.Add(-48 * time.Hour), Observed: t0, Links: []string{"https://example.com/a?x=1&y=2"},
	}
}

func immediate(n int) notify.Message {
	return notify.Message{ID: "ffs_abc", Kind: notify.KindImmediate, Cluster: "prod", TargetName: "ops", At: t0,
		Title: "New urgent finding: CVE-2026-0001 affects 1 workload", Items: []notify.Item{item("CVE-2026-0001", n)}}
}

func digest(items int) notify.Message {
	m := notify.Message{ID: "ffs_d", Kind: notify.KindDigest, Cluster: "prod", TargetName: "ops", At: t0, Title: "ffs digest for prod",
		Summary: &notify.Summary{Workloads: 7, Counts: map[model.Priority]int{model.PriorityUrgent: 1, model.PriorityLow: 3}},
		Feeds:   []notify.FeedStatus{{Name: "osv", LastSuccess: t0, StaleAfter: time.Hour}}}
	for i := range items {
		m.Items = append(m.Items, item(fmt.Sprintf("CVE-2026-%04d", i), 30))
	}
	return m
}

func marshalMap(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	var out map[string]any
	require.NoError(t, json.Unmarshal(b, &out))
	return out
}

func TestSlack_BlockKitWithFallback(t *testing.T) {
	p := marshalMap(t, slackPayload(immediate(300)))
	assert.NotEmpty(t, p["text"])
	blocks := p["blocks"].([]any)
	assert.LessOrEqual(t, len(blocks), 50)
	hdr := blocks[0].(map[string]any)["text"].(map[string]any)["text"].(string)
	assert.LessOrEqual(t, utf8.RuneCountInString(hdr), 150)
	var all strings.Builder
	for _, b := range blocks[1:] {
		bm := b.(map[string]any)
		if bm["type"] == "section" {
			txt := bm["text"].(map[string]any)["text"].(string)
			assert.LessOrEqual(t, utf8.RuneCountInString(txt), 3000)
			all.WriteString(txt)
		}
	}
	assert.Contains(t, all.String(), "&lt;script&gt;&amp;")
	last := blocks[len(blocks)-1].(map[string]any)
	assert.Equal(t, "context", last["type"])
	assert.Equal(t, "and 290 more workloads", last["elements"].([]any)[0].(map[string]any)["text"])
}

func TestSlack_ManyItemsOverflow(t *testing.T) {
	p := marshalMap(t, slackPayload(digest(25)))
	blocks := p["blocks"].([]any)
	assert.LessOrEqual(t, len(blocks), 50)
	last := blocks[len(blocks)-1].(map[string]any)
	assert.Equal(t, "and 5 more advisories", last["elements"].([]any)[0].(map[string]any)["text"])
	assert.Contains(t, p["text"], "Feeds: all current")
}

func TestSlack_OneMessagePerSecondPerWebhook(t *testing.T) {
	l := limiterFor("https://hooks.slack.com/services/A")
	assert.Equal(t, rate.Every(time.Second), l.Limit())
	assert.Equal(t, 1, l.Burst())
	assert.Same(t, l, limiterFor("https://hooks.slack.com/services/A"))
	assert.NotSame(t, l, limiterFor("https://hooks.slack.com/services/B"))
}

func TestDiscord_RespectsLimits(t *testing.T) {
	p := marshalMap(t, discordPayload(digest(25)))
	assert.LessOrEqual(t, utf8.RuneCountInString(p["content"].(string)), 2000)
	embeds := p["embeds"].([]any)
	assert.LessOrEqual(t, len(embeds), 10)
	assert.NotEmpty(t, embeds)
	total := 0
	for _, e := range embeds {
		em := e.(map[string]any)
		title, desc := em["title"].(string), em["description"].(string)
		assert.LessOrEqual(t, utf8.RuneCountInString(title), 256)
		assert.LessOrEqual(t, utf8.RuneCountInString(desc), 4096)
		total += utf8.RuneCountInString(title) + utf8.RuneCountInString(desc)
		fields, _ := em["fields"].([]any)
		assert.LessOrEqual(t, len(fields), 25)
		for _, f := range fields {
			fm := f.(map[string]any)
			assert.LessOrEqual(t, utf8.RuneCountInString(fm["value"].(string)), 1024)
			total += utf8.RuneCountInString(fm["name"].(string)) + utf8.RuneCountInString(fm["value"].(string))
		}
	}
	assert.LessOrEqual(t, total, 6000)
	assert.EqualValues(t, 0xC62828, embeds[0].(map[string]any)["color"])
}

func TestTeams_AdaptiveCardEnvelope(t *testing.T) {
	p := marshalMap(t, teamsPayload(immediate(300)))
	assert.Equal(t, "message", p["type"])
	att := p["attachments"].([]any)[0].(map[string]any)
	assert.Equal(t, "application/vnd.microsoft.card.adaptive", att["contentType"])
	assert.Nil(t, att["contentUrl"])
	c := att["content"].(map[string]any)
	assert.Equal(t, "AdaptiveCard", c["type"])
	assert.Equal(t, "1.4", c["version"])
	assert.Len(t, c["actions"], 1)
	b, err := json.Marshal(teamsPayload(immediate(300)))
	require.NoError(t, err)
	assert.LessOrEqual(t, len(b), 28*1024)
}

func TestTeams_DropsItemsToFit(t *testing.T) {
	m := digest(20)
	for i := range m.Items {
		m.Items[i].Reasons = []string{strings.Repeat("x", 3000)}
	}
	b, err := json.Marshal(teamsPayload(m))
	require.NoError(t, err)
	assert.LessOrEqual(t, len(b), 28*1024)
	assert.Contains(t, string(b), "more advisories")
}

func TestFormat_Lines(t *testing.T) {
	assert.Equal(t, "Deployment/x", ownerLine(model.OwnerRef{Kind: "Deployment", Name: "x"}))
	assert.Equal(t, "web 1 (no fix yet)", pkgLine(model.FindingPackage{Name: "web", Installed: "1"}))
	assert.Equal(t, "Suggested: r:1 → 2 (minor), fixes 2 high, 1 medium, introduces none",
		suggestionLine(&model.Suggestion{Repo: "r", FromTag: "1", ToTag: "2", Tier: model.TierMinor,
			Fixes: map[model.Priority]int{model.PriorityMedium: 1, model.PriorityHigh: 2}}))
	assert.Equal(t, "Published 2026-11-17 03:04 UTC, seen by ffs 2026-11-19 03:04 UTC", timesLine(item("X", 1)))
}

func TestGuard_CheckAddr(t *testing.T) {
	always := []string{"169.254.169.254", "fd00:ec2::254", "127.0.0.1", "::1", "fe80::1", "::ffff:169.254.169.254", "100.100.100.200", "0.0.0.0", "::", "224.0.0.1"}
	private := []string{"10.0.0.1", "172.16.0.1", "192.168.1.1", "fd12::1", "100.64.0.1"}
	public := []string{"8.8.8.8", "2606:4700::1"}
	for _, s := range always {
		a := netip.MustParseAddr(s)
		assert.Error(t, CheckAddr(a, false), s)
		assert.Error(t, CheckAddr(a, true), s)
	}
	for _, s := range private {
		a := netip.MustParseAddr(s)
		assert.Error(t, CheckAddr(a, false), s)
		assert.NoError(t, CheckAddr(a, true), s)
	}
	for _, s := range public {
		a := netip.MustParseAddr(s)
		assert.NoError(t, CheckAddr(a, false), s)
		assert.NoError(t, CheckAddr(a, true), s)
	}
}

func TestNew_URLRules(t *testing.T) {
	good := notify.SinkConfig{URL: "https://hooks.example.com/x", SigningSecret: testSecret}
	for _, typ := range []string{"slack", "discord", "teams", "webhook"} {
		s, err := New(typ, good)
		require.NoError(t, err, typ)
		assert.Equal(t, typ, s.Type())
	}
	_, err := New("slack", notify.SinkConfig{URL: "http://hooks.example.com/SECRET"})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "SECRET")
	_, err = New("slack", notify.SinkConfig{URL: "http://10.0.0.5/x", AllowPrivate: true})
	assert.NoError(t, err)
	for _, u := range []string{"", "hooks.example.com/x", "ftp://h/x", "https:///x"} {
		_, err = New("slack", notify.SinkConfig{URL: u})
		assert.Error(t, err, u)
	}
	_, err = New("webhook", notify.SinkConfig{URL: good.URL})
	assert.Error(t, err)
	_, err = New("webhook", notify.SinkConfig{URL: good.URL, SigningSecret: shortSecret})
	assert.Error(t, err)
	_, err = New("pagerduty", good)
	assert.Error(t, err)
}
