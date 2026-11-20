package sinks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/the-it-dept/ffs/internal/notify"
)

const (
	slackHeaderMax  = 150
	slackSectionMax = 3000
)

// slackLimiters holds one limiter per webhook URL, keyed by its hash so URLs are not kept as keys.
var (
	slackMu       sync.Mutex
	slackLimiters = map[string]*rate.Limiter{}
)

// limiterFor returns the limiter shared by every sink posting to url: Slack allows about one
// message per second per webhook.
func limiterFor(url string) *rate.Limiter {
	sum := sha256.Sum256([]byte(url))
	k := hex.EncodeToString(sum[:])
	slackMu.Lock()
	defer slackMu.Unlock()
	l, ok := slackLimiters[k]
	if !ok {
		l = rate.NewLimiter(rate.Every(time.Second), 1)
		slackLimiters[k] = l
	}
	return l
}

type slack struct {
	url    string
	poster *Poster
}

func (s *slack) Type() string { return "slack" }

// CloseIdleConnections closes the idle connections of the sink's Poster.
func (s *slack) CloseIdleConnections() { s.poster.CloseIdleConnections() }

func (s *slack) Send(ctx context.Context, m notify.Message) error {
	body, err := json.Marshal(slackPayload(m))
	if err != nil {
		return err
	}
	if err := limiterFor(s.url).Wait(ctx); err != nil {
		return err
	}
	return s.poster.Post(ctx, s.url, "application/json; charset=utf-8", body, nil)
}

var slackEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

func slackEsc(s string) string { return slackEscaper.Replace(s) }

// slackFit cuts s to n runes without leaving half an entity at the end.
func slackFit(s string, n int) string {
	if len([]rune(s)) <= n {
		return s
	}
	s = truncate(s, n)
	if i := strings.LastIndex(s, "&"); i >= 0 && len(s)-i <= 6 && !strings.Contains(s[i:], ";") {
		s = s[:i] + "…"
	}
	return s
}

func slackContext(text string) map[string]any {
	return map[string]any{"type": "context", "elements": []any{map[string]any{"type": "mrkdwn", "text": slackFit(text, slackSectionMax)}}}
}

func slackPayload(m notify.Message) map[string]any {
	items, hidden := capItems(m)
	blocks := []any{map[string]any{"type": "header", "text": map[string]any{"type": "plain_text", "text": truncate(m.Title, slackHeaderMax)}}}
	text := []string{m.Title}

	if extra := extraLines(m, plain); len(extra) > 0 {
		blocks = append(blocks, slackContext(slackEsc(strings.Join(extra, "\n"))))
		text = append(text, extra...)
	}
	for _, it := range items {
		lines := []string{"*" + slackEsc(heading(it, plain)) + "*"}
		for _, l := range itemLines(it, plain) {
			lines = append(lines, slackEsc(l))
		}
		owners, extraOwners := ownerLines(it, plain)
		for _, o := range owners {
			lines = append(lines, "• "+slackEsc(o))
		}
		if links := firstLinks([]notify.Item{it}); len(links) > 0 {
			for i, l := range links {
				links[i] = "<" + slackEsc(l) + ">"
			}
			lines = append(lines, strings.Join(links, " "))
		}
		blocks = append(blocks, map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": slackFit(strings.Join(lines, "\n"), slackSectionMax)}})
		if extraOwners > 0 {
			blocks = append(blocks, slackContext(more(extraOwners, "workload", "workloads")))
		}
		text = append(text, fmt.Sprintf("- %s: %s priority, %s", heading(it, plain), it.Priority, workloads(len(it.Owners)+it.TruncatedOwners)))
	}
	if hidden > 0 {
		blocks = append(blocks, slackContext(more(hidden, "advisory", "advisories")))
		text = append(text, more(hidden, "advisory", "advisories"))
	}
	return map[string]any{"text": slackEsc(strings.Join(text, "\n")), "blocks": blocks}
}
