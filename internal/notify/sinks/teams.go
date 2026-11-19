package sinks

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/the-it-dept/ffs/internal/notify"
)

// teamsMaxBytes is Teams' message size limit (28 KB).
const teamsMaxBytes = 28 * 1024

type teams struct {
	url    string
	poster *Poster
}

func (t *teams) Type() string { return "teams" }

func (t *teams) Send(ctx context.Context, m notify.Message) error {
	body, err := json.Marshal(teamsPayload(m))
	if err != nil {
		return err
	}
	return t.poster.Post(ctx, t.url, "application/json; charset=utf-8", body, nil)
}

func textBlock(text string, extra map[string]any) map[string]any {
	b := map[string]any{"type": "TextBlock", "text": text, "wrap": true}
	for k, v := range extra {
		b[k] = v
	}
	return b
}

// teamsPayload builds an Adaptive Card message, dropping trailing advisories until it fits.
func teamsPayload(m notify.Message) map[string]any {
	items, _ := capItems(m.Items)
	for n := len(items); ; n-- {
		p := teamsCard(m, items[:n], len(m.Items)-n)
		b, err := json.Marshal(p)
		if err != nil || len(b) <= teamsMaxBytes || n == 0 {
			return p
		}
	}
}

func teamsCard(m notify.Message, items []notify.Item, hidden int) map[string]any {
	body := []any{textBlock(m.Title, map[string]any{"weight": "Bolder", "size": "Medium"})}
	if extra := extraLines(m); len(extra) > 0 {
		body = append(body, textBlock(strings.Join(extra, "\n\n"), nil))
	}
	for _, it := range items {
		body = append(body, textBlock(heading(it), map[string]any{"weight": "Bolder", "separator": true}))
		body = append(body, textBlock(strings.Join(itemLines(it), "\n\n"), nil))
		if owners, extra := ownerLines(it); len(owners) > 0 {
			for i, o := range owners {
				owners[i] = "- " + o
			}
			if extra > 0 {
				owners = append(owners, more(extra, "workload", "workloads"))
			}
			body = append(body, textBlock(strings.Join(owners, "\n"), nil))
		}
	}
	if hidden > 0 {
		body = append(body, textBlock(more(hidden, "advisory", "advisories"), map[string]any{"isSubtle": true}))
	}
	actions := []any{}
	for _, l := range firstLinks(items, m.DashboardURL) {
		title := "Open"
		if u, err := url.Parse(l); err == nil && u.Hostname() != "" {
			title = u.Hostname()
		}
		actions = append(actions, map[string]any{"type": "Action.OpenUrl", "title": title, "url": l})
	}
	return map[string]any{"type": "message", "attachments": []any{map[string]any{
		"contentType": "application/vnd.microsoft.card.adaptive",
		"contentUrl":  nil,
		"content": map[string]any{
			"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
			"type":    "AdaptiveCard", "version": "1.4",
			"body": body, "actions": actions,
		},
	}}}
}
