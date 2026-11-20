package sinks

import (
	"context"
	"encoding/json"
	"strings"
	"unicode/utf8"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/notify"
)

// Discord's documented limits.
const (
	discordContentMax = 2000
	discordEmbedsMax  = 10
	discordTitleMax   = 256
	discordDescMax    = 4096
	discordFieldsMax  = 25
	discordValueMax   = 1024
	discordTotalMax   = 6000
)

type discordField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline,omitempty"`
}

type discordEmbed struct {
	Title       string         `json:"title"`
	Description string         `json:"description,omitempty"`
	Color       int            `json:"color"`
	Fields      []discordField `json:"fields,omitempty"`
}

func (e discordEmbed) size() int {
	n := utf8.RuneCountInString(e.Title) + utf8.RuneCountInString(e.Description)
	for _, f := range e.Fields {
		n += utf8.RuneCountInString(f.Name) + utf8.RuneCountInString(f.Value)
	}
	return n
}

type discord struct {
	url    string
	poster *Poster
}

func (d *discord) Type() string { return "discord" }

// CloseIdleConnections closes the idle connections of the sink's Poster.
func (d *discord) CloseIdleConnections() { d.poster.CloseIdleConnections() }

func (d *discord) Send(ctx context.Context, m notify.Message) error {
	body, err := json.Marshal(discordPayload(m))
	if err != nil {
		return err
	}
	return d.poster.Post(ctx, d.url, "application/json; charset=utf-8", body, nil)
}

func discordColor(p model.Priority) int {
	switch p {
	case model.PriorityUrgent:
		return 0xC62828
	case model.PriorityHigh:
		return 0xEF6C00
	case model.PriorityMedium:
		return 0xF9A825
	}
	return 0x607D8B
}

// discordPayload builds the message. Text from feeds, images and advisories is escaped, and
// allowed_mentions is empty, so nothing in it can mention anyone, @everyone included.
func discordPayload(m notify.Message) map[string]any {
	items, hidden := capItems(m)
	if len(items) > discordEmbedsMax {
		hidden += len(items) - discordEmbedsMax
		items = items[:discordEmbedsMax]
	}
	embeds := make([]discordEmbed, 0, len(items))
	for _, it := range items {
		embeds = append(embeds, discordItemEmbed(it))
	}
	// All embeds of a message share one text budget; drop whole advisories from the end.
	total := func() (n int) {
		for _, e := range embeds {
			n += e.size()
		}
		return n
	}
	for len(embeds) > 1 && total() > discordTotalMax {
		embeds = embeds[:len(embeds)-1]
		hidden++
	}
	if len(embeds) == 1 && total() > discordTotalMax {
		e := &embeds[0]
		e.Fields = nil
		e.Description = truncate(e.Description, discordTotalMax-utf8.RuneCountInString(e.Title))
	}

	content := append([]string{escapeMarkdown(m.Title)}, extraLines(m, escapeMarkdown)...)
	if hidden > 0 {
		content = append(content, more(hidden, "advisory", "advisories"))
	}
	return map[string]any{"content": truncate(strings.Join(content, "\n"), discordContentMax), "embeds": embeds,
		"allowed_mentions": map[string]any{"parse": []string{}}}
}

func discordItemEmbed(it notify.Item) discordEmbed {
	e := discordEmbed{Title: truncate(heading(it, escapeMarkdown), discordTitleMax), Color: discordColor(it.Priority)}
	e.Description = truncate(strings.Join(itemLines(it, escapeMarkdown), "\n"), discordDescMax)
	if owners, extra := ownerLines(it, escapeMarkdown); len(owners) > 0 {
		for i, o := range owners {
			owners[i] = "• " + o
		}
		if extra > 0 {
			owners = append(owners, more(extra, "workload", "workloads"))
		}
		e.Fields = append(e.Fields, discordField{Name: "Workloads", Value: truncate(strings.Join(owners, "\n"), discordValueMax)})
	}
	if links := firstLinks([]notify.Item{it}); len(links) > 0 {
		e.Fields = append(e.Fields, discordField{Name: "Links", Value: truncate(strings.Join(links, "\n"), discordValueMax)})
	}
	if len(e.Fields) > discordFieldsMax {
		e.Fields = e.Fields[:discordFieldsMax]
	}
	return e
}
