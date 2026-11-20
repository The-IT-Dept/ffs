package sinks

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/notify"
)

func TestEscapeMarkdown(t *testing.T) {
	for in, want := range map[string]string{
		"**bold** @everyone":            `\*\*bold\*\* \@everyone`,
		"[click](https://evil.example)": `\[click\](https://evil.example)`,
		"<@123> ||spoiler|| `code` ~x~": "\\<\\@123\\> \\|\\|spoiler\\|\\| \\`code\\` \\~x\\~",
		"a_b\\c":                        `a\_b\\c`,
		"# heading":                     `\# heading`,
		"- item":                        `\- item`,
		"+ item":                        `\+ item`,
		"12. item":                      `12\. item`,
		"3) item":                       `3\) item`,
		"> quote":                       `\> quote`,
		"line\n  - item\n# h":           "line\n  \\- item\n\\# h",
		"openssl 3.0.1-1ubuntu1":        "openssl 3.0.1-1ubuntu1",
		"3.0.1":                         "3.0.1",
		"CVE-2026-0001":                 "CVE-2026-0001",
	} {
		assert.Equal(t, want, escapeMarkdown(in), in)
	}
}

// injected is a feed-stale alert and a digest whose feed, image and advisory text carries an
// @everyone mention and bold markdown.
func injected() []notify.Message {
	it := item("CVE-2026-0001", 2)
	it.Title = "**bold** @everyone"
	it.Reasons = []string{"@everyone **bold** reason"}
	it.Packages = []model.FindingPackage{{Name: "**pkg**", Installed: "@everyone", Fixed: []string{"**2**"}}}
	it.Suggestion.Repo = "registry.example/@everyone/**bold**"
	it.NodeGroups = []string{"**group**"}
	d := digest(0)
	d.Items = []notify.Item{it}
	stale := notify.Message{ID: "ffs_f", Kind: notify.KindFeedStale, Cluster: "prod", Title: "Feed osv has never synced successfully",
		Feeds: []notify.FeedStatus{{Name: "osv", Stale: true, LastError: "@everyone **bold** upstream error"}}}
	return []notify.Message{d, stale}
}

var (
	bareMention = regexp.MustCompile(`(^|[^\\])@everyone`)
	bareBold    = regexp.MustCompile(`(^|[^\\])\*\*`)
)

// assertEscaped checks that no text in v carries a bare @everyone or ** and that the injected text
// is there, escaped.
func assertEscaped(t *testing.T, texts []string) {
	t.Helper()
	all := strings.Join(texts, "\n")
	assert.Contains(t, all, `\*\*bold\*\* \@everyone`)
	for _, s := range texts {
		assert.NotRegexp(t, bareMention, s)
		assert.NotRegexp(t, bareBold, s)
	}
}

// TestDiscord_NoMentionsAndEscapedMarkdown pins F91 for Discord: every payload has an empty
// allowed_mentions, and markdown and mentions in feed, image and advisory text are escaped.
func TestDiscord_NoMentionsAndEscapedMarkdown(t *testing.T) {
	for _, m := range injected() {
		p := marshalMap(t, discordPayload(m))
		assert.Equal(t, map[string]any{"parse": []any{}}, p["allowed_mentions"])
		texts := []string{p["content"].(string)}
		embeds, _ := p["embeds"].([]any)
		for _, e := range embeds {
			em := e.(map[string]any)
			texts = append(texts, em["title"].(string), em["description"].(string))
			fields, _ := em["fields"].([]any)
			for _, f := range fields {
				texts = append(texts, f.(map[string]any)["value"].(string))
			}
		}
		if m.Kind == notify.KindFeedStale {
			assert.Contains(t, texts[0], `last error: \@everyone \*\*bold\*\* upstream error`)
			continue
		}
		assertEscaped(t, texts)
		desc := strings.Join(texts, "\n")
		assert.Contains(t, desc, `\*\*pkg\*\* \@everyone → \*\*2\*\*`)
		assert.Contains(t, desc, `registry.example/\@everyone/\*\*bold\*\*`)
		assert.Contains(t, desc, `Node groups: \*\*group\*\*`)
	}
}

// TestTeams_EscapesMarkdown pins F91 for Teams: TextBlocks carry feed, image and advisory text
// with its markdown escaped.
func TestTeams_EscapesMarkdown(t *testing.T) {
	for _, m := range injected() {
		b, err := json.Marshal(teamsPayload(m))
		require.NoError(t, err)
		var card struct {
			Attachments []struct {
				Content struct {
					Body []struct{ Text string }
				}
			}
		}
		require.NoError(t, json.Unmarshal(b, &card))
		var texts []string
		for _, blk := range card.Attachments[0].Content.Body {
			texts = append(texts, blk.Text)
		}
		if m.Kind == notify.KindFeedStale {
			assert.Contains(t, strings.Join(texts, "\n"), `last error: \@everyone \*\*bold\*\* upstream error`)
			continue
		}
		assertEscaped(t, texts)
	}
}

// TestSinks_LinksAreWebURLs pins the link half of F91: only absolute http(s) URLs become links,
// so text in an advisory's references cannot become markdown or an invalid card action.
func TestSinks_LinksAreWebURLs(t *testing.T) {
	it := item("CVE-2026-0001", 1)
	it.Links = []string{"[click](https://evil.example)", "javascript:alert(1)", "https://ok.example/a b", "https://ok.example/advisory"}
	assert.Equal(t, []string{"https://ok.example/advisory"}, firstLinks([]notify.Item{it}))
}
