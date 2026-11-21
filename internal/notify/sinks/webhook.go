package sinks

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/notify"
)

const eventPrefix = "au.theitdept.ffs."

// Sign returns the Standard Webhooks v1 signature "v1,<base64>" of body for message msgID at ts.
// secret is "whsec_<base64>" or bare base64 and must decode to 24 to 64 bytes.
func Sign(secret, msgID string, ts time.Time, body []byte) (string, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	if err != nil {
		return "", fmt.Errorf("signing secret is not base64")
	}
	if len(key) < 24 || len(key) > 64 {
		return "", fmt.Errorf("signing secret must decode to 24 to 64 bytes, got %d", len(key))
	}
	mac := hmac.New(sha256.New, key)
	_, _ = fmt.Fprintf(mac, "%s.%d.", msgID, ts.Unix())
	_, _ = mac.Write(body)
	return "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

// EventType is the CloudEvents type of m.
func EventType(m notify.Message) string {
	switch m.Kind {
	case notify.KindDigest, notify.KindBaseline:
		return eventPrefix + "digest.v1"
	case notify.KindFeedStale:
		return eventPrefix + "feed.stale.v1"
	}
	if len(m.Items) > 0 {
		switch m.Items[0].Event {
		case notify.EventEscalated:
			return eventPrefix + "finding.escalated.v1"
		case notify.EventResolved:
			return eventPrefix + "finding.resolved.v1"
		}
	}
	return eventPrefix + "finding.detected.v1"
}

type webhook struct {
	url, secret, cluster string
	poster               *Poster
}

func (w *webhook) Type() string { return "webhook" }

// CloseIdleConnections closes the idle connections of the sink's Poster.
func (w *webhook) CloseIdleConnections() { w.poster.CloseIdleConnections() }

type cloudEvent struct {
	SpecVersion     string    `json:"specversion"`
	ID              string    `json:"id"`
	Source          string    `json:"source"`
	Type            string    `json:"type"`
	Time            time.Time `json:"time"`
	DataContentType string    `json:"datacontenttype"`
	Subject         string    `json:"subject,omitempty"`
	Data            wireData  `json:"data"`
}

type wireData struct {
	Kind         notify.Kind  `json:"kind"`
	Cluster      string       `json:"cluster"`
	Target       string       `json:"target"`
	Title        string       `json:"title"`
	Items        []wireItem   `json:"items"`
	Summary      *wireSummary `json:"summary,omitempty"`
	Feeds        []wireFeed   `json:"feeds,omitempty"`
	DashboardURL string       `json:"dashboardUrl,omitempty"`
	// Truncated counts the items left out of Items: a message lists at most notify.MaxItems, and
	// its payload is kept within notify.MaxPayloadBytes.
	Truncated int `json:"truncated"`
}

type wireItem struct {
	Event       notify.Event    `json:"event"`
	AdvisoryID  string          `json:"advisoryId,omitempty"`
	Title       string          `json:"title,omitempty"`
	Advisories  []string        `json:"advisories,omitempty"`
	Priority    model.Priority  `json:"priority"`
	Reasons     []string        `json:"reasons"`
	Owners      []wireOwner     `json:"owners"`
	NodeGroups  []string        `json:"nodeGroups,omitempty"`
	Packages    []wirePackage   `json:"packages"`
	FixedIn     []string        `json:"fixedIn"`
	Suggestion  *wireSuggestion `json:"suggestion,omitempty"`
	Published   time.Time       `json:"published,omitzero"`
	Observed    time.Time       `json:"observed,omitzero"`
	Links       []string        `json:"links"`
	Provisional bool            `json:"provisional"`
	// TruncatedOwners and TruncatedPackages count the owners and packages left out to keep the
	// payload within notify.MaxPayloadBytes; omitted when none were.
	TruncatedOwners   int `json:"truncatedOwners,omitempty"`
	TruncatedPackages int `json:"truncatedPackages,omitempty"`
}

type wireOwner struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

type wirePackage struct {
	Name      string   `json:"name"`
	Ecosystem string   `json:"ecosystem,omitempty"`
	Installed string   `json:"installed"`
	Fixed     []string `json:"fixed"`
	Path      string   `json:"path,omitempty"`
}

type wireSuggestion struct {
	Repo       string                 `json:"repo"`
	FromTag    string                 `json:"fromTag"`
	ToTag      string                 `json:"toTag"`
	Tier       model.Tier             `json:"tier"`
	Fixes      map[model.Priority]int `json:"fixes"`
	Introduces map[model.Priority]int `json:"introduces"`
}

type wireSummary struct {
	// Findings is absent from a summary queued by v0.0.1, which did not count findings.
	Findings  *int       `json:"findings,omitempty"`
	Workloads int        `json:"workloads"`
	Counts    wireCounts `json:"counts"`
}

type wireCounts struct {
	Urgent int `json:"urgent"`
	High   int `json:"high"`
	Medium int `json:"medium"`
	Low    int `json:"low"`
}

type wireFeed struct {
	Name              string    `json:"name"`
	LastSuccess       time.Time `json:"lastSuccess,omitzero"`
	StaleAfterSeconds int64     `json:"staleAfterSeconds"`
	Stale             bool      `json:"stale"`
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func counts(m map[model.Priority]int) map[model.Priority]int {
	if m == nil {
		return map[model.Priority]int{}
	}
	return m
}

func wireOf(m notify.Message) wireData {
	d := wireData{Kind: m.Kind, Cluster: m.Cluster, Target: m.TargetName, Title: m.Title,
		DashboardURL: m.DashboardURL, Items: make([]wireItem, 0, len(m.Items)), Truncated: m.Truncated}
	for _, it := range m.Items {
		wi := wireItem{Event: it.Event, AdvisoryID: it.AdvisoryID, Title: it.Title, Advisories: it.Grouped,
			Priority: it.Priority, Reasons: nonNil(it.Reasons), FixedIn: nonNil(it.FixedIn), Links: nonNil(it.Links),
			Owners: []wireOwner{}, NodeGroups: it.NodeGroups, Packages: []wirePackage{}, Published: it.Published,
			Observed: it.Observed, Provisional: it.Provisional, TruncatedOwners: it.TruncatedOwners,
			TruncatedPackages: it.TruncatedPackages}
		for _, o := range it.Owners {
			wi.Owners = append(wi.Owners, wireOwner{Kind: o.Kind, Namespace: o.Namespace, Name: o.Name})
		}
		for _, p := range it.Packages {
			wi.Packages = append(wi.Packages, wirePackage{Name: p.Name, Ecosystem: p.Ecosystem, Installed: p.Installed, Fixed: nonNil(p.Fixed), Path: p.Path})
		}
		if s := it.Suggestion; s != nil {
			wi.Suggestion = &wireSuggestion{Repo: s.Repo, FromTag: s.FromTag, ToTag: s.ToTag, Tier: s.Tier, Fixes: counts(s.Fixes), Introduces: counts(s.Introduces)}
		}
		d.Items = append(d.Items, wi)
	}
	if s := m.Summary; s != nil {
		d.Summary = &wireSummary{Workloads: s.Workloads, Counts: wireCounts{
			Urgent: s.Counts[model.PriorityUrgent], High: s.Counts[model.PriorityHigh],
			Medium: s.Counts[model.PriorityMedium], Low: s.Counts[model.PriorityLow]}}
		if !s.Legacy() {
			d.Summary.Findings = &s.Findings
		}
	}
	for _, f := range m.Feeds {
		d.Feeds = append(d.Feeds, wireFeed{Name: f.Name, LastSuccess: f.LastSuccess, StaleAfterSeconds: int64(f.StaleAfter / time.Second), Stale: f.Stale})
	}
	return d
}

func (w *webhook) Send(ctx context.Context, m notify.Message) error {
	cluster := m.Cluster
	if cluster == "" {
		cluster = w.cluster
	}
	ev := cloudEvent{SpecVersion: "1.0", ID: m.ID, Source: "/ffs/" + cluster, Type: EventType(m),
		Time: m.At.UTC(), DataContentType: "application/json", Data: wireOf(m)}
	if m.Kind == notify.KindImmediate && len(m.Items) > 0 {
		ev.Subject = m.Items[0].AdvisoryID
	}
	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	now := time.Now()
	sig, err := Sign(w.secret, m.ID, now, body)
	if err != nil {
		return &notify.DeliveryError{Permanent: true, Msg: err.Error()}
	}
	hdr := http.Header{}
	hdr.Set("webhook-id", m.ID)
	hdr.Set("webhook-timestamp", strconv.FormatInt(now.Unix(), 10))
	hdr.Set("webhook-signature", sig)
	return w.poster.Post(ctx, w.url, "application/cloudevents+json; charset=utf-8", body, hdr)
}
