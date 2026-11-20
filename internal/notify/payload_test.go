package notify_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/notify"
)

// bigItem is an advisory item with n owners and n packages.
func bigItem(id string, p model.Priority, n int) notify.Item {
	it := notify.Item{Event: notify.EventDetected, AdvisoryID: id, Title: "Title of " + id, Priority: p}
	for i := range n {
		it.Owners = append(it.Owners, dep("namespace-of-some-length", fmt.Sprintf("workload-with-a-long-name-%05d", i)))
		it.Packages = append(it.Packages, model.FindingPackage{Name: fmt.Sprintf("package-%05d", i), Ecosystem: "deb",
			Installed: "1.2.3-4", Fixed: []string{"1.2.3-5"}, Path: "/usr/lib/x86_64-linux-gnu"})
	}
	return it
}

func decode(t *testing.T, m notify.Message) (notify.Message, int) {
	t.Helper()
	b, err := notify.EncodePayload(m)
	require.NoError(t, err)
	var out notify.Message
	require.NoError(t, json.Unmarshal(b, &out))
	return out, len(b)
}

// TestPayload_CapsItemsAndBytes pins F92: a message lists at most 200 items and its stored payload
// is at most 256 KiB, cutting owner and package lists before whole items, and every cut is counted.
func TestPayload_CapsItemsAndBytes(t *testing.T) {
	m := notify.Message{ID: "ffs_x", Kind: notify.KindDigest, Title: "digest", At: time.Unix(0, 0).UTC()}
	for i := range 250 {
		m.Items = append(m.Items, bigItem(fmt.Sprintf("CVE-2026-%04d", i), medium, 1))
	}
	got, size := decode(t, m)
	assert.Len(t, got.Items, notify.MaxItems)
	assert.Equal(t, 50, got.Truncated)
	assert.Equal(t, "CVE-2026-0199", got.Items[199].AdvisoryID, "the first items are kept")
	assert.LessOrEqual(t, size, notify.MaxPayloadBytes)
	assert.Len(t, m.Items, 250, "the message itself is not changed")

	one := notify.Message{ID: "ffs_y", Kind: notify.KindImmediate, Items: []notify.Item{bigItem("CVE-2026-0001", urgent, 20000)}}
	got, size = decode(t, one)
	assert.LessOrEqual(t, size, notify.MaxPayloadBytes)
	require.Len(t, got.Items, 1)
	assert.Zero(t, got.Truncated)
	it := got.Items[0]
	assert.Len(t, it.Owners, 100)
	assert.Equal(t, 19900, it.TruncatedOwners)
	assert.Len(t, it.Packages, 100)
	assert.Equal(t, 19900, it.TruncatedPackages)
	assert.Len(t, one.Items[0].Owners, 20000, "the message itself is not changed")

	wide := notify.Message{ID: "ffs_z", Kind: notify.KindDigest}
	for i := range 200 {
		w := bigItem(fmt.Sprintf("CVE-2026-%04d", i), high, 300)
		w.Title = strings.Repeat("t", 2000)
		wide.Items = append(wide.Items, w)
	}
	got, size = decode(t, wide)
	assert.LessOrEqual(t, size, notify.MaxPayloadBytes)
	assert.Positive(t, got.Truncated, "items are left out once the lists are at their shortest")
	assert.Equal(t, 200, len(got.Items)+got.Truncated)
	for _, it := range got.Items {
		assert.Len(t, it.Owners, 5)
		assert.Equal(t, 295, it.TruncatedOwners)
	}

	feeds := notify.Message{ID: "ffs_f", Kind: notify.KindFeedStale,
		Feeds: []notify.FeedStatus{{Name: "osv", Stale: true, LastError: strings.Repeat("e", 300<<10)}}}
	got, size = decode(t, feeds)
	assert.LessOrEqual(t, size, notify.MaxPayloadBytes)
	assert.Empty(t, got.Feeds[0].LastError)

	small := notify.Message{ID: "ffs_s", Kind: notify.KindImmediate, Items: []notify.Item{bigItem("CVE-2026-0001", urgent, 3)}}
	b, err := notify.EncodePayload(small)
	require.NoError(t, err)
	want, err := json.Marshal(small)
	require.NoError(t, err)
	assert.Equal(t, want, b, "a message within the caps is stored as it is")
}

// TestPayload_DigestOverTwoHundredAdvisories pins F92 through the engine: a digest of 210
// advisories stores and sends 200 items and counts the other 10, while its title and summary count
// them all.
func TestPayload_DigestOverTwoHundredAdvisories(t *testing.T) {
	h := newHarness(t)
	h.target("ops")
	h.process() // baseline
	var fs []model.Finding
	for i := range 210 {
		fs = append(fs, finding(dep("shop", fmt.Sprintf("w%03d", i)), fmt.Sprintf("CVE-2026-%04d", i), medium))
	}
	h.batch(fs...)
	h.at("2026-11-19T09:00Z")
	h.process()
	d := h.sink.lastOfKind(notify.KindDigest)
	assert.Len(t, d.Items, notify.MaxItems)
	assert.Equal(t, 10, d.Truncated)
	assert.Equal(t, "ffs digest for test: 210 new, 0 escalated, 0 fixes available, 0 resolved", d.Title)
	require.NotNil(t, d.Summary)
	assert.Equal(t, 210, d.Summary.Findings)
	assert.Equal(t, 210, d.Summary.Workloads)
	for _, dl := range h.deliveries() {
		assert.LessOrEqual(t, len(dl.Payload), notify.MaxPayloadBytes)
	}
}
