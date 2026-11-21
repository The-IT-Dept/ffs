package notify

import (
	"encoding/json"
	"slices"
)

const (
	// MaxItems is the most items one message lists; the rest are counted in Message.Truncated.
	MaxItems = 200
	// MaxPayloadBytes caps a stored delivery payload, the encoded Message, and with it the size of
	// what is sent, so a receiver's request size limit is not what drops a digest.
	MaxPayloadBytes = 256 << 10
)

// listCaps are the lengths the owner and package lists of every item are cut to, in turn, while a
// message is over MaxPayloadBytes.
var listCaps = []int{100, 25, 5}

// encodePayload encodes m as a stored delivery payload of at most MaxPayloadBytes. It lists at
// most MaxItems items. While the message is too large, it cuts every item's owners and packages to
// 100, then 25, then 5, then clears the feeds' last errors, and then leaves out items from the end,
// the lowest priority, counting what it leaves out. The counts in the title and summary are those
// of the whole message.
func encodePayload(m Message) ([]byte, error) {
	if n := len(m.Items); n > MaxItems {
		m.Items, m.Truncated = m.Items[:MaxItems], m.Truncated+n-MaxItems
	}
	b, err := json.Marshal(m)
	if err != nil || len(b) <= MaxPayloadBytes {
		return b, err
	}
	m.Items = slices.Clone(m.Items)
	for _, n := range listCaps {
		for i := range m.Items {
			capLists(&m.Items[i], n)
		}
		if b, err = json.Marshal(m); err != nil || len(b) <= MaxPayloadBytes {
			return b, err
		}
	}
	// The feeds' last errors go before any item does.
	if slices.ContainsFunc(m.Feeds, func(f FeedStatus) bool { return f.LastError != "" }) {
		m.Feeds = slices.Clone(m.Feeds)
		for i := range m.Feeds {
			m.Feeds[i].LastError = ""
		}
		if b, err = json.Marshal(m); err != nil || len(b) <= MaxPayloadBytes {
			return b, err
		}
	}
	// The longest run of leading items that fits; the whole run is known not to.
	items, truncated := m.Items, m.Truncated
	fits := func(k int) ([]byte, bool, error) {
		m.Items, m.Truncated = items[:k], truncated+len(items)-k
		b, err := json.Marshal(m)
		return b, len(b) <= MaxPayloadBytes, err
	}
	lo, hi := 0, len(items)-1
	for lo < hi {
		mid := (lo + hi + 1) / 2
		_, ok, err := fits(mid)
		switch {
		case err != nil:
			return nil, err
		case ok:
			lo = mid
		default:
			hi = mid - 1
		}
	}
	b, _, err = fits(lo) // at lo = 0 it may still be over: nothing else is left to cut
	return b, err
}

// capLists cuts the owners and packages of it to at most n each, counting what it leaves out.
func capLists(it *Item, n int) {
	if extra := len(it.Owners) - n; extra > 0 {
		it.Owners, it.TruncatedOwners = it.Owners[:n], it.TruncatedOwners+extra
	}
	if extra := len(it.Packages) - n; extra > 0 {
		it.Packages, it.TruncatedPackages = it.Packages[:n], it.TruncatedPackages+extra
	}
}
