package events

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

func TestBuildNoteCountsOwnerPrefix(t *testing.T) {
	var items []item
	for i := 0; i < 100; i++ {
		items = append(items, item{id: strings.Repeat("a", 3) + string(rune('A'+i%26)) + string(rune('a'+i/26)), priority: model.PriorityHigh, text: strings.Repeat("x", 40)})
	}
	_, note := buildNote(ReasonDetected, "Container runtime containerd: ", items)
	if len(note) > MaxNoteBytes {
		t.Fatalf("note %d bytes > %d", len(note), MaxNoteBytes)
	}
	if !strings.HasPrefix(note, "Container runtime containerd: ") {
		t.Fatalf("prefix missing: %q", note[:40])
	}
}

// TestBuildNote_NeverOverCapAndListsFirstItem (F54): no note passes MaxNoteBytes whatever the sizes,
// and the first item is always listed, cut short when it alone is too long.
func TestBuildNote_NeverOverCapAndListsFirstItem(t *testing.T) {
	for _, n := range []int{1, 2, 9, 10, 11, 99, 100, 101, 1000} {
		for _, size := range []int{1, 20, 97, 500, 1023, 1024, 2000} {
			var items []item
			for i := range n {
				id := fmt.Sprintf("CVE-2026-%05d", i)
				items = append(items, item{id: id, priority: model.PriorityHigh, text: id + strings.Repeat("x", size)})
			}
			_, note := buildNote(ReasonDetected, "Container runtime containerd: ", items)
			require.LessOrEqual(t, len(note), MaxNoteBytes, "n %d size %d", n, size)
			require.True(t, utf8.ValidString(note))
			body := strings.TrimPrefix(note, fmt.Sprintf("Container runtime containerd: %d new: ", n))
			require.True(t, strings.HasPrefix(body, "CVE-2026-00000"), "n %d size %d: %q", n, size, note[:min(len(note), 80)])
		}
	}
	_, note := buildNote(ReasonDetected, "", []item{{id: "CVE-1", priority: model.PriorityHigh, text: "CVE-1 (" + strings.Repeat("é", 1000) + ")"},
		{id: "CVE-2", priority: model.PriorityHigh, text: "CVE-2"}})
	require.LessOrEqual(t, len(note), MaxNoteBytes)
	require.True(t, utf8.ValidString(note), "a cut never splits a character")
	require.True(t, strings.HasSuffix(note, "... and 1 more"), note[len(note)-20:])
}
