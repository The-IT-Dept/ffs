package events

import (
	"strings"
	"testing"

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
