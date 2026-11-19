package feeds

import (
	"strings"

	"github.com/the-it-dept/ffs/internal/store"
)

// metaPending is the FeedState.Meta key holding work a feed has taken in but not yet handed off.
const metaPending = "pending"

// Pending returns the IDs stored under Meta["pending"], or nil.
func Pending(st store.FeedState) []string {
	v := st.Meta[metaPending]
	if v == "" {
		return nil
	}
	return strings.Split(v, "\n")
}

// SetPending stores ids under Meta["pending"], newline-joined. A nil or empty ids clears the key.
func SetPending(st *store.FeedState, ids []string) {
	if len(ids) == 0 {
		delete(st.Meta, metaPending)
		return
	}
	if st.Meta == nil {
		st.Meta = make(map[string]string, 1)
	}
	st.Meta[metaPending] = strings.Join(ids, "\n")
}
