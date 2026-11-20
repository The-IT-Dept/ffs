package live

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

// StoreNodeMarks marks the node grouping and the node-agent state of st: the first 16 hex
// characters of a sha256 over each group's ID and members, by ID, and whether the agent is enabled
// and the runtime owner retired. Agent heartbeats are not read, so a report that changes nothing
// keeps the mark.
func StoreNodeMarks(st *store.Store) NodeMarks {
	return func(ctx context.Context) (string, error) {
		groups, err := st.NodeGroups(ctx)
		if err != nil {
			return "", err
		}
		state, err := st.NodesState(ctx)
		if err != nil {
			return "", err
		}
		slices.SortFunc(groups, func(a, b model.NodeGroup) int { return strings.Compare(a.ID, b.ID) })
		h := sha256.New()
		for _, g := range groups {
			_, _ = fmt.Fprintf(h, "%s\x1f%s\n", g.ID, strings.Join(g.Members, ","))
		}
		_, _ = fmt.Fprintf(h, "%t %t", state.AgentEnabled, state.RuntimeRetired)
		return hex.EncodeToString(h.Sum(nil))[:16], nil
	}
}
