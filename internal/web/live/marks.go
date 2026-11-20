package live

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

// StoreNodeMarks marks the node grouping and the node-agent state of st: the first 16 hex
// characters of a sha256 over each group's ID and members, by ID; whether the agent is enabled and
// the runtime owner retired; and each node's agent state as of the poll (a reporting agent turns
// stale once staleAfter passes without a report, which no write marks), its coverage gap codes and
// a hash of its last error. Report times are not read, so a heartbeat that changes none of these
// keeps the mark. A nil now is time.Now.
func StoreNodeMarks(st *store.Store, staleAfter time.Duration, now func() time.Time) NodeMarks {
	if now == nil {
		now = time.Now
	}
	return func(ctx context.Context) (string, error) {
		groups, err := st.NodeGroups(ctx)
		if err != nil {
			return "", err
		}
		state, err := st.NodesState(ctx)
		if err != nil {
			return "", err
		}
		agents, err := st.AgentStatus(ctx, now(), staleAfter)
		if err != nil {
			return "", err
		}
		slices.SortFunc(groups, func(a, b model.NodeGroup) int { return strings.Compare(a.ID, b.ID) })
		h := sha256.New()
		for _, g := range groups {
			_, _ = fmt.Fprintf(h, "%s\x1f%s\n", g.ID, strings.Join(g.Members, ","))
		}
		_, _ = fmt.Fprintf(h, "%t %t\n", state.AgentEnabled, state.RuntimeRetired)
		slices.SortFunc(agents, func(a, b model.NodeAgentStatus) int { return strings.Compare(a.Node, b.Node) })
		for _, a := range agents {
			codes := make([]string, 0, len(a.Coverage))
			for _, g := range a.Coverage {
				codes = append(codes, g.Code)
			}
			slices.Sort(codes)
			errSum := sha256.Sum256([]byte(a.LastError))
			_, _ = fmt.Fprintf(h, "%s\x1f%s\x1f%s\x1f%x\n", a.Node, a.State, strings.Join(slices.Compact(codes), ","), errSum[:8])
		}
		return hex.EncodeToString(h.Sum(nil))[:16], nil
	}
}
