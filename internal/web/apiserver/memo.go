package apiserver

import (
	"context"
	"net/http"
	"sync"

	"github.com/the-it-dept/ffs/internal/model"
)

// memo holds what one request reads more than once: the node groups and the agent statuses. Each is
// read the first time it is needed and kept for the rest of the request.
type memo struct {
	groupsMu sync.Mutex
	groups   *groupSet

	agentsMu sync.Mutex
	agents   *agentView
}

type memoKey struct{}

// withMemo gives every request its own memo.
func withMemo(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), memoKey{}, &memo{})))
	})
}

// memoOf is the request's memo; nil outside a request, where nothing is kept.
func memoOf(ctx context.Context) *memo {
	m, _ := ctx.Value(memoKey{}).(*memo)
	return m
}

// agentView is every stored node's agent status, and whether the node agent is enabled.
type agentView struct {
	byNode  map[string]model.NodeAgentStatus
	enabled bool
}

// of is a node's agent status; a node the store has none for is missing (missingAgent).
func (v *agentView) of(node string) model.NodeAgentStatus {
	if a, ok := v.byNode[node]; ok {
		return a
	}
	return missingAgent(node, v.enabled)
}

// agentView reads (once per request) every node's agent status and the node agent state.
func (s *Server) agentView(ctx context.Context) (*agentView, error) {
	m := memoOf(ctx)
	if m != nil {
		m.agentsMu.Lock()
		defer m.agentsMu.Unlock()
		if m.agents != nil {
			return m.agents, nil
		}
	}
	state, err := s.o.Store.NodesState(ctx)
	if err != nil {
		return nil, err
	}
	list, err := s.o.Store.AgentStatus(ctx, s.o.Now(), s.o.Config.NodeAgent.StaleAfter)
	if err != nil {
		return nil, err
	}
	v := &agentView{byNode: make(map[string]model.NodeAgentStatus, len(list)), enabled: state.AgentEnabled}
	for _, st := range list {
		v.byNode[st.Node] = st
	}
	if m != nil {
		m.agents = v
	}
	return v, nil
}

// groupSet reads (once per request) the node groups the API shows.
func (s *Server) groupSet(ctx context.Context) (*groupSet, error) {
	m := memoOf(ctx)
	if m != nil {
		m.groupsMu.Lock()
		defer m.groupsMu.Unlock()
		if m.groups != nil {
			return m.groups, nil
		}
	}
	groups, err := s.readNodeGroups(ctx)
	if err != nil {
		return nil, err
	}
	gs := newGroupSet(groups)
	if m != nil {
		m.groups = gs
	}
	return gs, nil
}
