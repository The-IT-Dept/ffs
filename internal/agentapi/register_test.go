package agentapi

import (
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/the-it-dept/ffs/internal/config"
	"github.com/the-it-dept/ffs/internal/controller/deps"
	"github.com/the-it-dept/ffs/internal/engine"
)

// fakeTarget records what register adds to the manager.
type fakeTarget struct {
	runnables []manager.Runnable
	indexer   *recordingIndexer
	cl        client.Client
}

func (f *fakeTarget) Add(r manager.Runnable) error {
	f.runnables = append(f.runnables, r)
	return nil
}
func (f *fakeTarget) GetClient() client.Client             { return f.cl }
func (f *fakeTarget) GetFieldIndexer() client.FieldIndexer { return f.indexer }

func TestRegister_ServerOnlyWhenEnabled(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		st := newStore(t)
		cfg := config.Default()
		cfg.NodeAgent.Enabled = enabled
		d := deps.Deps{Config: cfg, Store: st, Engine: engine.New(engine.Options{Config: cfg, Store: st}), Log: logr.Discard()}
		m := &fakeTarget{indexer: &recordingIndexer{}, cl: fake.NewClientBuilder().Build()}
		var handlers []toolscache.ResourceEventHandler
		onNodes := func(h toolscache.ResourceEventHandler) error {
			handlers = append(handlers, h)
			return nil
		}
		require.NoError(t, register(m, onNodes, d))

		if enabled {
			require.Len(t, m.runnables, 2)
			require.IsType(t, &Reconciler{}, m.runnables[0])
			require.IsType(t, &Server{}, m.runnables[1])
		} else {
			require.Len(t, m.runnables, 1, "no agent API while the node agent is disabled")
			require.IsType(t, &Reconciler{}, m.runnables[0])
		}
		for _, r := range m.runnables {
			le, ok := r.(manager.LeaderElectionRunnable)
			require.True(t, ok)
			require.True(t, le.NeedLeaderElection(), "%T is leader-only", r)
		}
		require.Len(t, m.indexer.calls, 1)
		require.Equal(t, "spec.nodeName", m.indexer.calls[0].field)
		require.Len(t, handlers, 1)
	}
}
