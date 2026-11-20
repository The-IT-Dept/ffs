package controller

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/store"
)

// FC-4: the controller lifts the previous version's crash quarantines at start and says so in one
// Info line with the counts, errors included; a fresh store only records the version, and a restart
// of the same version neither clears nor logs anything.
func TestResetCrashQuarantines_OncePerVersion(t *testing.T) {
	ctx := t.Context()
	st, err := store.Open(ctx, t.TempDir()+"/ffs.db")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	var (
		mu    sync.Mutex
		lines []string
	)
	log := funcr.New(func(prefix, args string) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, args)
	}, funcr.Options{})
	logged := func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), lines...)
	}

	require.NoError(t, resetCrashQuarantines(ctx, st, "v0.0.1-rc.6", log))
	require.Len(t, logged(), 1, "a store with no version stored starts the record")
	require.Contains(t, logged()[0], `"msg"="recorded controller version"`)
	require.Contains(t, logged()[0], `"version"="v0.0.1-rc.6"`)
	require.NotContains(t, logged()[0], "changed", "a fresh install has no previous version")
	now := time.Now()
	for range 2 {
		_, err := st.RecordAgentJobFailure(ctx, "nodehost:worker-1", "worker-1", "the controller stopped while processing the host inventory",
			now, 2, 24*time.Hour)
		require.NoError(t, err)
	}
	require.NoError(t, st.UpsertImage(ctx, model.Image{Digest: "sha256:a", Repo: "ghcr.io/example/a", Status: model.ImageCatalogFailed,
		StatusReason: "the controller stopped while processing the image", QuarantinedUntil: now.Add(24 * time.Hour)}))

	require.NoError(t, resetCrashQuarantines(ctx, st, "v0.0.1-rc.6", log))
	require.Len(t, logged(), 1, "the same version again: nothing cleared, nothing logged")
	_, quarantined, err := st.AgentJobOf(ctx, "nodehost:worker-1")
	require.NoError(t, err)
	require.True(t, quarantined)

	require.NoError(t, resetCrashQuarantines(ctx, st, "v0.0.1-rc.7", log))
	all := logged()
	require.Len(t, all, 2)
	require.Contains(t, all[1], `"previous"="v0.0.1-rc.6"`)
	require.Contains(t, all[1], `"cleared"=2`)
	require.Contains(t, all[1], `"errors"=0`)
	require.True(t, strings.Contains(all[1], "controller version changed"), all[1])
	_, quarantined, err = st.AgentJobOf(ctx, "nodehost:worker-1")
	require.NoError(t, err)
	require.False(t, quarantined, "the host inventory is tried again at once")
	img, _, err := st.GetImage(ctx, "sha256:a")
	require.NoError(t, err)
	require.Equal(t, model.ImagePending, img.Status)
}
