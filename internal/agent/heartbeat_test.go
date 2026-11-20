package agent

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCheckHeartbeat(t *testing.T) {
	p := filepath.Join(t.TempDir(), "heartbeat")
	now := time.Now()
	require.EqualError(t, CheckHeartbeat(p, 15*time.Minute, now), "no agent heartbeat at "+p)

	require.NoError(t, touchHeartbeat(p))
	require.NoError(t, CheckHeartbeat(p, 15*time.Minute, time.Now()))

	old := now.Add(-20 * time.Minute)
	require.NoError(t, os.Chtimes(p, old, old))
	require.EqualError(t, CheckHeartbeat(p, 15*time.Minute, now), "agent heartbeat is 20m0s old (limit 15m0s)")

	require.NoError(t, touchHeartbeat(p))
	require.NoError(t, CheckHeartbeat(p, 15*time.Minute, time.Now()), "a touch makes it fresh again")
}
