package settle

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestWait_AbsorbsABurst(t *testing.T) {
	changed := make(chan struct{}, 1)
	done := make(chan bool)
	start := time.Now()
	go func() { done <- Wait(context.Background(), changed, 100*time.Millisecond) }()
	for range 5 {
		changed <- struct{}{} // each send blocks until Wait absorbs the previous one
	}
	require.True(t, <-done)
	require.GreaterOrEqual(t, time.Since(start), 100*time.Millisecond)
	select {
	case <-changed:
		t.Fatal("a signal sent during the window was left for another sync")
	default:
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.False(t, Wait(ctx, changed, time.Hour))
}
