package agent

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"time"
)

// heartbeatEvery is how often the heartbeat is touched while a full report or a job runs; tests shorten it.
var heartbeatEvery = time.Minute

// touchHeartbeat creates or truncates the heartbeat file and sets its mtime to now. The liveness probe
// (`ffs agent check`) reads the mtime.
func touchHeartbeat(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644) //nolint:gosec // G302/G304: the agent's own heartbeat file
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	now := time.Now()
	return os.Chtimes(path, now, now)
}

// CheckHeartbeat returns an error when the heartbeat at path is missing or older than maxAge at now.
func CheckHeartbeat(path string, maxAge time.Duration, now time.Time) error {
	fi, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("no agent heartbeat at %s", path)
	}
	if err != nil {
		return err
	}
	if age := now.Sub(fi.ModTime()); age > maxAge {
		return fmt.Errorf("agent heartbeat is %s old (limit %s)", age.Round(time.Second), maxAge)
	}
	return nil
}

// keepAlive touches the heartbeat every heartbeatEvery until ctx ends or the returned stop is called, so a
// long full report or job does not look like a wedged agent. Bounding ctx keeps a truly wedged one stale.
func (a *agent) keepAlive(ctx context.Context) (stop func()) {
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		t := time.NewTicker(heartbeatEvery)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				a.touch()
			case <-done:
				return
			case <-ctx.Done():
				return
			}
		}
	})
	return func() {
		close(done)
		wg.Wait()
	}
}
