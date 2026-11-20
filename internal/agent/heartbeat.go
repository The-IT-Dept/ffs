package agent

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"time"
)

// heartbeatEvery is how often the heartbeat is touched while the run loop is healthy; tests shorten it.
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

// pulse is the run loop's lease on the heartbeat. Before each step (a sleep, a report, a job) the loop renews
// the lease for as long as that step may take; a ticker touches the heartbeat every heartbeatEvery while the
// lease holds. A loop wedged past its lease stops the touches, and the liveness probe restarts the collector.
type pulse struct {
	mu    sync.Mutex
	until time.Time
}

// lease marks the loop healthy for d more, plus two heartbeat periods.
func (a *agent) lease(d time.Duration) {
	a.pulse.mu.Lock()
	defer a.pulse.mu.Unlock()
	a.pulse.until = time.Now().Add(max(d, 0) + 2*heartbeatEvery)
}

// healthy reports whether the loop's lease holds at now.
func (a *agent) healthy(now time.Time) bool {
	a.pulse.mu.Lock()
	defer a.pulse.mu.Unlock()
	return now.Before(a.pulse.until)
}

// startPulse touches the heartbeat every heartbeatEvery while the loop's lease holds, until stop is called.
func (a *agent) startPulse() (stop func()) {
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		t := time.NewTicker(heartbeatEvery)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				if a.healthy(time.Now()) {
					a.touch()
				}
			case <-done:
				return
			}
		}
	})
	return func() {
		close(done)
		wg.Wait()
	}
}
