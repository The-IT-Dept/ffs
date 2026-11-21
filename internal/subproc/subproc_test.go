package subproc

import (
	"bufio"
	"context"
	"errors"
	"io/fs"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestStart_NiceRelativeToThisProcess: the group runs nice levels below this process, at most
// MaxNice; 0 leaves the priority alone. The test process may itself run niced (a shell's BG_NICE,
// say), so the child's value is compared with it.
func TestStart_NiceRelativeToThisProcess(t *testing.T) {
	own, err := niceOf(0)
	require.NoError(t, err)
	for _, n := range []int{0, 10, MaxNice + 5} {
		ctx, cancel := context.WithCancel(t.Context())
		cmd := exec.CommandContext(ctx, "sleep", "30")
		require.NoError(t, Start(cmd, n, time.Second))
		got, err := niceOf(cmd.Process.Pid)
		cancel()
		_ = cmd.Wait()
		require.NoError(t, err)
		require.Equal(t, min(own+n, MaxNice), got, "n %d, this process at nice %d", n, own)
	}
}

// TestStart_CancelKillsTheGroup: ending the context kills the child and the processes it started,
// which share its group.
func TestStart_CancelKillsTheGroup(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", "sleep 30 & echo $!; wait")
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, Start(cmd, 0, time.Second))
	line, err := bufio.NewReader(stdout).ReadString('\n')
	require.NoError(t, err)
	grandchild, err := strconv.Atoi(strings.TrimSpace(line))
	require.NoError(t, err)
	pgid, err := syscall.Getpgid(grandchild)
	require.NoError(t, err)
	require.Equal(t, cmd.Process.Pid, pgid, "the grandchild is in the child's group")

	cancel()
	require.Error(t, cmd.Wait())
	require.Eventually(t, func() bool {
		return errors.Is(syscall.Kill(grandchild, 0), syscall.ESRCH)
	}, 5*time.Second, 10*time.Millisecond, "the grandchild is killed")
}

// TestStart_StartErrorAsItIs: a process that cannot start is cmd.Start's error, not a
// PriorityError.
func TestStart_StartErrorAsItIs(t *testing.T) {
	cmd := exec.CommandContext(t.Context(), filepath.Join(t.TempDir(), "missing")) //nolint:gosec // G204: a path in the test's own temp directory
	err := Start(cmd, 10, time.Second)
	require.ErrorIs(t, err, fs.ErrNotExist)
	var pe *PriorityError
	require.NotErrorAs(t, err, &pe)
}

// TestPriorityError: the message names the step, and the cause unwraps.
func TestPriorityError(t *testing.T) {
	err := error(&PriorityError{Err: syscall.EACCES})
	require.EqualError(t, err, "setting the process group's priority: "+syscall.EACCES.Error())
	require.ErrorIs(t, err, syscall.EACCES)
}
