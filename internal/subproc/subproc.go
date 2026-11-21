// Package subproc starts helper processes in a process group of their own, so that ending their
// context kills the whole group, and at a lower priority than this process.
package subproc

import (
	"os/exec"
	"syscall"
	"time"
)

// MaxNice is the lowest priority there is.
const MaxNice = 19

// PriorityError is a failure to set the priority of a started process group. Start has killed the
// group and waited for it by the time it returns one.
type PriorityError struct {
	Err error
}

func (e *PriorityError) Error() string {
	return "setting the process group's priority: " + e.Err.Error()
}

func (e *PriorityError) Unwrap() error { return e.Err }

// Start starts cmd, which must come from exec.CommandContext, in a process group of its own. When
// cmd's context ends, the whole group is killed, and cmd.Wait returns at most waitDelay later.
//
// With nice above 0, the group runs nice levels below this process, at most MaxNice, as nice(1)
// does: a process that already runs niced never asks for a higher priority, which needs privileges.
// It sets the group, not the process: nice is per thread on Linux, and the Go runtime of the process
// has started threads before Start can set it. PRIO_PGRP sets every thread of the group, and threads
// created later inherit it. When that fails, the group is killed and waited for, and the error is a
// *PriorityError.
//
// An error from cmd.Start is returned as it is.
func Start(cmd *exec.Cmd, nice int, waitDelay time.Duration) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = waitDelay
	if err := cmd.Start(); err != nil {
		return err
	}
	if nice > 0 {
		if err := niceGroup(cmd.Process.Pid, nice); err != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			_ = cmd.Wait()
			return &PriorityError{Err: err}
		}
	}
	return nil
}

// niceGroup sets process group pgid n nice levels below this process, at most MaxNice.
func niceGroup(pgid, n int) error {
	own, err := niceOf(0)
	if err != nil {
		return err
	}
	return syscall.Setpriority(syscall.PRIO_PGRP, pgid, min(own+n, MaxNice))
}
