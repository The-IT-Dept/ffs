package subproc

import "syscall"

// niceOf is the nice value of process pid, 0 for this process. On Linux the getpriority system call
// returns 20 - nice, so that it is never negative; the C library converts it back, and the syscall
// package does not.
func niceOf(pid int) (int, error) {
	p, err := syscall.Getpriority(syscall.PRIO_PROCESS, pid)
	return 20 - p, err
}
