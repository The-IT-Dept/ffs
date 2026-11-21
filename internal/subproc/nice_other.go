//go:build !linux

package subproc

import "syscall"

// niceOf is the nice value of process pid, 0 for this process, which getpriority returns as it is
// outside Linux, as a C int.
func niceOf(pid int) (int, error) {
	p, err := syscall.Getpriority(syscall.PRIO_PROCESS, pid)
	return int(int32(p)), err //nolint:gosec // G115: getpriority returns a C int, -20 to 20
}
