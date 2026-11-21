package catalog

import "syscall"

// ownNice is this process's nice value. On Linux the getpriority system call returns 20 - nice, so
// that it is never negative; the C library converts it back, and the syscall package does not.
func ownNice() (int, error) {
	p, err := syscall.Getpriority(syscall.PRIO_PROCESS, 0)
	return 20 - p, err
}
