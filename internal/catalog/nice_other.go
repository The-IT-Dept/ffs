//go:build !linux

package catalog

import "syscall"

// ownNice is this process's nice value, which getpriority returns as it is outside Linux, as a C int.
func ownNice() (int, error) {
	p, err := syscall.Getpriority(syscall.PRIO_PROCESS, 0)
	return int(int32(p)), err //nolint:gosec // G115: getpriority returns a C int, -20 to 20
}
