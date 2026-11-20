package osv

import "testing"

// SetMaxZipBytes lowers the all.zip download cap for the test.
func SetMaxZipBytes(t testing.TB, n int64) {
	old := maxZipBytes
	maxZipBytes = n
	t.Cleanup(func() { maxZipBytes = old })
}
