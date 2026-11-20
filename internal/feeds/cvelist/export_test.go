package cvelist

import "testing"

// SetMaxZipBytes lowers the delta zip download cap for the test.
func SetMaxZipBytes(t testing.TB, n int64) {
	old := maxZipBytes
	maxZipBytes = n
	t.Cleanup(func() { maxZipBytes = old })
}
