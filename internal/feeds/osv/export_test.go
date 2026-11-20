package osv

import (
	"context"
	"sync"
	"testing"

	"github.com/the-it-dept/ffs/internal/store"
)

// SetMaxZipBytes lowers the all.zip download cap for the test.
func SetMaxZipBytes(t testing.TB, n int64) {
	old := maxZipBytes
	maxZipBytes = n
	t.Cleanup(func() { maxZipBytes = old })
}

// WatchRecordLoads records the number of ids in every read of cached records, for the test. Read
// the sizes once the reads are done.
func WatchRecordLoads(t testing.TB) *[]int {
	var (
		mu    sync.Mutex
		sizes []int
	)
	old := loadRecords
	loadRecords = func(st *store.Store, ctx context.Context, ids []string) ([][]byte, error) {
		mu.Lock()
		sizes = append(sizes, len(ids))
		mu.Unlock()
		return old(st, ctx, ids)
	}
	t.Cleanup(func() { loadRecords = old })
	return &sizes
}
