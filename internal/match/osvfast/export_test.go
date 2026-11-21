package osvfast

import (
	"context"
	"testing"

	"github.com/the-it-dept/ffs/internal/store"
)

// SetRecordChunk sets how many records MatchImage reads at a time, for the test.
func SetRecordChunk(t testing.TB, n int) {
	old := recordChunk
	recordChunk = n
	t.Cleanup(func() { recordChunk = old })
}

// RecordChunk is how many records MatchImage reads at a time, and the bytes one read may hold.
func RecordChunk() (records, bytes int) { return recordChunk, recordChunkBytes }

// WatchRecordLoads records the number of ids in every read of cached records, for the test.
func WatchRecordLoads(t testing.TB) *[]int {
	var sizes []int
	old := loadRecords
	loadRecords = func(st *store.Store, ctx context.Context, ids []string) ([][]byte, error) {
		sizes = append(sizes, len(ids))
		return old(st, ctx, ids)
	}
	t.Cleanup(func() { loadRecords = old })
	return &sizes
}
