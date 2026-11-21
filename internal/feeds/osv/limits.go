package osv

// MaxRecordBytes is the largest record, uncompressed, the feed fetches and caches; it skips larger
// ones, so no cached record is larger. Readers of the cache size their reads by it.
const MaxRecordBytes = maxRecordBytes
