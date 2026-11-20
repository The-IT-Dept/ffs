package store

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFeedState(t *testing.T) {
	s := newStore(t)
	st, err := s.FeedState(ctx, "osv")
	require.NoError(t, err)
	require.Equal(t, FeedState{Name: "osv"}, st)

	in := FeedState{Name: "osv", Watermark: "2026-11-19T00:55:00Z", LastSuccess: t0, LastAttempt: t0,
		Meta: map[string]string{"PyPI": "2026-11-19T00:55:00Z"}}
	require.NoError(t, s.PutFeedState(ctx, in))
	got, err := s.FeedState(ctx, "osv")
	require.NoError(t, err)
	require.Equal(t, in.Meta, got.Meta)
	require.Equal(t, in.Watermark, got.Watermark)
	require.True(t, got.LastSuccess.Equal(t0))
	require.True(t, got.LastAttempt.Equal(t0))
}

func TestUpstreamRanges(t *testing.T) {
	s := newStore(t)
	a, b, c := []byte(`{"r":"a"}`), []byte(`{"r":"b"}`), []byte(`{"r":"c"}`)
	require.NoError(t, s.PutUpstreamRanges(ctx, "CVE-2026-0001", "php", a))
	require.NoError(t, s.PutUpstreamRanges(ctx, "CVE-2026-0002", "php", b))
	require.NoError(t, s.PutUpstreamRanges(ctx, "CVE-2026-0001", "php", c))

	got, err := s.UpstreamRanges(ctx, "php")
	require.NoError(t, err)
	require.Len(t, got, 2)
	require.Equal(t, c, got["CVE-2026-0001"])
}

func TestOSVRecords(t *testing.T) {
	s := newStore(t)
	changed, err := s.PutOSVRecord(ctx, "PyPI", "GHSA-1", t0, "h1", []byte(`{"id":"GHSA-1"}`))
	require.NoError(t, err)
	require.True(t, changed)
	changed, _ = s.PutOSVRecord(ctx, "PyPI", "GHSA-1", t0.Add(time.Hour), "h1", []byte(`{"id":"GHSA-1","summary":"y"}`))
	require.False(t, changed) // timestamp-only churn
	changed, _ = s.PutOSVRecord(ctx, "PyPI", "GHSA-1", t0.Add(2*time.Hour), "h2", []byte(`{"id":"GHSA-1"}`))
	require.True(t, changed)
	_, _ = s.PutOSVRecord(ctx, "PyPI", "GHSA-2", t0.Add(-time.Hour), "h", []byte(`{"id":"GHSA-2"}`))
	recent, _ := s.OSVRecords(ctx, "PyPI", t0)
	require.Equal(t, [][]byte{[]byte(`{"id":"GHSA-1"}`)}, recent)
	all, _ := s.OSVRecords(ctx, "PyPI", time.Time{})
	require.Len(t, all, 2)
	require.NoError(t, s.DeleteOSVRecords(ctx, "PyPI", []string{"GHSA-2"}))
	all, _ = s.OSVRecords(ctx, "PyPI", time.Time{})
	require.Len(t, all, 1)
}

// TestPutOSVRecordAt_Observed (F2): a record's observation time is when ffs first stored its current
// affected content; a timestamp-only re-delivery keeps it and an affected change resets it.
func TestPutOSVRecordAt_Observed(t *testing.T) {
	s := newStore(t)
	_, err := s.PutOSVRecordAt(ctx, "PyPI", "GHSA-1", t0, "h1", []byte(`{"id":"GHSA-1"}`), t0)
	require.NoError(t, err)
	_, err = s.PutOSVRecordAt(ctx, "Go", "GHSA-1", t0, "h1", []byte(`{"id":"GHSA-1"}`), t0.Add(30*time.Minute))
	require.NoError(t, err)
	_, err = s.PutOSVRecordAt(ctx, "PyPI", "GHSA-1", t0.Add(time.Hour), "h1", []byte(`{"id":"GHSA-1"}`), t0.Add(time.Hour))
	require.NoError(t, err)
	obs, err := s.OSVRecordsObserved(ctx, []string{"GHSA-1", "GHSA-9"})
	require.NoError(t, err)
	require.Equal(t, map[string]time.Time{"GHSA-1": t0}, obs, "unchanged content keeps its time; the earliest bucket wins")

	_, err = s.PutOSVRecordAt(ctx, "PyPI", "GHSA-1", t0.Add(2*time.Hour), "h2", []byte(`{"id":"GHSA-1"}`), t0.Add(2*time.Hour))
	require.NoError(t, err)
	require.NoError(t, s.DeleteOSVRecords(ctx, "Go", []string{"GHSA-1"}))
	obs, err = s.OSVRecordsObserved(ctx, []string{"GHSA-1"})
	require.NoError(t, err)
	require.Equal(t, map[string]time.Time{"GHSA-1": t0.Add(2 * time.Hour)}, obs, "changed content is observed anew")
}

// TestRehashOSVRecords: the affected hash of every cached record, across pages, is recomputed;
// the raw, modified and observation times stay, an unreadable record keeps its hash and an
// unchanged hash is not counted.
func TestRehashOSVRecords(t *testing.T) {
	s := newStore(t)
	for i := range rehashPage + 10 {
		id := fmt.Sprintf("GHSA-%03d", i)
		_, err := s.PutOSVRecordAt(ctx, "PyPI", id, t0, "old", []byte(`{"id":"`+id+`"}`), t0)
		require.NoError(t, err)
	}
	_, err := s.PutOSVRecordAt(ctx, "Go", "GO-1", t0, "new:GO-1", []byte(`{"id":"GO-1"}`), t0)
	require.NoError(t, err)
	_, err = s.PutOSVRecordAt(ctx, "Go", "GO-2", t0, "old", []byte(`unreadable`), t0)
	require.NoError(t, err)
	hash := func(raw []byte) (string, error) {
		var r struct{ ID string }
		if err := json.Unmarshal(raw, &r); err != nil {
			return "", err
		}
		return "new:" + r.ID, nil
	}

	n, err := s.RehashOSVRecords(ctx, hash)
	require.NoError(t, err)
	require.Equal(t, rehashPage+10, n, "GO-1 already had its hash; GO-2 does not parse")
	for _, c := range []struct{ eco, id, hash string }{{"PyPI", "GHSA-000", "new:GHSA-000"}, {"PyPI", "GHSA-073", "new:GHSA-073"},
		{"Go", "GO-1", "new:GO-1"}, {"Go", "GO-2", "old"}} {
		var got string
		require.NoError(t, s.rdb.QueryRowContext(ctx, `SELECT affected_hash FROM osv_records WHERE ecosystem = ? AND id = ?`, c.eco, c.id).Scan(&got))
		require.Equal(t, c.hash, got, c.id)
	}
	obs, err := s.OSVRecordsObserved(ctx, []string{"GHSA-000"})
	require.NoError(t, err)
	require.Equal(t, map[string]time.Time{"GHSA-000": t0}, obs)
	raws, err := s.OSVRecords(ctx, "PyPI", t0)
	require.NoError(t, err)
	require.Len(t, raws, rehashPage+10)

	n, err = s.RehashOSVRecords(ctx, hash)
	require.NoError(t, err)
	require.Zero(t, n)
}

func TestOSVListed(t *testing.T) {
	s := newStore(t)
	got, err := s.OSVListed(ctx, "PyPI")
	require.NoError(t, err)
	require.Empty(t, got)

	at := time.Date(2026, 11, 20, 19, 0, 20, 462181115, time.UTC)
	require.NoError(t, s.ReplaceOSVListed(ctx, "PyPI", map[string]time.Time{"A": at, "B": at.Add(-time.Minute)}))
	require.NoError(t, s.ReplaceOSVListed(ctx, "Go", map[string]time.Time{"A": at}))
	require.NoError(t, s.ReplaceOSVListed(ctx, "PyPI", map[string]time.Time{"A": at, "C": at.Add(time.Minute)}))
	got, err = s.OSVListed(ctx, "PyPI")
	require.NoError(t, err)
	require.Equal(t, map[string]time.Time{"A": at, "C": at.Add(time.Minute)}, got, "replaced, to the nanosecond")
	got, err = s.OSVListed(ctx, "Go")
	require.NoError(t, err)
	require.Equal(t, map[string]time.Time{"A": at}, got)
	require.NoError(t, s.ReplaceOSVListed(ctx, "Go", nil))
	got, err = s.OSVListed(ctx, "Go")
	require.NoError(t, err)
	require.Empty(t, got)
}
