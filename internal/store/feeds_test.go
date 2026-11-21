package store

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
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
	require.True(t, got.FirstAttempt.IsZero())
	require.Zero(t, got.Fails)

	in.FirstAttempt, in.Fails, in.LastError = t0.Add(-time.Hour), 3, "boom"
	require.NoError(t, s.PutFeedState(ctx, in))
	got, err = s.FeedState(ctx, "osv")
	require.NoError(t, err)
	require.True(t, got.FirstAttempt.Equal(t0.Add(-time.Hour)), "FirstAttempt %v", got.FirstAttempt)
	require.Equal(t, 3, got.Fails)
	require.Equal(t, "boom", got.LastError)
}

// TestFeedState_StaleFrom (W53): staleness is measured from the last success, else from the earliest
// attempt known (FirstAttempt, or a v0.0.1 state's LastAttempt) when that is before the caller's
// start, else from the start.
func TestFeedState_StaleFrom(t *testing.T) {
	started := t0
	for _, c := range []struct {
		name          string
		st            FeedState
		earliest, ref time.Time
	}{
		{"never attempted", FeedState{}, time.Time{}, started},
		{"succeeded", FeedState{LastSuccess: t0.Add(-time.Hour), LastAttempt: t0.Add(-time.Hour), FirstAttempt: t0.Add(-48 * time.Hour)},
			t0.Add(-48 * time.Hour), t0.Add(-time.Hour)},
		{"succeeded under v0.0.1", FeedState{LastSuccess: t0.Add(-time.Hour), LastAttempt: t0.Add(-time.Minute)},
			time.Time{}, t0.Add(-time.Hour)},
		{"first attempt before the start", FeedState{FirstAttempt: t0.Add(-3 * time.Hour), LastAttempt: t0.Add(-time.Hour)},
			t0.Add(-3 * time.Hour), t0.Add(-3 * time.Hour)},
		{"first attempt after the start", FeedState{FirstAttempt: t0.Add(time.Minute)}, t0.Add(time.Minute), started},
		{"failed under v0.0.1", FeedState{LastAttempt: t0.Add(-2 * time.Hour), LastError: "boom"},
			t0.Add(-2 * time.Hour), t0.Add(-2 * time.Hour)},
	} {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.earliest, c.st.EarliestAttempt())
			require.Equal(t, c.ref, c.st.StaleFrom(started))
		})
	}
}

// TestAdvisoryIDsListed (W53): an id is listed by itself, by its canonical id or by any alias of
// that canonical.
func TestAdvisoryIDsListed(t *testing.T) {
	s := newStore(t)
	require.NoError(t, s.UpsertAdvisory(ctx, model.Advisory{ID: "GHSA-aaaa", Aliases: []string{"CVE-2026-1000", "CVE-2026-2000"}}))
	require.NoError(t, s.UpsertAdvisory(ctx, model.Advisory{ID: "CVE-2026-3000"}))
	require.NoError(t, s.UpsertAdvisory(ctx, model.Advisory{ID: "CVE-2026-4000"}))
	ids := []string{"CVE-2026-1000", "CVE-2026-3000", "CVE-2026-4000", "GHSA-aaaa", "CVE-2026-9999"}

	for _, c := range []struct {
		listed []string
		want   []string
	}{
		{[]string{"CVE-2026-2000"}, []string{"CVE-2026-1000", "GHSA-aaaa"}}, // an alias of the canonical CVE-2026-1000
		{[]string{"CVE-2026-3000", "CVE-2026-9999"}, []string{"CVE-2026-3000", "CVE-2026-9999"}},
		{[]string{"CVE-2026-0001"}, nil},
		{nil, nil},
	} {
		got, err := s.AdvisoryIDsListed(ctx, ids, c.listed)
		require.NoError(t, err)
		require.Equal(t, c.want, got, "%v", c.listed)
	}
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

// TestPutOSVRecordAt_RatingOnlyChangeKeepsObserved (W3): with "<match>:<rating>" hashes, a change to
// the rating part alone is a change (the record is handed off) that keeps the observation time; a
// change to the match part moves it. A hash without a ':' (v1) compares as its match part.
func TestPutOSVRecordAt_RatingOnlyChangeKeepsObserved(t *testing.T) {
	s := newStore(t)
	put := func(hash string, at time.Time) bool {
		t.Helper()
		changed, err := s.PutOSVRecordAt(ctx, "Ubuntu", "UBUNTU-CVE-1", at, hash, []byte(`{"id":"UBUNTU-CVE-1"}`), at)
		require.NoError(t, err)
		return changed
	}
	observed := func() time.Time {
		t.Helper()
		obs, err := s.OSVRecordsObserved(ctx, []string{"UBUNTU-CVE-1"})
		require.NoError(t, err)
		return obs["UBUNTU-CVE-1"]
	}
	require.True(t, put("m1", t0))
	require.True(t, put("m1:medium", t0.Add(time.Hour)), "the v1 hash differs from the full v3 one")
	require.Equal(t, t0, observed(), "a v1 hash is the match part")
	require.True(t, put("m1:high", t0.Add(2*time.Hour)), "a rating-only change is handed off")
	require.Equal(t, t0, observed(), "a rating-only change keeps the observation time")
	require.False(t, put("m1:high", t0.Add(3*time.Hour)))
	require.True(t, put("m2:high", t0.Add(4*time.Hour)))
	require.Equal(t, t0.Add(4*time.Hour), observed(), "a match change is observed anew")
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
	last := fmt.Sprintf("GHSA-%03d", rehashPage+9)
	for _, c := range []struct{ eco, id, hash string }{{"PyPI", "GHSA-000", "new:GHSA-000"}, {"PyPI", last, "new:" + last},
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

func TestOSVRecordsModified(t *testing.T) {
	s := newStore(t)
	at := time.Date(2026, 11, 20, 19, 0, 20, 462181115, time.UTC)
	for id, m := range map[string]time.Time{"A": at, "B": at.Add(-time.Hour), "C": at.Add(-time.Hour - time.Nanosecond)} {
		_, err := s.PutOSVRecord(ctx, "PyPI", id, m, "h", []byte(`{}`))
		require.NoError(t, err)
	}
	_, err := s.PutOSVRecord(ctx, "Go", "D", at, "h", []byte(`{}`))
	require.NoError(t, err)
	got, err := s.OSVRecordsModified(ctx, "PyPI", at.Add(-time.Hour))
	require.NoError(t, err)
	require.Equal(t, map[string]time.Time{"A": at, "B": at.Add(-time.Hour)}, got, "at or after since, in that bucket, to the nanosecond")
	got, err = s.OSVRecordsModified(ctx, "Debian", at.Add(-48*time.Hour))
	require.NoError(t, err)
	require.Empty(t, got)
}
