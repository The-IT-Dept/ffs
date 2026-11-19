package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestOSVRecordNames_Lookup(t *testing.T) {
	s := newStore(t)
	require.NoError(t, s.PutOSVRecordNames(ctx, "Debian", "DEBIAN-CVE-1", []string{"openssl"}))
	ids, err := s.OSVRecordIDsByName(ctx, "Debian", []string{"openssl"})
	require.NoError(t, err)
	require.Equal(t, []string{"DEBIAN-CVE-1"}, ids)

	// other buckets and names do not match; empty names are ignored
	require.NoError(t, s.PutOSVRecordNames(ctx, "Ubuntu", "UBUNTU-CVE-1", []string{"openssl", ""}))
	ids, _ = s.OSVRecordIDsByName(ctx, "Debian", []string{"openssl", "curl"})
	require.Equal(t, []string{"DEBIAN-CVE-1"}, ids)
	ids, _ = s.OSVRecordIDsByName(ctx, "Debian", nil)
	require.Empty(t, ids)

	// replace
	require.NoError(t, s.PutOSVRecordNames(ctx, "Debian", "DEBIAN-CVE-1", []string{"openssl3"}))
	ids, _ = s.OSVRecordIDsByName(ctx, "Debian", []string{"openssl"})
	require.Empty(t, ids)
	ids, _ = s.OSVRecordIDsByName(ctx, "Debian", []string{"openssl3"})
	require.Equal(t, []string{"DEBIAN-CVE-1"}, ids)
}

func TestOSVRecordNames_RecordsByIDAndDelete(t *testing.T) {
	s := newStore(t)
	_, err := s.PutOSVRecord(ctx, "PyPI", "GHSA-1", t0, "h", []byte(`{"id":"GHSA-1","v":"pypi"}`))
	require.NoError(t, err)
	_, _ = s.PutOSVRecord(ctx, "npm", "GHSA-1", t0.Add(time.Hour), "h", []byte(`{"id":"GHSA-1","v":"npm"}`))
	_, _ = s.PutOSVRecord(ctx, "PyPI", "GHSA-2", t0, "h", []byte(`{"id":"GHSA-2"}`))
	require.NoError(t, s.PutOSVRecordNames(ctx, "PyPI", "GHSA-1", []string{"a"}))

	raws, err := s.OSVRecordsByID(ctx, []string{"GHSA-2", "GHSA-1", "GHSA-9"})
	require.NoError(t, err)
	require.Equal(t, [][]byte{[]byte(`{"id":"GHSA-1","v":"npm"}`), []byte(`{"id":"GHSA-2"}`)}, raws) // newest copy, once

	ids, _ := s.OSVRecordIDs(ctx, "PyPI")
	require.Equal(t, []string{"GHSA-1", "GHSA-2"}, ids)

	require.NoError(t, s.DeleteOSVRecords(ctx, "PyPI", []string{"GHSA-1"}))
	ids, _ = s.OSVRecordIDs(ctx, "PyPI")
	require.Equal(t, []string{"GHSA-2"}, ids)
	ids, _ = s.OSVRecordIDsByName(ctx, "PyPI", []string{"a"})
	require.Empty(t, ids)
	raws, _ = s.OSVRecordsByID(ctx, []string{"GHSA-1"})
	require.Equal(t, [][]byte{[]byte(`{"id":"GHSA-1","v":"npm"}`)}, raws)
}
