package store

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCursor_RoundTripAndShape(t *testing.T) {
	cols := []keyCol{{"priority", true, kindInt}, {"advisory_id", false, kindString}, {"fingerprint", false, kindString}}
	c := encodeCursor("-priority", []any{int64(4), "CVE-2026-0001", "ab"})
	vals, err := decodeCursor(c, "-priority", cols)
	require.NoError(t, err)
	require.Equal(t, []any{int64(4), "CVE-2026-0001", "ab"}, vals)
	require.NotContains(t, c, "=") // unpadded base64url

	// a kindFloat column round-trips exactly
	fcols := []keyCol{{"epss", true, kindFloat}, {"fingerprint", false, kindString}}
	vals, err = decodeCursor(encodeCursor("-epss", []any{0.123456789012, "ab"}), "-epss", fcols)
	require.NoError(t, err)
	require.Equal(t, []any{0.123456789012, "ab"}, vals)

	raw := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	for name, bad := range map[string]string{
		"another tag":            encodeCursor("workload", []any{int64(4), "CVE-2026-0001", "ab"}),
		"2 elements":             encodeCursor("-priority", []any{int64(4), "CVE-2026-0001"}),
		"4 elements":             encodeCursor("-priority", []any{int64(4), "CVE-2026-0001", "ab", "cd"}),
		`"4" where kindInt`:      encodeCursor("-priority", []any{"4", "CVE-2026-0001", "ab"}),
		"1.5 where kindInt":      encodeCursor("-priority", []any{1.5, "CVE-2026-0001", "ab"}),
		"a number for a string":  encodeCursor("-priority", []any{int64(4), int64(1), "ab"}),
		"not base64":             "!!",
		"an object":              raw(`{"a":1}`),
		"an empty array":         raw(`[]`),
		"trailing data":          raw(`["-priority",4,"a","b"]x`),
		"a tag that is a number": raw(`[1,4,"a","b"]`),
	} {
		_, err := decodeCursor(bad, "-priority", cols)
		require.ErrorIs(t, err, ErrBadCursor, name)
	}

	v, err := decodeCursor("", "-priority", cols)
	require.NoError(t, err)
	require.Nil(t, v)
}

func TestKeysetAfter_MixedDirections(t *testing.T) {
	cols := []keyCol{{"priority", true, kindInt}, {"advisory_id", false, kindString}, {"fingerprint", false, kindString}}
	q, args := keysetAfter(cols, []any{int64(3), "CVE-1", "fp"})
	require.Equal(t, "(priority < ? OR (priority = ? AND (advisory_id > ? OR (advisory_id = ? AND fingerprint > ?))))", q)
	require.Equal(t, []any{int64(3), int64(3), "CVE-1", "CVE-1", "fp"}, args)

	q, args = keysetAfter([]keyCol{{"id", true, kindInt}}, []any{int64(7)})
	require.Equal(t, "id < ?", q)
	require.Equal(t, []any{int64(7)}, args)
	require.Equal(t, " ORDER BY priority DESC, advisory_id, fingerprint", orderBy(cols))

	for in, want := range map[int]int{0: 50, -5: 1, 1: 1, 200: 200, 201: 200} {
		require.Equal(t, want, clampLimit(in), in)
	}
}
