package catalog

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestLimitedBuffer_GrowsToTheLimitAtMost (W24): the worker output buffer doubles as it fills, but never
// reserves more than its limit, and a write past the limit fails and is not kept.
func TestLimitedBuffer_GrowsToTheLimitAtMost(t *testing.T) {
	const limit = 10_000
	b := &limitedBuffer{limit: limit}
	chunk := bytes.Repeat([]byte("x"), 700)
	var want []byte
	var caps []int
	for len(want)+len(chunk) <= limit {
		n, err := b.Write(chunk)
		require.NoError(t, err)
		require.Equal(t, len(chunk), n)
		want = append(want, chunk...)
		if len(caps) == 0 || caps[len(caps)-1] != cap(b.buf) {
			caps = append(caps, cap(b.buf))
		}
	}
	require.Equal(t, want, b.buf)
	require.Equal(t, []int{700, 1400, 2800, 5600, limit}, caps, "doubling, then the limit rather than twice the last")

	n, err := b.Write(chunk)
	require.ErrorIs(t, err, errOutputTooLarge)
	require.Zero(t, n)
	require.True(t, b.over)
	require.Equal(t, want, b.buf, "the write past the limit is not kept")
	require.Equal(t, limit, cap(b.buf))

	small := &limitedBuffer{limit: 100}
	_, err = small.Write([]byte("{}"))
	require.NoError(t, err)
	require.Equal(t, 100, cap(small.buf), "a first allocation never exceeds the limit either")
}

func TestJSONObject(t *testing.T) {
	for in, want := range map[string]bool{
		`{}`: true, " \n{\"a\":1}\n": true,
		``: false, `null`: false, `[]`: false, `"x"`: false, `1`: false, `{`: false, `{} {}`: false,
	} {
		require.Equal(t, want, jsonObject([]byte(in)), "%q", in)
	}
}
