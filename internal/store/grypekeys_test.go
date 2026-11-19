package store

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGrypeKeys_ReplaceAndLookup(t *testing.T) {
	s := newStore(t)
	const d, other = "sha256:d", "sha256:other"
	require.NoError(t, s.PutGrypeKeys(ctx, d, []string{"openssl"}, []string{"php"}))
	require.NoError(t, s.PutGrypeKeys(ctx, other, []string{"OpenSSL", "libssl3"}, nil))

	got, err := s.DigestsForGrypeKeys(ctx, nil, []string{"php"})
	require.NoError(t, err)
	require.Equal(t, []string{d}, got)
	got, err = s.DigestsForGrypeKeys(ctx, []string{"openssl"}, nil)
	require.NoError(t, err)
	require.Equal(t, []string{d, other}, got, "names are lowercased on write")
	got, err = s.DigestsForGrypeKeys(ctx, []string{"php"}, nil)
	require.NoError(t, err)
	require.Empty(t, got, "a CPE product is not a package name")

	// a second put replaces the digest's keys
	require.NoError(t, s.PutGrypeKeys(ctx, d, []string{"bind9"}, []string{"Bind"}))
	got, err = s.DigestsForGrypeKeys(ctx, []string{"openssl"}, []string{"php"})
	require.NoError(t, err)
	require.Equal(t, []string{other}, got)
	got, err = s.DigestsForGrypeKeys(ctx, []string{"BIND9"}, []string{"bind"})
	require.NoError(t, err)
	require.Equal(t, []string{d}, got)

	all, err := s.GrypeDigests(ctx)
	require.NoError(t, err)
	require.Equal(t, []string{d, other}, all)
}
