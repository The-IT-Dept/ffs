package match_test

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/match"
	"github.com/the-it-dept/ffs/internal/store"
)

var (
	ctx = context.Background()
	// osvTestdata holds the OSV fast path's trimmed real records.
	osvTestdata = os.DirFS(filepath.Join("osvfast", "testdata"))
)

func newStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "ffs.db"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	return st
}

// record parses one of the OSV fast path's real-record fixtures.
func record(t *testing.T, id string) (*osvschema.Vulnerability, []byte) {
	t.Helper()
	raw, err := fs.ReadFile(osvTestdata, id+".json")
	require.NoError(t, err)
	v, err := match.ParseOSV(raw)
	require.NoError(t, err)
	return v, raw
}

func TestOSVCanonicalID(t *testing.T) {
	for _, tc := range []struct {
		name string
		v    *osvschema.Vulnerability
		want string
	}{
		{"GHSA with a CVE alias", &osvschema.Vulnerability{Id: "GHSA-x", Aliases: []string{"CVE-2025-1"}}, "CVE-2025-1"},
		{"PYSEC with a GHSA alias", &osvschema.Vulnerability{Id: "PYSEC-1", Aliases: []string{"GHSA-a"}}, "GHSA-a"},
		{"malicious package, no aliases", &osvschema.Vulnerability{Id: "MAL-2025-9"}, "MAL-2025-9"},
		{"Debian record of one upstream CVE", &osvschema.Vulnerability{Id: "DEBIAN-CVE-2026-1", Upstream: []string{"CVE-2026-1"}}, "CVE-2026-1"},
		{"two CVE aliases", &osvschema.Vulnerability{Id: "GHSA-y", Aliases: []string{"CVE-2025-9", "CVE-2025-10"}}, "CVE-2025-10"},
		{"several upstream CVEs", &osvschema.Vulnerability{Id: "ALSA-2026:1", Upstream: []string{"CVE-2026-3", "CVE-2026-4"}}, "ALSA-2026:1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := match.UpsertOSVAdvisory(ctx, newStore(t), tc.v)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}

	t.Run("stored alias graph wins", func(t *testing.T) {
		st := newStore(t)
		_, err := match.UpsertOSVAdvisory(ctx, st, &osvschema.Vulnerability{Id: "GHSA-b", Aliases: []string{"CVE-2025-5"}})
		require.NoError(t, err)
		got, err := match.UpsertOSVAdvisory(ctx, st, &osvschema.Vulnerability{Id: "PYSEC-2", Aliases: []string{"GHSA-b"}})
		require.NoError(t, err)
		require.Equal(t, "CVE-2025-5", got)
	})
}

func TestUpsertOSVAdvisory(t *testing.T) {
	st := newStore(t)

	ghsa, _ := record(t, "GHSA-9wx4-h78v-vm56")
	canon, err := match.UpsertOSVAdvisory(ctx, st, ghsa)
	require.NoError(t, err)
	require.Equal(t, "CVE-2024-35195", canon)
	a, ok, err := st.GetAdvisory(ctx, canon)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, ghsa.GetSummary(), a.Title)
	require.Equal(t, []string{
		"https://github.com/psf/requests/security/advisories/GHSA-9wx4-h78v-vm56",
		"https://nvd.nist.gov/vuln/detail/CVE-2024-35195",
		"https://github.com/psf/requests/pull/6655",
	}, a.Links)
	require.Subset(t, a.Aliases, []string{"GHSA-9wx4-h78v-vm56", "PYSEC-2026-1873"})
	require.Equal(t, time.Date(2024, 5, 20, 20, 15, 0, 0, time.UTC), a.Published.Truncate(time.Second))
	require.False(t, a.Malicious)
	require.False(t, a.Withdrawn)
	ids, err := match.AdvisoryRecordIDs(ctx, st, canon)
	require.NoError(t, err)
	require.Equal(t, []string{"CVE-2024-35195", "GHSA-9wx4-h78v-vm56", "PYSEC-2026-1873"}, ids)

	t.Run("title from details", func(t *testing.T) {
		deb, _ := record(t, "DEBIAN-CVE-2024-5535")
		canon, err := match.UpsertOSVAdvisory(ctx, st, deb)
		require.NoError(t, err)
		a, _, err := st.GetAdvisory(ctx, canon)
		require.NoError(t, err)
		require.Equal(t, 200, utf8.RuneCountInString(a.Title))
		require.True(t, strings.HasPrefix(deb.GetDetails(), a.Title))
	})

	t.Run("malicious", func(t *testing.T) {
		mal, _ := record(t, "MAL-2024-1")
		canon, err := match.UpsertOSVAdvisory(ctx, st, mal)
		require.NoError(t, err)
		require.Equal(t, "MAL-2024-1", canon)
		a, _, err := st.GetAdvisory(ctx, canon)
		require.NoError(t, err)
		require.True(t, a.Malicious)
	})

	t.Run("withdrawn", func(t *testing.T) {
		_, raw := record(t, "GHSA-grv7-fg5c-xmjg")
		v, err := match.ParseOSV(bytes.Replace(raw, []byte("{"), []byte(`{"withdrawn": "2024-07-01T00:00:00Z",`), 1))
		require.NoError(t, err)
		canon, err := match.UpsertOSVAdvisory(ctx, st, v)
		require.NoError(t, err)
		require.Equal(t, "CVE-2024-4068", canon)
		a, _, err := st.GetAdvisory(ctx, canon)
		require.NoError(t, err)
		require.True(t, a.Withdrawn)
	})

	t.Run("unknown fields and enum values", func(t *testing.T) {
		v, err := match.ParseOSV([]byte(`{"id": "X-1", "future_field": {"a": 1},
			"severity": [{"type": "CVSS_V9", "score": "9"}, {"type": "Ubuntu", "score": "high"}]}`))
		require.NoError(t, err)
		require.Equal(t, "X-1", v.GetId())
		require.Equal(t, "high", v.GetSeverity()[len(v.GetSeverity())-1].GetScore())
		_, err = match.ParseOSV([]byte(`{"id": 1}`))
		require.Error(t, err)
	})
}
