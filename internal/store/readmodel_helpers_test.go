package store

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

// Fixture builders for the read-model tests; the explorer and UI read tests reuse them.

const testCluster = "test"

func ref(kind, ns, name string) model.OwnerRef {
	return model.OwnerRef{Kind: kind, Namespace: ns, Name: name}
}

// uiFinding is an open finding of o on repo and advisory at priority p: severity high, published two
// days before t0, on digest "sha256:<o.Name>", affecting deb openssl 3.0.15-1. mods run last.
func uiFinding(o model.OwnerRef, repo, advisory string, p model.Priority, mods ...func(*model.Finding)) model.Finding {
	f := model.Finding{
		Fingerprint: model.FindingFingerprint(testCluster, o, repo, advisory),
		Owner:       o,
		ImageRepo:   repo,
		AdvisoryID:  advisory,
		State:       model.StateOpen,
		Priority:    p,
		Severity:    model.SeverityHigh,
		Published:   t0.Add(-48 * time.Hour),
		LastSeen:    t0,
		Digests:     []string{"sha256:" + o.Name},
		Packages:    []model.FindingPackage{{Name: "openssl", Ecosystem: "deb", Installed: "3.0.15-1"}},
	}
	for _, m := range mods {
		m(&f)
	}
	return f
}

// uiOwner is the owner r with one container, named r.Name, running "ghcr.io/example/<r.Name>" at
// digest "sha256:<r.Name>". mods run last.
func uiOwner(r model.OwnerRef, mods ...func(*model.Owner)) model.Owner {
	o := model.Owner{Ref: r, Containers: []model.ContainerUse{{Name: r.Name, Kind: model.ContainerRegular,
		Repo: "ghcr.io/example/" + r.Name, Digest: "sha256:" + r.Name}}}
	for _, m := range mods {
		m(&o)
	}
	return o
}

func apply(t *testing.T, s *Store, fs ...model.Finding) {
	t.Helper()
	require.NoError(t, s.ApplyFindings(ctx, fs, nil))
}

func statsOf(t *testing.T, s *Store, key string) OwnerStats {
	t.Helper()
	st, err := s.OwnerStatsOf(ctx, []string{key})
	require.NoError(t, err)
	return st[key]
}

// rollupDrift compares each rollup table with what the findings rows say it should hold, in both
// directions, and returns "<table>: <side> <row>" for each row found on one side only. Nil digests
// and packages are stored as JSON null, which json_each returns as one NULL row: it holds nothing.
func rollupDrift(t *testing.T, s *Store) []string {
	t.Helper()
	checks := []struct{ table, expected, actual string }{
		{"owner_stats",
			`SELECT f.owner_key, min(f.namespace), min(f.owner_kind), ` + findingContributions + `
			FROM findings f WHERE f.state IN ('open', 'excepted') GROUP BY f.owner_key`,
			`SELECT owner_key, namespace, owner_kind, ` + ownerStatsCols + ` FROM owner_stats`},
		{"finding_digests",
			`SELECT DISTINCT d.value, f.fingerprint, f.state, f.priority, f.fix_available FROM findings f, json_each(f.data, '$.Digests') d
			WHERE d.value IS NOT NULL`,
			`SELECT digest, fingerprint, state, priority, fix_available FROM finding_digests`},
		{"finding_packages",
			`SELECT DISTINCT coalesce(json_extract(p.value, '$.Ecosystem'), ''), coalesce(json_extract(p.value, '$.Name'), ''),
				coalesce(json_extract(p.value, '$.Installed'), ''), f.fingerprint, f.state, f.priority, f.fix_available
			FROM findings f, json_each(f.data, '$.Packages') p WHERE p.value IS NOT NULL`,
			`SELECT ecosystem, name, version, fingerprint, state, priority, fix_available FROM finding_packages`},
	}
	var drift []string
	for _, c := range checks {
		q := "SELECT 'expected only', * FROM (" + c.expected + " EXCEPT " + c.actual + ") UNION ALL SELECT 'rollup only', * FROM (" + c.actual + " EXCEPT " + c.expected + ")" //nolint:gosec // G202: joins this test's constant queries
		rows, err := s.wdb.QueryContext(ctx, q)
		require.NoError(t, err, c.table)
		cols, err := rows.Columns()
		require.NoError(t, err)
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			require.NoError(t, rows.Scan(ptrs...))
			drift = append(drift, fmt.Sprintf("%s: %v %v", c.table, vals[0], vals[1:]))
		}
		require.NoError(t, rows.Err())
		require.NoError(t, rows.Close())
	}
	return drift
}
