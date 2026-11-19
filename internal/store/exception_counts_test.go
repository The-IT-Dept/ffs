package store

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

func TestCountExceptedBy(t *testing.T) {
	s := newStore(t)
	owner := func(name string) model.OwnerRef {
		return model.OwnerRef{Kind: "Deployment", Namespace: "web", Name: name, UID: "u-" + name}
	}
	f := func(name, state, by string) model.Finding {
		o := owner(name)
		return model.Finding{Fingerprint: model.FindingFingerprint("c", o, "repo", "CVE-1"), Owner: o, ImageRepo: "repo",
			AdvisoryID: "CVE-1", Priority: model.PriorityHigh, State: model.FindingState(state), ExceptedBy: by}
	}
	require.NoError(t, s.ApplyFindings(ctx, []model.Finding{
		f("a", "excepted", "web/accept"), f("b", "excepted", "web/accept"), f("c", "excepted", "ffs/global"),
		f("d", "open", "web/accept"), // a stale ExceptedBy on an open finding does not count
	}, nil))

	n, err := s.CountExceptedBy(ctx, "web/accept")
	require.NoError(t, err)
	require.Equal(t, 2, n)
	n, err = s.CountExceptedBy(ctx, "web/none")
	require.NoError(t, err)
	require.Zero(t, n)

	var plan string
	rows, err := s.rdb.QueryContext(ctx, `EXPLAIN QUERY PLAN SELECT count(*) FROM findings WHERE excepted_by = ?`, "web/accept")
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id, parent, unused int
		var detail string
		require.NoError(t, rows.Scan(&id, &parent, &unused, &detail))
		plan += detail + "\n"
	}
	require.NoError(t, rows.Err())
	require.Contains(t, plan, "findings_by_excepted_by")
}
