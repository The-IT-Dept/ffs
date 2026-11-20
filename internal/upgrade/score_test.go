package upgrade

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

const (
	urgent = model.PriorityUrgent
	high   = model.PriorityHigh
	medium = model.PriorityMedium
	low    = model.PriorityLow
)

type byPriority = map[model.Priority]int

func open(id string, p model.Priority, fixable bool) model.Finding {
	return model.Finding{AdvisoryID: id, ImageRepo: "docker.io/library/nginx", State: model.StateOpen, Priority: p, FixAvailable: fixable}
}

func excepted(id string, p model.Priority) model.Finding {
	f := open(id, p, true)
	f.State = model.StateExcepted
	return f
}

func TestScore_FixesRemainingIntroduces(t *testing.T) {
	before := []model.Finding{open("A", urgent, true), open("B", high, true), open("C", medium, false), excepted("E", urgent)}
	after := []model.Finding{open("B", high, true), open("D", low, false), excepted("F", high)}
	fixes, remaining, introduces, fixedIDs, clears := Score(before, after)
	require.Equal(t, byPriority{urgent: 1, medium: 1}, fixes)
	require.Equal(t, byPriority{high: 1}, remaining)
	require.Equal(t, byPriority{low: 1}, introduces)
	require.Equal(t, []string{"A", "C"}, fixedIDs)
	require.False(t, clears, "B is fixable, high and remains")

	// a remaining finding without a fix, or below high, does not block clearing
	_, remaining, _, fixedIDs, clears = Score(
		[]model.Finding{open("A", urgent, true), open("B", high, false), open("C", medium, true)},
		[]model.Finding{open("B", urgent, false), open("C", medium, true)})
	require.True(t, clears)
	require.Equal(t, []string{"A"}, fixedIDs)
	require.Equal(t, byPriority{urgent: 1, medium: 1}, remaining, "remaining counts at the after priority")
}

func TestRecommend(t *testing.T) {
	type cand struct {
		tier              model.Tier
		fixes, introduces byPriority
		fixed             []string
		clears            bool
	}
	for _, tc := range []struct {
		name     string
		cands    []cand
		wantRec  model.Tier // "" = no recommendation
		wantAlts []model.Tier
	}{
		{"nearest tier that clears wins", []cand{
			{model.TierPatch, byPriority{urgent: 1, high: 1, medium: 1}, nil, []string{"A", "B", "C"}, true},
			{model.TierRefresh, byPriority{urgent: 1, high: 1}, nil, []string{"A", "B"}, true},
		}, model.TierRefresh, []model.Tier{model.TierPatch}},
		{"clearing beats fixing less", []cand{
			{model.TierRefresh, byPriority{high: 1}, nil, []string{"B"}, false},
			{model.TierPatch, byPriority{urgent: 1, high: 1}, nil, []string{"A", "B"}, true},
		}, model.TierPatch, nil},
		{"urgent before high", []cand{
			{model.TierRefresh, byPriority{high: 1}, nil, []string{"B"}, false},
			{model.TierMinor, byPriority{urgent: 1}, nil, []string{"A"}, false},
		}, model.TierMinor, nil},
		{"medium breaks the urgent and high tie", []cand{
			{model.TierPatch, byPriority{high: 1}, nil, []string{"B"}, false},
			{model.TierMinor, byPriority{high: 1, medium: 3}, nil, []string{"B", "C", "D", "E"}, false},
		}, model.TierMinor, nil},
		{"full tie goes to the nearer tier", []cand{
			{model.TierMinor, byPriority{high: 1}, nil, []string{"B"}, false},
			{model.TierPatch, byPriority{high: 1}, nil, []string{"B"}, false},
		}, model.TierPatch, nil},
		{"major is only an alternative", []cand{
			{model.TierMajor, byPriority{urgent: 1, high: 1}, nil, []string{"A", "B"}, true},
			{model.TierPatch, byPriority{high: 1}, nil, []string{"B"}, false},
		}, model.TierPatch, []model.Tier{model.TierMajor}},
		{"only major fixes", []cand{
			{model.TierPatch, byPriority{}, nil, nil, false},
			{model.TierMajor, byPriority{urgent: 1, high: 1}, nil, []string{"A", "B"}, true},
		}, "", []model.Tier{model.TierMajor}},
		{"introducing high disqualifies a clearing tier", []cand{
			{model.TierRefresh, byPriority{urgent: 1, high: 1}, byPriority{high: 1}, []string{"A", "B"}, true},
			{model.TierPatch, byPriority{urgent: 1, high: 1}, nil, []string{"A", "B"}, true},
		}, model.TierPatch, nil},
		{"nothing fixes anything", []cand{
			{model.TierRefresh, byPriority{}, nil, nil, false},
			{model.TierPatch, byPriority{}, byPriority{low: 1}, nil, false},
		}, "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var in []Scored
			for _, c := range tc.cands {
				in = append(in, Scored{Tag: string(c.tier), Tier: c.tier, Fixes: c.fixes, Introduces: c.introduces,
					FixedIDs: c.fixed, ClearsUrgentHigh: c.clears})
			}
			rec, alts := Recommend(in)
			if tc.wantRec == "" {
				require.Nil(t, rec)
			} else {
				require.NotNil(t, rec)
				require.Equal(t, tc.wantRec, rec.Tier)
			}
			var got []model.Tier
			for _, a := range alts {
				got = append(got, a.Tier)
			}
			require.Equal(t, tc.wantAlts, got)
		})
	}
}

func TestRecommend_FirstRuleNeedsAMediumFixOrNoHarm(t *testing.T) {
	// no urgent or high findings: clearing them is vacuous for every candidate
	lowFixAddsMediums := Scored{Tag: "refresh", Tier: model.TierRefresh, Fixes: byPriority{low: 1},
		Introduces: byPriority{medium: 2}, FixedIDs: []string{"L"}, ClearsUrgentHigh: true}
	fixesMedium := Scored{Tag: "patch", Tier: model.TierPatch, Fixes: byPriority{medium: 1},
		Introduces: byPriority{medium: 2}, FixedIDs: []string{"M"}, ClearsUrgentHigh: true}
	rec, _ := Recommend([]Scored{lowFixAddsMediums, fixesMedium})
	require.NotNil(t, rec)
	require.Equal(t, model.TierPatch, rec.Tier, "a candidate that fixes a medium wins on the first rule")

	noHarm := Scored{Tag: "minor", Tier: model.TierMinor, Fixes: byPriority{low: 2}, Introduces: byPriority{low: 1},
		FixedIDs: []string{"L", "K"}, ClearsUrgentHigh: true}
	rec, _ = Recommend([]Scored{lowFixAddsMediums, noHarm})
	require.NotNil(t, rec)
	require.Equal(t, model.TierMinor, rec.Tier, "a non-negative net medium and low change wins on the first rule")

	rec, _ = Recommend([]Scored{lowFixAddsMediums})
	require.Nil(t, rec, "fixing one low while introducing two mediums is no recommendation")
}

func TestNetChange(t *testing.T) {
	require.Equal(t, "fixes 1 urgent, 2 high; introduces none",
		NetChange(model.Suggestion{Fixes: byPriority{urgent: 1, high: 2, low: 0}, Introduces: byPriority{}}))
	require.Equal(t, "fixes none; introduces 1 low", NetChange(model.Suggestion{Fixes: byPriority{}, Introduces: byPriority{low: 1}}))
	require.Equal(t, "fixes none; introduces none", NetChange(model.Suggestion{}))
}

func TestTarget(t *testing.T) {
	for _, tc := range []struct {
		s    model.Suggestion
		want string
	}{
		{model.Suggestion{Repo: "docker.io/library/nginx", ToTag: "1.30.7", Tier: model.TierPatch}, "nginx:1.30.7"},
		{model.Suggestion{Repo: "docker.io/bitnami/postgresql", ToTag: "17.6.0", Tier: model.TierMinor}, "bitnami/postgresql:17.6.0"},
		{model.Suggestion{Repo: "ghcr.io/org/app", ToTag: "2.1.0", Tier: model.TierRefresh}, "ghcr.io/org/app:2.1.0 (new digest)"},
		{model.Suggestion{Repo: "kubernetes", ToTag: "v1.35.10"}, "kubernetes v1.35.10"},
		{model.Suggestion{Repo: "containerd", ToTag: "2.2.3"}, "containerd 2.2.3"},
		{model.Suggestion{Repo: "docker.io/library/nginx", Tier: model.TierNone}, ""},
	} {
		require.Equal(t, tc.want, Target(tc.s), tc.s.Repo)
	}
}
