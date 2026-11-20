package store

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
)

func TestFindingsPage_KeysetStableWhenRowsInserted(t *testing.T) { // Review Focus 4
	owners := []model.OwnerRef{ref("Deployment", "shop", "web"), ref("Deployment", "shop", "worker"), ref("Deployment", "shop", "cart"),
		ref("CronJob", "ops", "backup"), ref("DaemonSet", "ops", "exporter"), ref("Deployment", "ops", "report")}
	mk := func(i int) model.Finding {
		o := owners[i%len(owners)]
		return uiFinding(o, "ghcr.io/example/"+o.Name, fmt.Sprintf("CVE-2026-%04d", i%40), model.Priority(1+i%4), func(f *model.Finding) {
			f.Severity = model.Severity(i % 6)
			f.Signals.EPSS = float64(i%5) / 10
			f.Published = t0.Add(-time.Duration(i%7) * 24 * time.Hour)
		})
	}
	for _, sort := range []FindingSort{SortPriority, SortSeverity, SortPublished, SortEPSS, SortAdvisory, SortWorkload, SortNamespace} {
		t.Run(string(sort), func(t *testing.T) {
			s := newStore(t)
			orig := make([]model.Finding, 120)
			for i := range orig {
				orig[i] = mk(i)
			}
			apply(t, s, orig...)
			full, err := s.FindingsPage(ctx, FindingQuery{Sort: sort, Limit: 200})
			require.NoError(t, err)
			require.Len(t, full.Rows, 120)
			require.Empty(t, full.Next)

			p1, err := s.FindingsPage(ctx, FindingQuery{Sort: sort, Limit: 50})
			require.NoError(t, err)
			require.Equal(t, fps(full.Rows[:50]), fps(p1.Rows))
			require.Equal(t, 120, p1.Total)
			require.NotEmpty(t, p1.Next)

			// 30 new findings whose sort values copy rows 0, 49, 50 and 119 of the full order
			positions := []int{0, 49, 50, 119}
			added := make([]model.Finding, 30)
			for i := range added {
				c := full.Rows[positions[i%len(positions)]]
				c.ImageRepo = fmt.Sprintf("%s-copy-%d", c.ImageRepo, i)
				c.Fingerprint = model.FindingFingerprint(testCluster, c.Owner, c.ImageRepo, c.AdvisoryID)
				added[i] = c
			}
			apply(t, s, added...)

			seen := map[string]int{}
			for _, f := range p1.Rows {
				seen[f.Fingerprint]++
			}
			next, pages := p1.Next, 1
			for next != "" {
				p, err := s.FindingsPage(ctx, FindingQuery{Sort: sort, Limit: 50, After: next})
				require.NoError(t, err)
				require.Equal(t, 150, p.Total)
				for _, f := range p.Rows {
					seen[f.Fingerprint]++
				}
				next, pages = p.Next, pages+1
				require.LessOrEqual(t, pages, 4)
			}
			for fp, n := range seen {
				require.Equal(t, 1, n, "fingerprint %s read twice", fp)
			}
			for _, f := range orig {
				require.Equal(t, 1, seen[f.Fingerprint], "original %s/%s", f.Owner.Key(), f.AdvisoryID)
			}
		})
	}
}

// explorerFixture holds findings in every fix class, signal and scope for the filter tests.
type explorerFixture struct {
	w1, w2, w3, k1, k2, b1, c1, n1, r1, r2, e1 model.Finding
}

func seedFindingsExplorer(t *testing.T, s *Store) explorerFixture {
	t.Helper()
	web, worker, backup := ref("Deployment", "shop", "web"), ref("Deployment", "shop", "worker"), ref("CronJob", "ops", "backup")
	cluster, nodes := ref("Cluster", "", testCluster), ref("Nodes", "", testCluster)
	const webRepo, workerRepo = "ghcr.io/example/web", "ghcr.io/example/worker"
	rebuild := &model.FixAction{Kind: model.FixKindRebuild, Key: "rebuild:debian:12", Label: "debian 12 rebuild",
		Distro: &model.Distro{ID: "debian", VersionID: "12"}}
	resolved := func(days int) func(*model.Finding) {
		return func(f *model.Finding) {
			at := t0.Add(-time.Duration(days) * 24 * time.Hour)
			f.State, f.ResolvedAt = model.StateResolved, &at
		}
	}
	var x explorerFixture
	x.w1 = uiFinding(web, webRepo, "CVE-2026-0001", model.PriorityUrgent, func(f *model.Finding) {
		f.Signals = model.FindingSignals{Exposed: true, KEV: true}
		f.FixAvailable, f.Fix = true, rebuild
		f.Packages = []model.FindingPackage{{Name: "libcurl4", Ecosystem: "deb", Installed: "7.88.1-10"},
			{Name: "libssl3", Ecosystem: "deb", Installed: "3.0.15-1"}}
	})
	x.w2 = uiFinding(web, webRepo, "CVE-2026-0002", model.PriorityHigh, func(f *model.Finding) {
		f.Signals.Exposed = true
		f.FixAvailable, f.Fix = true, rebuild
	})
	x.w3 = uiFinding(web, webRepo, "CVE-2026-0003", model.PriorityMedium, func(f *model.Finding) {
		f.FixAvailable = true
		f.Packages = []model.FindingPackage{{Name: "lodash", Ecosystem: "npm", Installed: "4.17.20", Fixed: []string{"4.17.21"}}}
		f.Fix = &model.FixAction{Kind: model.FixKindPackage, Key: "package:npm:lodash:4.17.20:4.17.21", Label: "lodash 4.17.20 → 4.17.21",
			Package: "lodash", Ecosystem: "npm", From: "4.17.20", To: "4.17.21"}
	})
	x.k1 = uiFinding(worker, workerRepo, "CVE-2026-0004", model.PriorityLow, func(f *model.Finding) { f.FixState = model.FixWontFix })
	x.k2 = uiFinding(worker, workerRepo, "CVE-2026-0005", model.PriorityHigh, func(f *model.Finding) {
		f.FixState, f.Signals.KEV = model.FixNotFixed, true
	})
	x.b1 = uiFinding(backup, "ghcr.io/example/backup", "CVE-2026-0006", model.PriorityMedium, func(f *model.Finding) {
		f.Signals = model.FindingSignals{Exposed: true, KEV: true}
		f.FixAvailable, f.Fix = true, rebuild
	})
	x.c1 = uiFinding(cluster, "kubernetes", "CVE-2026-0007", model.PriorityHigh, func(f *model.Finding) { f.Digests = []string{"k8s:1.35.1"} })
	x.n1 = uiFinding(nodes, "host", "CVE-2026-0008", model.PriorityUrgent, func(f *model.Finding) { f.Digests = []string{"nodegroup:g1"} })
	x.r1 = uiFinding(web, webRepo, "CVE-2026-0009", model.PriorityHigh, resolved(10))
	x.r2 = uiFinding(web, webRepo, "CVE-2026-0010", model.PriorityHigh, resolved(40))
	x.e1 = uiFinding(worker, workerRepo, "CVE-2026-0011", model.PriorityMedium, func(f *model.Finding) {
		f.State, f.ExceptedBy = model.StateExcepted, "shop/accepted"
	})
	apply(t, s, x.w1, x.w2, x.w3, x.k1, x.k2, x.b1, x.c1, x.n1, x.r1, x.r2, x.e1)
	require.NoError(t, s.PutSuggestion(ctx, web.Key(), model.Suggestion{Repo: webRepo, FromTag: "1.0.0", ToTag: "1.0.1",
		Tier: model.TierPatch, FixedIDs: []string{x.w2.AdvisoryID}}, nil))
	require.NoError(t, s.UpsertAdvisory(ctx, model.Advisory{ID: x.k2.AdvisoryID, Aliases: []string{"GHSA-xxxx-yyyy-zzzz"}, Title: "t"}))
	return x
}

// advisories returns the advisory IDs of fs, sorted.
func advisories(fs []model.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.AdvisoryID
	}
	slices.Sort(out)
	return out
}

func ids(fs ...model.Finding) []string { return advisories(fs) }

func TestFindingsPage_FiltersAndDefaults(t *testing.T) {
	s := newStore(t)
	x := seedFindingsExplorer(t, s)
	page := func(q FindingQuery) FindingPage {
		t.Helper()
		p, err := s.FindingsPage(ctx, q)
		require.NoError(t, err)
		require.Equal(t, len(p.Rows), p.Total, "one page holds every row")
		return p
	}
	got := func(q FindingQuery) []string { t.Helper(); return advisories(page(q).Rows) }
	open := []model.Finding{x.w1, x.w2, x.w3, x.k1, x.k2, x.b1, x.c1, x.n1}

	p := page(FindingQuery{})
	require.Equal(t, ids(open...), advisories(p.Rows))
	for _, f := range p.Rows {
		require.Equal(t, model.StateOpen, f.State)
	}
	require.Empty(t, p.Next)

	require.Equal(t, ids(x.w1, x.w2, x.k2, x.c1, x.n1), got(FindingQuery{Priorities: []model.Priority{model.PriorityUrgent, model.PriorityHigh}}))

	byClass := map[model.FixClass][]string{
		model.FixClassUpgrade: ids(x.w2), model.FixClassFixed: ids(x.w1, x.w3, x.b1),
		model.FixClassWontFix: ids(x.k1), model.FixClassNone: ids(x.k2, x.c1, x.n1),
	}
	var sum []string
	for class, want := range byClass {
		require.Equal(t, want, got(FindingQuery{Fix: []model.FixClass{class}}), class)
		sum = append(sum, want...)
	}
	slices.Sort(sum)
	require.Equal(t, ids(open...), sum, "the fix classes are disjoint and cover every open finding")

	require.Equal(t, ids(x.w1, x.b1), got(FindingQuery{Signals: []model.Signal{model.SignalExposed, model.SignalExploited}}))
	require.Equal(t, ids(x.w3), got(FindingQuery{Ecosystems: []string{"npm"}}))
	require.Equal(t, ids(x.w1), got(FindingQuery{Package: "libssl3"}), "matches the second package")
	require.Equal(t, ids(x.b1), got(FindingQuery{Namespaces: []string{"ops"}}))
	require.Equal(t, ids(x.b1), got(FindingQuery{Kinds: []string{"CronJob"}}))
	require.Equal(t, ids(x.k2), got(FindingQuery{Advisory: "GHSA-xxxx-yyyy-zzzz"}))
	require.Equal(t, ids(x.k1, x.k2), got(FindingQuery{Repo: "ghcr.io/example/worker"}))
	require.Empty(t, got(FindingQuery{Repo: "ghcr.io/example/work"}))
	require.Equal(t, ids(x.w1, x.w2, x.w3), got(FindingQuery{Q: "WEB"}))

	// FixKey: exactly the findings whose effective fix has that key
	all, err := s.ListFindings(ctx, FindingFilter{States: []model.FindingState{model.StateOpen}})
	require.NoError(t, err)
	var rebuilds []model.Finding
	for _, f := range all {
		if f.EffectiveFix().Key == "rebuild:debian:12" {
			rebuilds = append(rebuilds, f)
		}
	}
	require.Equal(t, ids(x.w1, x.b1), advisories(rebuilds))
	require.Equal(t, advisories(rebuilds), got(FindingQuery{FixKey: "rebuild:debian:12"}))
	webFix := FindingQuery{Scope: model.Scope{Kind: model.ScopeWorkload, Value: "Deployment/shop/web"}, FixKey: "rebuild:debian:12"}
	require.Equal(t, ids(x.w1), got(webFix))
	ps, err := findingPageStmt(webFix)
	require.NoError(t, err)
	require.Contains(t, queryPlan(t, s, ps.query, ps.args...), "findings_fix")
	webFix.States = []model.FindingState{model.StateOpen, model.StateResolved}
	require.Equal(t, ids(x.w1), got(webFix), "findings_fix also serves a state predicate with resolved")

	require.Equal(t, ids(x.r1), got(FindingQuery{States: []model.FindingState{model.StateResolved}, ResolvedSince: t0.Add(-30 * 24 * time.Hour)}))
	require.Equal(t, ids(x.r1, x.r2), got(FindingQuery{States: []model.FindingState{model.StateResolved}}))
	require.Equal(t, ids(x.k2, x.e1), got(FindingQuery{States: []model.FindingState{model.StateOpen, model.StateExcepted},
		Repo: "ghcr.io/example/worker", Priorities: []model.Priority{model.PriorityHigh, model.PriorityMedium}}))

	require.Equal(t, ids(x.w1, x.w2, x.w3), got(FindingQuery{Scope: model.Scope{Kind: model.ScopeImage, Value: "sha256:web"}}))
	require.Equal(t, ids(x.n1), got(FindingQuery{Scope: model.Scope{Kind: model.ScopeNodeGroup, Value: "g1"}}))
	require.Equal(t, ids(x.c1), got(FindingQuery{Scope: model.Scope{Kind: model.ScopeControlPlane}}))
	_, err = s.FindingsPage(ctx, FindingQuery{Scope: model.Scope{Kind: model.ScopeNode, Value: "worker-1"}})
	require.ErrorIs(t, err, ErrScope)

	first, err := s.FindingsPage(ctx, FindingQuery{Limit: 2})
	require.NoError(t, err)
	require.NotEmpty(t, first.Next)
	_, err = s.FindingsPage(ctx, FindingQuery{Sort: SortWorkload, Limit: 2, After: first.Next})
	require.ErrorIs(t, err, ErrBadCursor)
	_, err = s.FindingsPage(ctx, FindingQuery{After: "!!"})
	require.ErrorIs(t, err, ErrBadCursor)

	// Limit 0 is 50 rows; above 200 is 200
	big := newStore(t)
	many := make([]model.Finding, 210)
	for i := range many {
		many[i] = uiFinding(ref("Deployment", "shop", "web"), "ghcr.io/example/web", fmt.Sprintf("CVE-2026-%04d", i), model.PriorityHigh)
	}
	apply(t, big, many...)
	for limit, want := range map[int]int{0: 50, 500: 200} {
		p, err := big.FindingsPage(ctx, FindingQuery{Limit: limit})
		require.NoError(t, err)
		require.Len(t, p.Rows, want, limit)
		require.Equal(t, 210, p.Total)
		require.NotEmpty(t, p.Next)
	}
}

func TestFindingGroups_FixOrderAndSample(t *testing.T) {
	s := newStore(t)
	web := ref("Deployment", "shop", "web")
	const repo = "ghcr.io/example/web"
	n := 0
	mk := func(p model.Priority, mod func(*model.Finding)) model.Finding {
		n++
		return uiFinding(web, repo, fmt.Sprintf("CVE-2026-%04d", n), p, mod)
	}
	rebuild := func(f *model.Finding) {
		f.FixAvailable, f.Fix = true, &model.FixAction{Kind: model.FixKindRebuild, Key: "rebuild:debian:12", Label: "debian 12 rebuild",
			Distro: &model.Distro{ID: "debian", VersionID: "12"}}
	}
	none := func(f *model.Finding) { f.FixState = model.FixNotFixed }
	up1, up2 := mk(model.PriorityUrgent, rebuild), mk(model.PriorityUrgent, rebuild)
	rbUrgent := mk(model.PriorityUrgent, rebuild)
	fs := []model.Finding{up1, up2, rbUrgent, mk(model.PriorityHigh, rebuild), mk(model.PriorityHigh, rebuild), mk(model.PriorityHigh, rebuild),
		mk(model.PriorityHigh, func(f *model.Finding) {
			f.FixAvailable, f.Fix = true, &model.FixAction{Kind: model.FixKindPackage, Key: "package:npm:lodash:4.17.20:4.17.21",
				Label: "lodash 4.17.20 → 4.17.21", Package: "lodash", Ecosystem: "npm", From: "4.17.20", To: "4.17.21"}
		}),
		mk(model.PriorityUrgent, none), mk(model.PriorityUrgent, none), mk(model.PriorityUrgent, none), mk(model.PriorityUrgent, none),
		mk(model.PriorityUrgent, none),
		mk(model.PriorityLow, func(f *model.Finding) { f.FixState = model.FixWontFix }),
	}
	apply(t, s, fs...)
	require.NoError(t, s.PutSuggestion(ctx, web.Key(), model.Suggestion{Repo: repo, FromTag: "1.0.0", ToTag: "1.0.1", Tier: model.TierPatch,
		FixedIDs: []string{up1.AdvisoryID, up2.AdvisoryID}}, nil))

	page, err := s.FindingGroups(ctx, FindingQuery{}, GroupFix)
	require.NoError(t, err)
	var keys []string
	for _, r := range page.Rows {
		keys = append(keys, r.Key)
		require.Equal(t, r.Key, r.Label)
		require.NotNil(t, r.Sample, r.Key)
		require.Equal(t, r.Key, r.Sample.EffectiveFix().Key)
		require.Equal(t, r.Worst, r.Sample.Priority, "the sample is the group's highest-priority finding")
	}
	require.Equal(t, []string{"upgrade:" + repo + ":1.0.1", "rebuild:debian:12", "package:npm:lodash:4.17.20:4.17.21", "none", "wontfix"}, keys)
	require.Equal(t, rbUrgent.Fingerprint, page.Rows[1].Sample.Fingerprint)
	require.Equal(t, PriorityCounts{Urgent: 1, High: 3}, page.Rows[1].Counts)
	require.Equal(t, PriorityCounts{Urgent: 5}, page.Rows[3].Counts)
	require.Equal(t, 5, page.Groups)
	flat, err := s.FindingsPage(ctx, FindingQuery{})
	require.NoError(t, err)
	require.Equal(t, flat.Total, page.Findings)
	require.Equal(t, len(fs), page.Findings)
	require.Empty(t, page.Next)

	// the keyset walks the same order a page at a time
	var walked []string
	after := ""
	for {
		p, err := s.FindingGroups(ctx, FindingQuery{Limit: 2, After: after}, GroupFix)
		require.NoError(t, err)
		for _, r := range p.Rows {
			walked = append(walked, r.Key)
		}
		if after = p.Next; after == "" {
			break
		}
	}
	require.Equal(t, keys, walked)
}

func TestFindingGroups_CountsAndDistinct(t *testing.T) {
	s := newStore(t)
	web, worker := ref("Deployment", "shop", "web"), ref("Deployment", "shop", "worker")
	backup, cluster := ref("CronJob", "ops", "backup"), ref("Cluster", "", testCluster)
	apply(t, s,
		uiFinding(web, "ghcr.io/example/web", "CVE-2026-0001", model.PriorityUrgent, func(f *model.Finding) {
			f.FixAvailable, f.Signals.KEV = true, true
			f.Packages = []model.FindingPackage{{Name: "libssl3", Ecosystem: "deb", Installed: "3.0.15-1"},
				{Name: "openssl", Ecosystem: "deb", Installed: "3.0.15-1"}}
		}),
		uiFinding(web, "ghcr.io/example/web", "CVE-2026-0002", model.PriorityHigh),
		uiFinding(worker, "ghcr.io/example/worker", "CVE-2026-0001", model.PriorityHigh, func(f *model.Finding) { f.FixAvailable = true }),
		uiFinding(worker, "ghcr.io/example/worker", "CVE-2026-0003", model.PriorityLow),
		uiFinding(cluster, "kubernetes", "CVE-2026-0004", model.PriorityMedium, func(f *model.Finding) { f.Digests = []string{"k8s:1.35.1"} }),
		uiFinding(backup, "ghcr.io/example/backup", "CVE-2026-0005", model.PriorityLow, func(f *model.Finding) { f.Signals.KEV = true }),
	)
	flat, err := s.FindingsPage(ctx, FindingQuery{Limit: 200})
	require.NoError(t, err)
	require.Equal(t, 6, flat.Total)

	keysOf := map[FindingGroup]func(model.Finding) []string{
		GroupAdvisory:  func(f model.Finding) []string { return []string{f.AdvisoryID} },
		GroupWorkload:  func(f model.Finding) []string { return []string{f.Owner.Key()} },
		GroupImage:     func(f model.Finding) []string { return []string{f.ImageRepo} },
		GroupNamespace: func(f model.Finding) []string { return []string{f.Owner.Namespace} },
		GroupFix:       func(f model.Finding) []string { return []string{f.EffectiveFix().Key} },
		GroupPackage: func(f model.Finding) []string {
			var ks []string
			for _, p := range f.Packages {
				ks = append(ks, p.Ecosystem+"/"+p.Name+"@"+p.Installed)
			}
			return ks
		},
	}
	for g, keyOf := range keysOf {
		want := map[string]GroupRow{}
		distinct := map[string]map[string]bool{}
		for _, f := range flat.Rows {
			for _, k := range keyOf(f) {
				r := want[k]
				r.Key, r.Label, r.Findings = k, k, r.Findings+1
				switch f.Priority {
				case model.PriorityUrgent:
					r.Counts.Urgent++
				case model.PriorityHigh:
					r.Counts.High++
				case model.PriorityMedium:
					r.Counts.Medium++
				case model.PriorityLow:
					r.Counts.Low++
				}
				if f.FixAvailable {
					r.Fixable++
				}
				if f.Signals.KEV {
					r.Exploited++
				}
				r.Worst = max(r.Worst, f.Priority)
				if distinct[k] == nil {
					distinct[k] = map[string]bool{}
				}
				if g == GroupAdvisory {
					distinct[k][f.Owner.Key()] = true
				} else {
					distinct[k][f.AdvisoryID] = true
				}
				want[k] = r
			}
		}
		page, err := s.FindingGroups(ctx, FindingQuery{}, g)
		require.NoError(t, err, g)
		require.Len(t, page.Rows, len(want), g)
		require.Equal(t, len(want), page.Groups, g)
		sum := 0
		for _, r := range page.Rows {
			w := want[r.Key]
			w.Distinct = len(distinct[r.Key])
			r.Sample = nil
			require.Equal(t, w, r, "%s group %q", g, r.Key)
			sum += r.Findings
		}
		require.Equal(t, sum, page.Findings, g)
		if g == GroupPackage {
			require.Greater(t, page.Findings, flat.Total, "a finding counts under each of its packages")
			require.Equal(t, 6, want["deb/openssl@3.0.15-1"].Findings)
		} else {
			require.Equal(t, flat.Total, page.Findings, g)
		}
	}

	ns, err := s.FindingGroups(ctx, FindingQuery{}, GroupNamespace)
	require.NoError(t, err)
	var clusterLevel *GroupRow
	for i := range ns.Rows {
		if ns.Rows[i].Key == "" {
			clusterLevel = &ns.Rows[i]
		}
	}
	require.NotNil(t, clusterLevel, "the cluster-level findings group under namespace \"\"")
	require.Equal(t, 1, clusterLevel.Findings)
	adv, err := s.FindingGroups(ctx, FindingQuery{}, GroupAdvisory)
	require.NoError(t, err)
	require.Equal(t, 2, adv.Rows[0].Distinct, "CVE-2026-0001 is on two workloads")
	require.Equal(t, "CVE-2026-0001", adv.Rows[0].Key)

	// keyset: 5 advisory groups, 2 a page
	var seen []string
	after, pages := "", 0
	for {
		p, err := s.FindingGroups(ctx, FindingQuery{Limit: 2, After: after}, GroupAdvisory)
		require.NoError(t, err)
		require.Equal(t, 5, p.Groups)
		for _, r := range p.Rows {
			seen = append(seen, r.Key)
		}
		pages++
		if after = p.Next; after == "" {
			break
		}
		_, err = s.FindingGroups(ctx, FindingQuery{Limit: 2, After: p.Next}, GroupWorkload)
		require.ErrorIs(t, err, ErrBadCursor)
	}
	require.Equal(t, 3, pages)
	var wantKeys []string
	for _, r := range adv.Rows {
		wantKeys = append(wantKeys, r.Key)
	}
	require.Equal(t, wantKeys, seen, "no group repeats or is skipped")
}

func TestFindingFacets_ExcludeOwnSelection(t *testing.T) {
	s := newStore(t)
	web, worker, backup := ref("Deployment", "shop", "web"), ref("Deployment", "shop", "worker"), ref("CronJob", "ops", "backup")
	resolved := func(days int) func(*model.Finding) {
		return func(f *model.Finding) {
			at := t0.Add(-time.Duration(days) * 24 * time.Hour)
			f.State, f.ResolvedAt = model.StateResolved, &at
		}
	}
	apply(t, s,
		uiFinding(web, "ghcr.io/example/web", "CVE-2026-0001", model.PriorityUrgent, func(f *model.Finding) {
			f.FixAvailable, f.Fix = true, &model.FixAction{Kind: model.FixKindRebuild, Key: "rebuild:debian:12", Label: "debian 12 rebuild"}
			f.Signals = model.FindingSignals{Exposed: true, KEV: true}
		}),
		uiFinding(web, "ghcr.io/example/web", "CVE-2026-0002", model.PriorityUrgent, func(f *model.Finding) { f.Signals.Exposed = true }),
		uiFinding(web, "ghcr.io/example/web", "CVE-2026-0003", model.PriorityHigh),
		uiFinding(worker, "ghcr.io/example/worker", "CVE-2026-0004", model.PriorityUrgent, func(f *model.Finding) {
			f.State, f.ExceptedBy = model.StateExcepted, "shop/accepted"
		}),
		uiFinding(web, "ghcr.io/example/web", "CVE-2026-0005", model.PriorityUrgent, resolved(10)),
		uiFinding(web, "ghcr.io/example/web", "CVE-2026-0006", model.PriorityUrgent, resolved(40)),
		uiFinding(backup, "ghcr.io/example/backup", "CVE-2026-0007", model.PriorityUrgent),
		uiFinding(backup, "ghcr.io/example/backup", "CVE-2026-0008", model.PriorityMedium),
		uiFinding(backup, "ghcr.io/example/backup", "CVE-2026-0009", model.PriorityMedium),
	)
	q := FindingQuery{Priorities: []model.Priority{model.PriorityUrgent}, Namespaces: []string{"shop"}, ResolvedSince: t0.Add(-30 * 24 * time.Hour)}
	got, err := s.FindingFacets(ctx, q, []FindingFacet{FacetPriority, FacetNamespace, FacetFix, FacetKind, FacetState, FacetSignal})
	require.NoError(t, err)
	type fv = FacetValue
	require.Equal(t, []fv{{"urgent", 2}, {"high", 1}, {"low", 0}, {"medium", 0}}, got[FacetPriority])
	require.Equal(t, []fv{{"shop", 2}, {"ops", 1}}, got[FacetNamespace])
	require.Equal(t, []fv{{"fixed", 1}, {"none", 1}, {"upgrade", 0}, {"wontfix", 0}}, got[FacetFix])
	require.Equal(t, []fv{{"Deployment", 2}}, got[FacetKind])
	require.Equal(t, []fv{{"open", 2}, {"excepted", 1}, {"resolved", 1}}, got[FacetState])
	require.Equal(t, []fv{{"exposed", 2}, {"exploited", 1}, {"epss", 0}, {"malicious", 0}, {"not_running", 0}, {"privileged", 0},
		{"provisional", 0}, {"sa_power", 0}}, got[FacetSignal])
	require.Len(t, got[FacetSignal], len(model.Signals))

	// the signal facet ignores the signal selection but keeps every other one
	withSignal := q
	withSignal.Signals = []model.Signal{model.SignalExploited}
	got, err = s.FindingFacets(ctx, withSignal, []FindingFacet{FacetSignal, FacetPriority})
	require.NoError(t, err)
	require.Equal(t, 2, got[FacetSignal][0].Count)
	require.Equal(t, []fv{{"urgent", 1}, {"high", 0}, {"low", 0}, {"medium", 0}}, got[FacetPriority])

	_, err = s.FindingFacets(ctx, q, []FindingFacet{"colour"})
	require.ErrorContains(t, err, "colour")

	// namespace: the top 50 by count plus a selected namespace with the smallest count
	many := newStore(t)
	var fs []model.Finding
	for i := range 55 {
		o := ref("Deployment", fmt.Sprintf("ns-%02d", i), "app")
		for j := range i + 1 {
			fs = append(fs, uiFinding(o, "ghcr.io/example/app", fmt.Sprintf("CVE-2026-%04d", j), model.PriorityLow))
		}
	}
	apply(t, many, fs...)
	got, err = many.FindingFacets(ctx, FindingQuery{Namespaces: []string{"ns-00"}}, []FindingFacet{FacetNamespace})
	require.NoError(t, err)
	nsVals := got[FacetNamespace]
	require.Len(t, nsVals, 51)
	require.Equal(t, FacetValue{Value: "ns-54", Count: 55}, nsVals[0])
	require.Equal(t, FacetValue{Value: "ns-05", Count: 6}, nsVals[49])
	require.Equal(t, FacetValue{Value: "ns-00", Count: 1}, nsVals[50])
	require.True(t, slices.IsSortedFunc(nsVals, func(a, b FacetValue) int { return b.Count - a.Count }))
}

// requireIndexOnly asserts that st reads findings only through index: its plan names the index,
// and its EXPLAIN bytecode has no Column read on a cursor opened on the findings table's root page
// and no json_extract call.
func requireIndexOnly(t *testing.T, s *Store, index string, st stmt, name string) {
	t.Helper()
	var root int64
	require.NoError(t, s.rdb.QueryRowContext(ctx, `SELECT rootpage FROM sqlite_schema WHERE type = 'table' AND name = 'findings'`).Scan(&root))
	require.Contains(t, queryPlan(t, s, st.query, st.args...), "INDEX "+index, name)
	rows, err := s.rdb.QueryContext(ctx, `EXPLAIN `+st.query, st.args...)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	type op struct {
		opcode string
		p1, p2 int64
		p4     string
	}
	var ops []op
	for rows.Next() {
		var (
			addr, p1, p2, p3 int64
			opcode           string
			p4, p5, comment  any
		)
		require.NoError(t, rows.Scan(&addr, &opcode, &p1, &p2, &p3, &p4, &p5, &comment))
		ops = append(ops, op{opcode, p1, p2, fmt.Sprint(p4)})
	}
	require.NoError(t, rows.Err())
	tables := map[int64]bool{}
	for _, o := range ops {
		if o.opcode == "OpenRead" && o.p2 == root {
			tables[o.p1] = true
		}
	}
	for _, o := range ops {
		require.False(t, o.opcode == "Column" && tables[o.p1], "%s reads a findings column: %s", name, st.query)
		require.NotContains(t, o.p4, "json_extract", name)
	}
}

func TestFindingFacets_UseCoveringIndex(t *testing.T) {
	s := newStore(t)
	seedFindingsExplorer(t, s)
	web := model.Scope{Kind: model.ScopeWorkload, Value: "Deployment/shop/web"}
	for name, q := range map[string]FindingQuery{
		"default": {},
		"every coverable filter": {States: []model.FindingState{model.StateOpen, model.StateExcepted}, Scope: web,
			Priorities: []model.Priority{model.PriorityUrgent, model.PriorityHigh}, Fix: []model.FixClass{model.FixClassFixed, model.FixClassNone},
			Signals: []model.Signal{model.SignalExposed}, Ecosystems: []string{"deb"}, Namespaces: []string{"shop"},
			Kinds: []string{"Deployment"}, Advisory: "CVE-2026-0001"},
		"namespace":     {Scope: model.Scope{Kind: model.ScopeNamespace, Value: "shop"}},
		"control plane": {Scope: model.Scope{Kind: model.ScopeControlPlane}},
	} {
		cnt, err := findingCountStmt(q)
		require.NoError(t, err)
		require.True(t, cnt.indexOnly, name)
		requireIndexOnly(t, s, "findings_groups", cnt, name+" count")
		var notIndexOnly []string
		for _, f := range []FindingFacet{FacetState, FacetPriority, FacetFix, FacetSignal, FacetEcosystem, FacetNamespace, FacetKind} {
			stmts, err := findingFacetStmts(q, f)
			require.NoError(t, err)
			for _, st := range stmts {
				if !st.indexOnly {
					notIndexOnly = append(notIndexOnly, string(f)+": "+st.query)
					continue
				}
				requireIndexOnly(t, s, "findings_groups", st, name+" "+string(f))
			}
		}
		require.Len(t, notIndexOnly, 1, name)
		require.True(t, strings.HasPrefix(notIndexOnly[0], "state: SELECT 'resolved'"), notIndexOnly[0])
	}

	// not coverable: the planner chooses, and findings_groups is not named
	for _, q := range []FindingQuery{{Q: "web"}, {Repo: "ghcr.io/example/web"}, {Package: "openssl"}, {FixKey: "none"},
		{Scope: model.Scope{Kind: model.ScopeImage, Value: "sha256:web"}}, {States: []model.FindingState{model.StateResolved}}} {
		cnt, err := findingCountStmt(q)
		require.NoError(t, err)
		require.False(t, cnt.indexOnly)
		require.NotContains(t, cnt.query, "INDEXED BY")
	}
}

func TestTransitionsPage_ScopesNewestFirst(t *testing.T) {
	s := newStore(t)
	web, worker, cluster := ref("Deployment", "shop", "web"), ref("Deployment", "shop", "worker"), ref("Cluster", "", testCluster)
	tr := func(o model.OwnerRef, advisory string, at time.Time) model.Transition {
		return model.Transition{Fingerprint: model.FindingFingerprint(testCluster, o, "ghcr.io/example/"+o.Name, advisory), Owner: o,
			AdvisoryID: advisory, ToState: model.StateOpen, ToPriority: model.PriorityHigh, Trigger: model.TriggerNewAdvisory, At: at}
	}
	require.NoError(t, s.ApplyFindings(ctx, nil, []model.Transition{
		tr(web, "CVE-2026-0001", t0.Add(-40*24*time.Hour)), // id 1, older than 30 days
		tr(web, "CVE-2026-0002", t0.Add(-5*time.Hour)),     // id 2
		tr(worker, "CVE-2026-0003", t0.Add(-4*time.Hour)),  // id 3
		tr(cluster, "CVE-2026-0004", t0.Add(-3*time.Hour)), // id 4
		tr(web, "CVE-2026-0005", t0.Add(-2*time.Hour)),     // id 5
		tr(web, "CVE-2026-0006", t0.Add(-1*time.Hour)),     // id 6
	}))
	idsOf := func(ts []model.Transition) []int64 {
		out := make([]int64, len(ts))
		for i, x := range ts {
			out[i] = x.ID
		}
		return out
	}
	scope := func(s string) model.Scope {
		sc, err := model.ParseScope(s)
		require.NoError(t, err)
		return sc
	}

	p, err := s.TransitionsPage(ctx, scope("workload:Deployment/shop/web"), "", 2)
	require.NoError(t, err)
	require.Equal(t, []int64{6, 5}, idsOf(p.Rows))
	require.Equal(t, "CVE-2026-0006", p.Rows[0].AdvisoryID)
	require.NotEmpty(t, p.Next)
	p, err = s.TransitionsPage(ctx, scope("workload:Deployment/shop/web"), p.Next, 2)
	require.NoError(t, err)
	require.Equal(t, []int64{2, 1}, idsOf(p.Rows))
	require.Empty(t, p.Next)

	p, err = s.TransitionsPage(ctx, scope("namespace:shop"), "", 0)
	require.NoError(t, err)
	require.Equal(t, []int64{6, 5, 3, 2, 1}, idsOf(p.Rows))
	p, err = s.TransitionsPage(ctx, scope("controlplane"), "", 0)
	require.NoError(t, err)
	require.Equal(t, []int64{4}, idsOf(p.Rows))
	p, err = s.TransitionsPage(ctx, scope("cluster"), "", 0)
	require.NoError(t, err)
	require.Equal(t, []int64{6, 5, 4, 3, 2, 1}, idsOf(p.Rows))

	_, err = s.TransitionsPage(ctx, scope("image:sha256:web"), "", 0)
	require.ErrorIs(t, err, ErrScope)
	_, err = s.TransitionsPage(ctx, scope("cluster"), encodeCursor("-priority", []any{int64(1)}), 0)
	require.ErrorIs(t, err, ErrBadCursor)

	n, err := s.TransitionCount(ctx, scope("workload:Deployment/shop/web"), t0.Add(-30*24*time.Hour))
	require.NoError(t, err)
	require.Equal(t, 3, n)
	n, err = s.TransitionCount(ctx, scope("controlplane"), t0.Add(-30*24*time.Hour))
	require.NoError(t, err)
	require.Equal(t, 1, n)
	_, err = s.TransitionCount(ctx, scope("nodegroup:g1"), t0)
	require.ErrorIs(t, err, ErrScope)
}

func TestFindingsExploreIndexIsDropped(t *testing.T) {
	s := newStore(t)
	var n int
	require.NoError(t, s.rdb.QueryRowContext(ctx,
		`SELECT count(*) FROM sqlite_schema WHERE type = 'index' AND name IN ('findings_explore', 'findings_groups')`).Scan(&n))
	require.Equal(t, 1, n, "findings_groups serves what findings_explore did (060)")
}
