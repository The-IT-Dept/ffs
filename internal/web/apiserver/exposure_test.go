package apiserver_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/web/apigen"
	"github.com/the-it-dept/ffs/internal/web/webtest"
)

func rowIDs(rows []apigen.ExposureRow) []string {
	out := []string{}
	for _, r := range rows {
		out = append(out, r.Id)
	}
	return out
}

func rowByID(t *testing.T, rows []apigen.ExposureRow, id string) apigen.ExposureRow {
	t.Helper()
	for _, r := range rows {
		if r.Id == id {
			return r
		}
	}
	require.Failf(t, "row missing", "%s in %v", id, rowIDs(rows))
	return apigen.ExposureRow{}
}

// childLabels are the labels of the rows under parent, in order.
func childLabels(rows []apigen.ExposureRow, parent string) []string {
	out := []string{}
	for _, r := range rows {
		if r.Parent != nil && *r.Parent == parent {
			out = append(out, r.Label)
		}
	}
	return out
}

// topIDs are the ids of the depth-0 rows, in order.
func topIDs(rows []apigen.ExposureRow) []string {
	out := []string{}
	for _, r := range rows {
		if r.Depth == apigen.ExposureRowDepthN0 {
			out = append(out, r.Id)
		}
	}
	return out
}

func TestExposure_EntryGroupsAndInternal(t *testing.T) {
	_, h := newAPI(t)
	got := ok[apigen.ExposureTable](t, get(t, h, "/api/v1/exposure"))
	require.Equal(t, apigen.ExposureGroupEntry, got.Group)
	require.Equal(t, []string{"gw:gateway/public", "gw:gateway/public/shop.example.com", "host", "host/DaemonSet/ops/node-exporter",
		"nodes", "nodes/worker-1", "internal", "internal/gateway:gateway/internal/api.payments.example.com", "not-exposed"},
		rowIDs(got.Rows))

	gw := got.Rows[0]
	require.Equal(t, "Internet → Gateway gateway/public", gw.Label)
	require.Equal(t, "1 hostname · public", *gw.Detail)
	require.Equal(t, 1, *gw.Hostnames)
	require.Equal(t, apigen.EntryKindGateway, *gw.Entry)
	require.Equal(t, apigen.ExposureRowDepthN0, gw.Depth)
	require.Equal(t, apigen.ExposureRowKindEntry, gw.Kind)

	hn := got.Rows[1]
	require.Equal(t, apigen.ExposureRowDepthN1, hn.Depth)
	require.Equal(t, "gw:gateway/public", *hn.Parent)
	require.Equal(t, apigen.ExposureRowKindHostname, hn.Kind)
	require.Equal(t, "shop.example.com", hn.Label)
	require.Equal(t, "shop", *hn.Detail)
	require.Equal(t, []apigen.WorkloadRef{{Scope: "workload:Deployment/shop/web", Kind: "Deployment", Namespace: "shop", Name: "web"}},
		hn.Workloads)
	require.Zero(t, hn.MoreWorkloads)
	sig := hn.Signals
	require.Equal(t, 1, sig.Urgent)
	require.Equal(t, 1, sig.High)
	require.Equal(t, 2, sig.Fixable)
	require.Equal(t, 1, sig.Exploited)
	require.Equal(t, 0, *sig.Privileged)
	require.Equal(t, 0, *sig.SaPower)
	require.Equal(t, apigen.CoverageFigure{InUse: 2, SeenInto: 1, Full: 1}, sig.Coverage)
	require.NotNil(t, sig.BestFix)
	require.Equal(t, apigen.FixKindUpgrade, sig.BestFix.Kind)
	require.Equal(t, &apigen.ScopeRef{Scope: "workload:Deployment/shop/web", Kind: apigen.ScopeKindWorkload, Label: "web"}, hn.Target)

	require.Equal(t, "Node network (hostNetwork / hostPort)", rowByID(t, got.Rows, "host").Label)
	exporter := rowByID(t, got.Rows, "host/DaemonSet/ops/node-exporter")
	require.Equal(t, "node-exporter", exporter.Label)
	require.Equal(t, apigen.EntryKindHostnetwork, *exporter.Entry)
	nodes := rowByID(t, got.Rows, "nodes")
	require.Equal(t, "Exposed nodes", nodes.Label)
	require.Equal(t, 1, nodes.Signals.High)
	w1 := rowByID(t, got.Rows, "nodes/worker-1")
	require.Nil(t, w1.Signals.Privileged)
	require.Nil(t, w1.Signals.SaPower)
	require.Equal(t, apigen.ExposureRowKindNode, w1.Kind)
	require.Equal(t, 1, w1.Signals.High)
	require.Equal(t, "node:worker-1", w1.Target.Scope)

	internal := rowByID(t, got.Rows, "internal")
	require.True(t, internal.Internal)
	require.Equal(t, "Internal entry points", internal.Label)
	ic := rowByID(t, got.Rows, "internal/gateway:gateway/internal/api.payments.example.com")
	require.True(t, ic.Internal)
	require.Equal(t, "api.payments.example.com", ic.Label)

	ne := rowByID(t, got.Rows, "not-exposed")
	require.Equal(t, "Not exposed", ne.Label)
	require.True(t, ne.Collapsed)
	require.True(t, ne.Expandable)
	require.Empty(t, childLabels(got.Rows, "not-exposed"))
	require.Equal(t, 0, ne.Signals.Urgent)
	require.Equal(t, 1, ne.Signals.High)
	require.Equal(t, 3, ne.Signals.Fixable)
	require.Equal(t, 1, ne.Signals.Exploited)
	require.Equal(t, 1, *ne.Signals.Privileged)
	require.Equal(t, 1, *ne.Signals.SaPower)
	require.Equal(t, 1, got.MaxUrgent)

	expanded := ok[apigen.ExposureTable](t, get(t, h, "/api/v1/exposure?expand=not-exposed"))
	require.False(t, rowByID(t, expanded.Rows, "not-exposed").Collapsed)
	require.Equal(t, []string{"api", "backup", "worker", "coredns", "report"}, childLabels(expanded.Rows, "not-exposed"))
}

func TestExposure_FoldsTailAndExpands(t *testing.T) {
	f := webtest.Open(t)
	ctx := t.Context()
	for i := 1; i <= 12; i++ {
		name := fmt.Sprintf("app-%02d", i)
		ref := model.OwnerRef{Kind: "Deployment", Namespace: "shop", Name: name}
		path := "HTTPRoute shop/" + name + " on Gateway gateway/public"
		require.NoError(t, f.Store.UpsertOwner(ctx, model.Owner{Ref: ref, ServiceAccount: "default", UpdatedAt: webtest.Now,
			Context: model.WorkloadContext{Exposed: true, ExposurePaths: []string{path}, Exposure: []model.ExposureEdge{{
				Entry: model.EntryGateway, EntryName: "gateway/public", Hostname: name + ".example.com", Route: "HTTPRoute shop/" + name,
				Service: "shop/" + name, Path: path}}}}))
		if i == 12 {
			require.NoError(t, f.Store.ApplyFindings(ctx, []model.Finding{{
				Fingerprint: model.FindingFingerprint(webtest.ClusterName, ref, "ghcr.io/example/app", "CVE-2026-0001"), Owner: ref,
				ImageRepo: "ghcr.io/example/app", AdvisoryID: "CVE-2026-0001", State: model.StateOpen, Priority: model.PriorityUrgent,
				Severity: model.SeverityCritical, Digests: []string{"sha256:app"}, LastSeen: webtest.Now,
			}}, nil))
		}
	}
	h := handlerOf(f)
	got := ok[apigen.ExposureTable](t, get(t, h, "/api/v1/exposure"))
	gw := rowByID(t, got.Rows, "gw:gateway/public")
	require.Equal(t, "13 hostnames · public", *gw.Detail)
	require.Equal(t, 13, *gw.Hostnames)
	require.True(t, gw.Expandable)
	require.Equal(t, []string{"shop.example.com", "app-12.example.com", "app-01.example.com", "app-02.example.com", "app-03.example.com",
		"app-04.example.com", "app-05.example.com", "app-06.example.com", "5 more hostnames"}, childLabels(got.Rows, "gw:gateway/public"))
	tail := rowByID(t, got.Rows, "gw:gateway/public/tail")
	require.Equal(t, apigen.ExposureRowKindTail, tail.Kind)
	require.Equal(t, "5 more hostnames", tail.Label)
	require.Equal(t, "nothing above low", *tail.Detail)
	require.True(t, tail.Expandable)
	require.Equal(t, apigen.ExposureRowDepthN1, tail.Depth)

	got = ok[apigen.ExposureTable](t, get(t, h, "/api/v1/exposure?expand=gw:gateway/public"))
	labels := childLabels(got.Rows, "gw:gateway/public")
	require.Len(t, labels, 13)
	require.NotContains(t, rowIDs(got.Rows), "gw:gateway/public/tail")
	for _, r := range got.Rows {
		if r.Parent != nil && *r.Parent == "gw:gateway/public" {
			require.Equal(t, apigen.ExposureRowKindHostname, r.Kind, r.Id)
		}
	}
}

func TestExposure_NamespaceAndNodeRegroup(t *testing.T) {
	_, h := newAPI(t)
	got := ok[apigen.ExposureTable](t, get(t, h, "/api/v1/exposure?group=namespace"))
	require.Equal(t, apigen.ExposureGroupNamespace, got.Group)
	require.Equal(t, []string{"ns:shop", "ns:ops", "ns:payments", "ns:kube-system"}, topIDs(got.Rows))
	require.Equal(t, []string{"web", "worker"}, childLabels(got.Rows, "ns:shop"))
	shop := rowByID(t, got.Rows, "ns:shop")
	require.Equal(t, apigen.ExposureRowKindNamespace, shop.Kind)
	require.Equal(t, "namespace:shop", shop.Target.Scope)

	got = ok[apigen.ExposureTable](t, get(t, h, "/api/v1/exposure?group=node"))
	cp := got.Rows[0]
	require.Equal(t, apigen.ExposureRowKindControlplane, cp.Kind)
	require.Equal(t, "Control plane", cp.Label)
	require.Equal(t, 1, cp.Signals.High)
	require.Nil(t, cp.Signals.Privileged)
	require.Nil(t, cp.Signals.SaPower)
	require.Equal(t, &apigen.ScopeRef{Scope: "controlplane", Kind: apigen.ScopeKindControlplane, Label: "Control plane"}, cp.Target)
	require.Equal(t, []string{"controlplane", "ng:" + webtest.AgentGroupID, "ng:" + webtest.CP1GroupID}, topIDs(got.Rows))
	require.Equal(t, []string{"worker-1", "worker-2"}, childLabels(got.Rows, "ng:"+webtest.AgentGroupID))
	require.Equal(t, []string{"cp-1"}, childLabels(got.Rows, "ng:"+webtest.CP1GroupID))
	ag := rowByID(t, got.Rows, "ng:"+webtest.AgentGroupID)
	require.Equal(t, apigen.ExposureRowKindNodegroup, ag.Kind)
	require.Equal(t, 1, ag.Signals.High)
	require.Equal(t, "nodegroup:"+webtest.AgentGroupID, ag.Target.Scope)

	wantProblem(t, get(t, h, "/api/v1/exposure?group=node&scope=namespace:shop"), 400, apigen.ProblemCodeInvalidParameter)
	wantProblem(t, get(t, h, "/api/v1/exposure?scope=workload:Deployment/shop/web"), 400, apigen.ProblemCodeInvalidScope)
}
