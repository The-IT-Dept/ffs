package store

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/the-it-dept/ffs/internal/model"
	"github.com/the-it-dept/ffs/internal/nodegroup"
)

// ErrNodeGroupNotFound means no node group is stored under the requested ID.
var ErrNodeGroupNotFound = errors.New("store: node group not found")

// NodeGroups returns the node groups with at least one member, with Members filled: agent groups
// first, then nodeinfo groups, each ordered by Label and then ID.
func (s *Store) NodeGroups(ctx context.Context) ([]model.NodeGroup, error) {
	groups, err := queryAll(ctx, s.rdb, scanNodeGroup, `SELECT `+nodeGroupCols+` FROM node_groups
		WHERE id IN (SELECT group_id FROM node_group_members)`)
	if err != nil {
		return nil, err
	}
	members, err := s.groupMembers(ctx, "")
	if err != nil {
		return nil, err
	}
	for i := range groups {
		groups[i].Members = members[groups[i].ID]
	}
	slices.SortFunc(groups, func(a, b model.NodeGroup) int {
		return cmp.Or(cmp.Compare(kindRank(a.Kind), kindRank(b.Kind)), strings.Compare(a.Label, b.Label), strings.Compare(a.ID, b.ID))
	})
	return groups, nil
}

// kindRank orders agent groups before nodeinfo groups.
func kindRank(k model.NodeGroupKind) int {
	switch k {
	case model.NodeGroupAgent:
		return 0
	case model.NodeGroupNodeInfo:
		return 1
	}
	return 2
}

// groupMembers returns the sorted members of every group, or of the one group id when it is not "".
func (s *Store) groupMembers(ctx context.Context, id string) (map[string][]string, error) {
	type member struct{ node, group string }
	scan := func(r scanner) (member, error) {
		var m member
		err := r.Scan(&m.node, &m.group)
		return m, err
	}
	var w where
	if id != "" {
		w.add(`group_id = ?`, id)
	}
	rows, err := queryAll(ctx, s.rdb, scan, `SELECT node, group_id FROM node_group_members`+w.String()+` ORDER BY node`, w.args...)
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, m := range rows {
		out[m.group] = append(out[m.group], m.node)
	}
	return out, nil
}

// NodeGroup returns the group stored under id, memberless groups included, with Members filled.
func (s *Store) NodeGroup(ctx context.Context, id string) (model.NodeGroup, bool, error) {
	g, ok, err := nodeGroupRow(ctx, s.rdb, id)
	if err != nil || !ok {
		return model.NodeGroup{}, false, err
	}
	members, err := s.groupMembers(ctx, id)
	if err != nil {
		return model.NodeGroup{}, false, err
	}
	g.Members = members[id]
	return g, true, nil
}

// NodeGroupOfNode returns node's group. It is false when the node has no membership or its group
// has no row.
func (s *Store) NodeGroupOfNode(ctx context.Context, node string) (model.NodeGroup, bool, error) {
	ids, err := queryAll(ctx, s.rdb, scanString, `SELECT group_id FROM node_group_members WHERE node = ?`, node)
	if err != nil || len(ids) == 0 {
		return model.NodeGroup{}, false, err
	}
	return s.NodeGroup(ctx, ids[0])
}

// NodeDrift compares group toID with group fromID (nodegroup.Drift) over their stored host SBOMs. A
// group whose digest is empty or whose images row is not catalogued has no packages (nil); a
// catalogued SBOM without packages gives an empty slice. An unknown ID is ErrNodeGroupNotFound.
func (s *Store) NodeDrift(ctx context.Context, fromID, toID string) (model.NodeDrift, error) {
	var (
		groups [2]model.NodeGroup
		pkgs   [2][]model.Package
	)
	for i, id := range []string{fromID, toID} {
		g, ok, err := nodeGroupRow(ctx, s.rdb, id)
		if err != nil {
			return model.NodeDrift{}, err
		}
		if !ok {
			return model.NodeDrift{}, fmt.Errorf("%w: %s", ErrNodeGroupNotFound, id)
		}
		if pkgs[i], err = s.groupPackages(ctx, g.Digest); err != nil {
			return model.NodeDrift{}, err
		}
		groups[i] = g
	}
	return nodegroup.Drift(groups[0], groups[1], pkgs[0], pkgs[1]), nil
}

// groupPackages returns the packages stored for a group digest: nil unless the digest is a
// catalogued image, and a non-nil slice when it is.
func (s *Store) groupPackages(ctx context.Context, digest string) ([]model.Package, error) {
	if digest == "" {
		return nil, nil
	}
	img, ok, err := s.GetImage(ctx, digest)
	if err != nil || !ok || img.Status != model.ImageCatalogued {
		return nil, err
	}
	pkgs, err := s.PackagesForImage(ctx, digest)
	if err != nil {
		return nil, err
	}
	if pkgs == nil {
		pkgs = []model.Package{}
	}
	return pkgs, nil
}

// AgentStatus returns the agent status of every stored node, ordered by name.
//
// The state is disabled when the node agent is not enabled (no nodes_state row included), never
// without a report, stale when the last report is older than staleAfter at now (exactly staleAfter
// old is still reporting), else reporting. After the stored gaps:
//   - a reporting node whose host inventory is not stored or not current gets GapHostNotInventoried:
//     its host inventory is quarantined, its last full report's host part failed (last_error), it is
//     in no agent group yet, or its last full report is older than NodesState.FullReportOverdue;
//   - any other state adds GapNodeAgentUnsupported for a node in NodesState.Unsupported while the
//     agent is enabled, else GapNodeAgentMissing.
func (s *Store) AgentStatus(ctx context.Context, now time.Time, staleAfter time.Duration) ([]model.NodeAgentStatus, error) {
	return s.agentStatus(ctx, "", now, staleAfter)
}

// NodeAgentStatus returns the agent status of one stored node, as AgentStatus does; false when no
// node of that name is stored.
func (s *Store) NodeAgentStatus(ctx context.Context, node string, now time.Time, staleAfter time.Duration) (model.NodeAgentStatus, bool, error) {
	if node == "" {
		return model.NodeAgentStatus{}, false, nil
	}
	st, err := s.agentStatus(ctx, node, now, staleAfter)
	if err != nil || len(st) == 0 {
		return model.NodeAgentStatus{}, false, err
	}
	return st[0], true, nil
}

// agentStatus builds the agent status of every stored node, or of the one node when it is not "".
func (s *Store) agentStatus(ctx context.Context, node string, now time.Time, staleAfter time.Duration) ([]model.NodeAgentStatus, error) {
	state, err := s.NodesState(ctx)
	if err != nil {
		return nil, err
	}
	var w where
	if node != "" {
		w.add(`n.name = ?`, node)
	}
	type row struct{ name, group string }
	rows, err := queryAll(ctx, s.rdb, func(r scanner) (row, error) {
		var x row
		err := r.Scan(&x.name, &x.group)
		return x, err
	}, `SELECT n.name, COALESCE(m.group_id, '') FROM nodes n LEFT JOIN node_group_members m ON m.node = n.name`+
		w.String()+` ORDER BY n.name`, w.args...)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	var aw where
	if node != "" {
		aw.add(`node = ?`, node)
	}
	stored, err := queryAll(ctx, s.rdb, scanAgentNode, `SELECT `+agentNodeCols+` FROM nodes_agent`+aw.String(), aw.args...)
	if err != nil {
		return nil, err
	}
	agents := make(map[string]AgentNode, len(stored))
	for _, a := range stored {
		agents[a.Node] = a
	}
	quarantined, err := s.hostQuarantines(ctx, node, now)
	if err != nil {
		return nil, err
	}
	out := make([]model.NodeAgentStatus, 0, len(rows))
	for _, x := range rows {
		out = append(out, nodeAgentStatus(x.name, x.group, agents[x.name], state, quarantined[x.name], now, staleAfter))
	}
	return out, nil
}

// hostQuarantines returns the host-inventory jobs quarantined past now, by node: every node's, or the one
// node's when it is not "".
func (s *Store) hostQuarantines(ctx context.Context, node string, now time.Time) (map[string]AgentJob, error) {
	var w where
	w.add(`substr(digest, 1, ?) = ?`, len(agentHostJobPrefix), agentHostJobPrefix)
	w.add(`quarantined_until > ?`, nanos(now))
	if node != "" {
		w.add(`digest = ?`, agentHostJobPrefix+node)
	}
	jobs, err := queryAll(ctx, s.rdb, scanAgentJob, `SELECT `+agentJobCols+` FROM agent_jobs`+w.String(), w.args...)
	if err != nil {
		return nil, err
	}
	out := make(map[string]AgentJob, len(jobs))
	for _, j := range jobs {
		out[strings.TrimPrefix(j.Digest, agentHostJobPrefix)] = j
	}
	return out, nil
}

// Coverage gap details (copy).
const (
	detailAgentNeverReported = "node agent has not reported"
	detailAgentStaleFmt      = "node agent not reporting since %s"
	detailNotScheduledFmt    = "not scheduled by the node agent: %s"
	detailHostPending        = "host packages not inventoried yet"
	detailHostQuarantinedFmt = "host inventory quarantined until %s: %s"
	detailNoFullReportSince  = "no full host report since %s"
	detailNoFullReport       = "no full host report received"
)

// nodeAgentStatus derives one node's status from its nodes_agent row (zero when it never reported), the
// node-agent state and its host-inventory quarantine (zero when none is active).
func nodeAgentStatus(node, groupID string, a AgentNode, state NodesState, quarantine AgentJob, now time.Time,
	staleAfter time.Duration) model.NodeAgentStatus {
	st := model.NodeAgentStatus{Node: node, AgentVersion: a.AgentVersion, BootID: a.BootID, LastReport: a.LastReport,
		LastFullReport: a.LastFullReport, LastError: a.LastError, GroupID: groupID, KernelRelease: a.KernelRelease,
		RebootPending: a.RebootPending, RebootReason: a.RebootReason, Coverage: slices.Clone(a.Coverage), Problems: a.Problems}
	switch {
	case !state.AgentEnabled:
		st.State = model.AgentDisabled
	case a.LastReport.IsZero():
		st.State = model.AgentNever
	case a.LastReport.Before(now.Add(-staleAfter)):
		st.State = model.AgentStale
	default:
		st.State = model.AgentReporting
	}
	if st.State == model.AgentReporting {
		if detail, ok := hostNotInventoried(a, state, quarantine, now); ok {
			st.Coverage = append(st.Coverage, model.NodeCoverageGap{Code: model.GapHostNotInventoried, Detail: detail})
		}
		return st
	}
	if why, ok := state.Unsupported[node]; ok && state.AgentEnabled {
		st.Coverage = append(st.Coverage, model.NodeCoverageGap{Code: model.GapNodeAgentUnsupported,
			Detail: fmt.Sprintf(detailNotScheduledFmt, why)})
		return st
	}
	detail := detailAgentNeverReported
	if !a.LastReport.IsZero() {
		detail = fmt.Sprintf(detailAgentStaleFmt, a.LastReport.UTC().Format(time.RFC3339))
	}
	st.Coverage = append(st.Coverage, model.NodeCoverageGap{Code: model.GapNodeAgentMissing, Detail: detail})
	return st
}

// hostNotInventoried says why a reporting node's host inventory is not stored or not current, if it is not.
func hostNotInventoried(a AgentNode, state NodesState, quarantine AgentJob, now time.Time) (string, bool) {
	switch {
	case quarantine.QuarantinedUntil.After(now):
		return fmt.Sprintf(detailHostQuarantinedFmt, quarantine.QuarantinedUntil.UTC().Format(time.RFC3339), quarantine.LastError), true
	case a.LastError != "":
		return a.LastError, true
	case a.GroupID == "":
		return detailHostPending, true
	case state.FullReportOverdue > 0 && a.LastFullReport.IsZero():
		return detailNoFullReport, true
	case state.FullReportOverdue > 0 && a.LastFullReport.Before(now.Add(-state.FullReportOverdue)):
		return fmt.Sprintf(detailNoFullReportSince, a.LastFullReport.UTC().Format(time.RFC3339)), true
	}
	return "", false
}

// NodeImages returns the images cached on node, ordered by digest. Status and StatusReason come
// from the images row of the image digest, else of the config digest.
func (s *Store) NodeImages(ctx context.Context, node string) ([]model.NodeImage, error) {
	return s.queryNodeImages(ctx, []string{node})
}

// NodeGroupImages returns the union of the images cached on groupID's members, ordered by digest:
// InUse and Complete OR'd, Names the sorted union, SizeBytes the largest, Kind, ConfigDigest and
// Status the first non-empty in node order, Source the common value or "both", and Nodes the sorted
// holders. An unknown or memberless group has none.
func (s *Store) NodeGroupImages(ctx context.Context, groupID string) ([]model.NodeImage, error) {
	if groupID == "" {
		return nil, nil
	}
	members, err := s.groupMembers(ctx, groupID)
	if err != nil || len(members[groupID]) == 0 {
		return nil, err
	}
	rows, err := s.queryNodeImages(ctx, members[groupID])
	if err != nil {
		return nil, err
	}
	var out []model.NodeImage
	for _, img := range rows { // ordered by digest, then node
		if len(out) == 0 || out[len(out)-1].Digest != img.Digest {
			out = append(out, img)
			continue
		}
		u := &out[len(out)-1]
		u.InUse = u.InUse || img.InUse
		u.Complete = u.Complete || img.Complete
		u.Names = append(u.Names, img.Names...)
		u.SizeBytes = max(u.SizeBytes, img.SizeBytes)
		u.Kind = cmp.Or(u.Kind, img.Kind)
		u.ConfigDigest = cmp.Or(u.ConfigDigest, img.ConfigDigest)
		if u.Status == "" {
			u.Status, u.StatusReason = img.Status, img.StatusReason
		}
		if u.Source != img.Source {
			u.Source = "both"
		}
		u.Nodes = append(u.Nodes, img.Nodes...)
	}
	for i := range out {
		slices.Sort(out[i].Names)
		out[i].Names = slices.Compact(out[i].Names)
	}
	return out, nil
}

// queryNodeImages reads the node_images rows of nodes, ordered by digest and then node, each with
// Nodes [node] and the status of its images row.
func (s *Store) queryNodeImages(ctx context.Context, nodes []string) ([]model.NodeImage, error) {
	return queryAll(ctx, s.rdb, func(r scanner) (model.NodeImage, error) {
		var (
			img         model.NodeImage
			node, names string
			status      string
		)
		if err := r.Scan(&node, &img.Digest, &img.ConfigDigest, &img.Kind, &names, &img.SizeBytes, &img.Complete,
			&img.InUse, &img.Source, &status, &img.StatusReason); err != nil {
			return model.NodeImage{}, err
		}
		var err error
		if img.Names, err = textStrings(names); err != nil {
			return model.NodeImage{}, fmt.Errorf("node %s image %s names: %w", node, img.Digest, err)
		}
		img.Status, img.Nodes = model.ImageStatus(status), []string{node}
		return img, nil
	}, `SELECT n.node, n.digest, n.config_digest, n.kind, n.names, n.size_bytes, n.complete, n.in_use, n.source,
		CASE WHEN i.digest IS NOT NULL THEN i.status WHEN c.digest IS NOT NULL THEN c.status ELSE '' END,
		CASE WHEN i.digest IS NOT NULL THEN i.status_reason WHEN c.digest IS NOT NULL THEN c.status_reason ELSE '' END
		FROM node_images n
		LEFT JOIN images i ON i.digest = n.digest
		LEFT JOIN images c ON n.config_digest <> '' AND c.digest = n.config_digest
		WHERE n.node IN (SELECT value FROM json_each(?)) ORDER BY n.digest, n.node`, idList(nodes))
}
