package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/the-it-dept/ffs/internal/model"
)

// agentHostJobPrefix starts the agent_jobs key of a node's host inventory: "nodehost:<node>".
const agentHostJobPrefix = "nodehost:"

// AgentReport is one agent report as the store applies it.
type AgentReport struct {
	Node, AgentVersion, BootID string
	Instance                   string    // random per agent process start; with BootID and Seq it orders reports
	StartedAt                  time.Time // when the reporting agent process started; orders only reports without an Instance
	Seq                        uint64    // per-process report counter, starting at 1
	At                         time.Time // when the report was received; zero means now
	// Full is false for an images-only report, whose host fields below are ignored.
	Full                           bool
	KernelRelease, Arch, PackageDB string
	RebootPending                  bool
	RebootReason                   string
	// Coverage is the node's coverage gaps after this report, written for every applied report: the
	// caller carries the last full report's host gaps into an images-only report.
	Coverage []model.NodeCoverageGap
	Problems []string
}

// DuplicateOf reports whether r is a duplicate or stale report given the node's stored row: the same
// boot and the same agent process (Instance) as the stored report, with a sequence number no higher
// than the stored one. A report of another boot, or of another process of the same boot (a newer
// one: the older has exited), is never a duplicate and starts a new sequence. The wall clock, which
// can step back, never orders reports of agents that send an Instance.
//
// An agent older than the Instance field sends none. Its processes of the same boot are told apart by
// StartedAt: a report from a process that started earlier than the stored one is stale, and one from
// the same process is a duplicate unless its sequence number is higher.
func (r AgentReport) DuplicateOf(n AgentNode) bool {
	if n.BootID != r.BootID {
		return false
	}
	if r.Instance == "" {
		return r.StartedAt.Before(n.StartedAt) || r.StartedAt.Equal(n.StartedAt) && r.Seq <= n.Seq
	}
	return n.Instance == r.Instance && r.Seq <= n.Seq
}

// AgentNode is one nodes_agent row.
type AgentNode struct {
	Node, AgentVersion, BootID string
	Instance                   string
	StartedAt                  time.Time
	Seq                        uint64
	LastReport, LastFullReport time.Time
	LastError                  string
	KernelRelease, Arch        string
	PackageDB                  string
	Fingerprint                string // host fingerprint whose group SBOM is stored; written only by SetAgentFingerprint
	GroupID                    string // the node's agent group; "" outside an agent group; written only by ApplyNodeGrouping
	RebootPending              bool
	RebootReason               string
	Coverage                   []model.NodeCoverageGap
	Problems                   []string
}

const agentNodeCols = `node, agent_version, boot_id, instance, started_at, seq, last_report, last_full_report, last_error,
	kernel_release, arch, package_db, fingerprint, group_id, reboot_pending, reboot_reason, coverage, problems`

func scanAgentNode(r scanner) (AgentNode, error) {
	var (
		n                       AgentNode
		started, last, lastFull sql.NullInt64
		seq                     int64
		coverage, problems      string
	)
	if err := r.Scan(&n.Node, &n.AgentVersion, &n.BootID, &n.Instance, &started, &seq, &last, &lastFull, &n.LastError,
		&n.KernelRelease, &n.Arch, &n.PackageDB, &n.Fingerprint, &n.GroupID, &n.RebootPending, &n.RebootReason,
		&coverage, &problems); err != nil {
		return AgentNode{}, err
	}
	n.StartedAt, n.LastReport, n.LastFullReport = fromNanos(started), fromNanos(last), fromNanos(lastFull)
	n.Seq = uint64(seq)
	if err := json.Unmarshal([]byte(coverage), &n.Coverage); err != nil {
		return AgentNode{}, fmt.Errorf("node %s coverage: %w", n.Node, err)
	}
	if len(n.Coverage) == 0 {
		n.Coverage = nil
	}
	var err error
	if n.Problems, err = textStrings(problems); err != nil {
		return AgentNode{}, fmt.Errorf("node %s problems: %w", n.Node, err)
	}
	return n, nil
}

func agentNodeOf(ctx context.Context, q querier, node string) (AgentNode, bool, error) {
	n, err := scanAgentNode(q.QueryRowContext(ctx, `SELECT `+agentNodeCols+` FROM nodes_agent WHERE node = ?`, node))
	if errors.Is(err, sql.ErrNoRows) {
		return AgentNode{}, false, nil
	}
	return n, err == nil, err
}

// AgentNodes returns every nodes_agent row, ordered by node.
func (s *Store) AgentNodes(ctx context.Context) ([]AgentNode, error) {
	return queryAll(ctx, s.rdb, scanAgentNode, `SELECT `+agentNodeCols+` FROM nodes_agent ORDER BY node`)
}

// WriteChanges returns how many rows the writer connection has inserted, updated or deleted since it
// opened (SQLite total_changes), so a caller can tell whether a pass wrote anything.
func (s *Store) WriteChanges(ctx context.Context) (int64, error) {
	var n int64
	err := s.wdb.QueryRowContext(ctx, `SELECT total_changes()`).Scan(&n)
	return n, err
}

// AgentNode returns node's nodes_agent row; false when it has none.
func (s *Store) AgentNode(ctx context.Context, node string) (AgentNode, bool, error) {
	return agentNodeOf(ctx, s.rdb, node)
}

// AcceptAgentReport applies r in one transaction and reports whether it was applied. A duplicate
// or stale report (r.DuplicateOf the stored row) writes nothing.
//
// An applied report writes the agent version, boot ID, instance, process start, sequence,
// last_report = r.At (zero means now) and the coverage. A Full report also writes
// last_full_report, the host fields and problems, and clears last_error. A report never writes
// the fingerprint or the group.
func (s *Store) AcceptAgentReport(ctx context.Context, r AgentReport) (applied bool, err error) {
	at := orNow(r.At)
	err = s.inTx(ctx, func(tx *sql.Tx) error {
		stored, ok, err := agentNodeOf(ctx, tx, r.Node)
		if err != nil {
			return err
		}
		if ok && r.DuplicateOf(stored) {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO nodes_agent(node) VALUES(?) ON CONFLICT(node) DO NOTHING`, r.Node); err != nil {
			return err
		}
		coverage := "[]"
		if len(r.Coverage) > 0 {
			if coverage, err = jsonText(r.Coverage); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE nodes_agent SET agent_version = ?, boot_id = ?, instance = ?, started_at = ?,
			seq = ?, last_report = ?, coverage = ? WHERE node = ?`,
			r.AgentVersion, r.BootID, r.Instance, nanos(r.StartedAt), int64(r.Seq), nanos(at), coverage, r.Node); err != nil {
			return err
		}
		if r.Full {
			if _, err := tx.ExecContext(ctx, `UPDATE nodes_agent SET last_full_report = ?, kernel_release = ?, arch = ?,
				package_db = ?, reboot_pending = ?, reboot_reason = ?, problems = ?, last_error = '' WHERE node = ?`,
				nanos(at), r.KernelRelease, r.Arch, r.PackageDB, r.RebootPending, r.RebootReason,
				stringsText(r.Problems), r.Node); err != nil {
				return err
			}
		}
		applied = true
		return nil
	})
	return applied, err
}

// SetAgentFingerprint records the host fingerprint whose group SBOM is stored for node. It is an
// error when node has no nodes_agent row.
func (s *Store) SetAgentFingerprint(ctx context.Context, node, fingerprint string) error {
	return s.updateAgentNode(ctx, node, `UPDATE nodes_agent SET fingerprint = ? WHERE node = ?`, fingerprint, node)
}

// SetAgentError records the last error processing node's reports ("" clears it). It is an error
// when node has no nodes_agent row.
func (s *Store) SetAgentError(ctx context.Context, node, msg string) error {
	return s.updateAgentNode(ctx, node, `UPDATE nodes_agent SET last_error = ? WHERE node = ?`, msg, node)
}

func (s *Store) updateAgentNode(ctx context.Context, node, query string, args ...any) error {
	res, err := s.wdb.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("store: node %q has no agent report", node)
	}
	return nil
}

// PutNodeGroup upserts the description of g. It requires an ID and ignores g's Members,
// ExposedNodes and times: a stored row keeps its exposure, first_seen and last_seen, and a new row
// gets first_seen = last_seen = now (zero means now).
func (s *Store) PutNodeGroup(ctx context.Context, g model.NodeGroup, now time.Time) error {
	return s.inTx(ctx, func(tx *sql.Tx) error { return putNodeGroupTx(ctx, tx, g, orNow(now)) })
}

// putNodeGroupTx is PutNodeGroup inside tx: g keeps the stored row's exposure.
func putNodeGroupTx(ctx context.Context, tx *sql.Tx, g model.NodeGroup, now time.Time) error {
	if g.ID == "" {
		return errors.New("store: node group without an ID")
	}
	stored, ok, err := nodeGroupRow(ctx, tx, g.ID)
	if err != nil {
		return err
	}
	g.ExposedNodes = nil
	if ok {
		g.ExposedNodes = stored.ExposedNodes
	}
	return writeNodeGroupTx(ctx, tx, g, now)
}

// nodeGroupRow reads one node_groups row, with its times and without Members.
func nodeGroupRow(ctx context.Context, q querier, id string) (model.NodeGroup, bool, error) {
	g, err := scanNodeGroup(q.QueryRowContext(ctx, `SELECT `+nodeGroupCols+` FROM node_groups WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return model.NodeGroup{}, false, nil
	}
	return g, err == nil, err
}

const nodeGroupCols = `id, kind, label, digest, data, first_seen, last_seen`

// scanNodeGroup reads one node_groups row without Members. The id, kind, label, digest and time
// columns override the decoded data.
func scanNodeGroup(r scanner) (model.NodeGroup, error) {
	var (
		id, kind, label, digest, data string
		first, last                   sql.NullInt64
	)
	if err := r.Scan(&id, &kind, &label, &digest, &data, &first, &last); err != nil {
		return model.NodeGroup{}, err
	}
	var g model.NodeGroup
	if err := json.Unmarshal([]byte(data), &g); err != nil {
		return model.NodeGroup{}, fmt.Errorf("node group %s: %w", id, err)
	}
	g.ID, g.Kind, g.Label, g.Digest = id, model.NodeGroupKind(kind), label, digest
	g.Members, g.FirstSeen, g.LastSeen = nil, fromNanos(first), fromNanos(last)
	return g, nil
}

// NodeGrouping is one reconcile pass's grouping of the cluster's nodes.
type NodeGrouping struct {
	Members  map[string]string   // node → group ID, for every node
	Fallback []model.NodeGroup   // the nodeinfo groups of nodes outside an agent group
	Exposed  map[string][]string // group ID → its members matching the exposed-node selector
	// InUse is node → the digests its pods run, for the nodes whose cached images' in_use is set as
	// SetNodeImagesInUse does; nodes not in it are left alone.
	InUse map[string][]string
	Now   time.Time // zero means now
}

// lastSeenEvery is how often the last_seen of a group with members is moved forward: often enough to
// show, rarely enough that a pass with nothing new writes nothing.
const lastSeenEvery = 10 * time.Minute

// ApplyNodeGrouping writes g in one transaction, writing only what differs from the stored rows, so
// a pass that changes nothing writes nothing:
//
//  1. the Fallback groups are upserted like PutNodeGroup;
//  2. node_group_members is made Members, as given (a group ID without a row included);
//  3. nodes_agent.group_id is the node's group when that is an agent group, else "" (a node in a
//     nodeinfo group or outside Members);
//  4. every group's exposure is Exposed's, sorted, nil when absent;
//  5. groups with members are seen at Now, once last_seen is lastSeenEvery old;
//  6. memberless nodeinfo groups, and memberless agent groups that no nodes_agent fingerprint names,
//     are deleted;
//  7. the cached images of each node in InUse are marked in use exactly when a digest of its pods
//     names them (SetNodeImagesInUse).
func (s *Store) ApplyNodeGrouping(ctx context.Context, g NodeGrouping) error {
	now := orNow(g.Now)
	exposed := make(map[string][]string, len(g.Exposed))
	for id, nodes := range g.Exposed {
		if len(nodes) > 0 {
			exposed[id] = slices.Sorted(slices.Values(nodes))
		}
	}
	return s.inTx(ctx, func(tx *sql.Tx) error {
		for _, fb := range g.Fallback {
			fb.ExposedNodes = exposed[fb.ID]
			if err := writeNodeGroupTx(ctx, tx, fb, now); err != nil {
				return err
			}
		}
		if err := replaceMembersTx(ctx, tx, g.Members); err != nil {
			return err
		}
		if err := setExposureTx(ctx, tx, exposed); err != nil {
			return err
		}
		const groupOf = `COALESCE((SELECT m.group_id FROM node_group_members m JOIN node_groups ng ON ng.id = m.group_id
			WHERE m.node = nodes_agent.node AND ng.kind = ?), '')`
		agent := string(model.NodeGroupAgent)
		for _, q := range []struct {
			query string
			args  []any
		}{
			{`UPDATE nodes_agent SET group_id = ` + groupOf + ` WHERE group_id <> ` + groupOf, []any{agent, agent}},
			{`UPDATE node_groups SET last_seen = ? WHERE id IN (SELECT group_id FROM node_group_members)
				AND (last_seen IS NULL OR last_seen <= ?)`, []any{nanos(now), nanos(now.Add(-lastSeenEvery))}},
			{`DELETE FROM node_groups WHERE id NOT IN (SELECT group_id FROM node_group_members)
				AND (kind = ? OR NOT EXISTS (SELECT 1 FROM nodes_agent a WHERE a.fingerprint = node_groups.id))`,
				[]any{string(model.NodeGroupNodeInfo)}},
		} {
			if _, err := tx.ExecContext(ctx, q.query, q.args...); err != nil {
				return fmt.Errorf("store: apply node grouping: %w", err)
			}
		}
		for _, node := range slices.Sorted(maps.Keys(g.InUse)) {
			if err := setInUseTx(ctx, tx, node, g.InUse[node]); err != nil {
				return err
			}
		}
		return nil
	})
}

// writeNodeGroupTx upserts g with g.ExposedNodes as its exposure, writing nothing when the stored row
// is the same. Its Members and times are not stored in data; a new row is first and last seen at now.
func writeNodeGroupTx(ctx context.Context, tx *sql.Tx, g model.NodeGroup, now time.Time) error {
	if g.ID == "" {
		return errors.New("store: node group without an ID")
	}
	g.Members, g.FirstSeen, g.LastSeen = nil, time.Time{}, time.Time{}
	data, err := jsonText(g)
	if err != nil {
		return err
	}
	var kind, label, digest, stored string
	err = tx.QueryRowContext(ctx, `SELECT kind, label, digest, data FROM node_groups WHERE id = ?`, g.ID).
		Scan(&kind, &label, &digest, &stored)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		_, err = tx.ExecContext(ctx, `INSERT INTO node_groups(id, kind, label, digest, data, first_seen, last_seen)
			VALUES(?, ?, ?, ?, ?, ?, ?)`, g.ID, string(g.Kind), g.Label, g.Digest, data, nanos(now), nanos(now))
		return err
	case err != nil:
		return err
	case kind == string(g.Kind) && label == g.Label && digest == g.Digest && stored == data:
		return nil
	}
	_, err = tx.ExecContext(ctx, `UPDATE node_groups SET kind = ?, label = ?, digest = ?, data = ? WHERE id = ?`,
		string(g.Kind), g.Label, g.Digest, data, g.ID)
	return err
}

// replaceMembersTx makes node_group_members members, deleting and inserting only the rows that differ.
func replaceMembersTx(ctx context.Context, tx *sql.Tx, members map[string]string) error {
	type row struct{ node, group string }
	stored, err := queryAll(ctx, tx, func(r scanner) (row, error) {
		var x row
		err := r.Scan(&x.node, &x.group)
		return x, err
	}, `SELECT node, group_id FROM node_group_members`)
	if err != nil {
		return err
	}
	have := make(map[string]string, len(stored))
	for _, x := range stored {
		have[x.node] = x.group
	}
	for node, group := range have {
		if want, ok := members[node]; !ok || want != group {
			if _, err := tx.ExecContext(ctx, `DELETE FROM node_group_members WHERE node = ?`, node); err != nil {
				return err
			}
		}
	}
	for _, node := range slices.Sorted(maps.Keys(members)) {
		if group, ok := have[node]; ok && group == members[node] {
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO node_group_members(node, group_id) VALUES(?, ?)`, node, members[node]); err != nil {
			return err
		}
	}
	return nil
}

// setExposureTx sets every stored group's exposure to exposed's, rewriting only the groups whose
// exposure differs.
func setExposureTx(ctx context.Context, tx *sql.Tx, exposed map[string][]string) error {
	type row struct{ id, data string }
	rows, err := queryAll(ctx, tx, func(r scanner) (row, error) {
		var x row
		err := r.Scan(&x.id, &x.data)
		return x, err
	}, `SELECT id, data FROM node_groups`)
	if err != nil {
		return err
	}
	for _, x := range rows {
		var g model.NodeGroup
		if err := json.Unmarshal([]byte(x.data), &g); err != nil {
			return fmt.Errorf("node group %s: %w", x.id, err)
		}
		if slices.Equal(g.ExposedNodes, exposed[x.id]) {
			continue
		}
		g.ExposedNodes = exposed[x.id]
		data, err := jsonText(g)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE node_groups SET data = ? WHERE id = ?`, data, x.id); err != nil {
			return err
		}
	}
	return nil
}

// setInUseTx is SetNodeImagesInUse inside tx, writing only the rows whose in_use changes.
func setInUseTx(ctx context.Context, e execer, node string, digests []string) error {
	list := idList(digests)
	const inUse = `(digest IN (SELECT value FROM json_each(?)) OR (config_digest <> '' AND config_digest IN (SELECT value FROM json_each(?))))`
	_, err := e.ExecContext(ctx, `UPDATE node_images SET in_use = `+inUse+` WHERE node = ? AND in_use <> `+inUse,
		list, list, node, list, list)
	return err
}

// PruneAgentNodes deletes the agent state of every node not in live: its nodes_agent,
// node_images and node_group_members rows, and its host inventory's agent_jobs and
// acquisitions_inflight rows. An empty live is an error and deletes nothing, so an informer that
// has not synced never wipes agent state.
func (s *Store) PruneAgentNodes(ctx context.Context, live []string) error {
	if len(live) == 0 {
		return errors.New("store: prune agent nodes without live nodes")
	}
	list := idList(live)
	return s.inTx(ctx, func(tx *sql.Tx) error {
		for _, q := range []string{
			`DELETE FROM nodes_agent WHERE node NOT IN (SELECT value FROM json_each(?))`,
			`DELETE FROM node_images WHERE node NOT IN (SELECT value FROM json_each(?))`,
			`DELETE FROM node_group_members WHERE node NOT IN (SELECT value FROM json_each(?))`,
		} {
			if _, err := tx.ExecContext(ctx, q, list); err != nil {
				return fmt.Errorf("store: prune agent nodes: %w", err)
			}
		}
		for _, q := range []string{
			`DELETE FROM agent_jobs WHERE substr(digest, 1, ?) = ? AND substr(digest, ?) NOT IN (SELECT value FROM json_each(?))`,
			`DELETE FROM acquisitions_inflight WHERE substr(digest, 1, ?) = ?
				AND substr(digest, ?) NOT IN (SELECT value FROM json_each(?))`,
		} {
			if _, err := tx.ExecContext(ctx, q, len(agentHostJobPrefix), agentHostJobPrefix, len(agentHostJobPrefix)+1, list); err != nil {
				return fmt.Errorf("store: prune agent nodes: %w", err)
			}
		}
		return nil
	})
}

// ReplaceNodeImages replaces node's cached images in one transaction. A digest the node still
// holds keeps its stored in_use; a new one takes img.InUse. An empty Kind is stored as "manifest".
func (s *Store) ReplaceNodeImages(ctx context.Context, node string, imgs []model.NodeImage) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		inUse := map[string]bool{}
		rows, err := queryAll(ctx, tx, func(r scanner) (model.NodeImage, error) {
			var img model.NodeImage
			err := r.Scan(&img.Digest, &img.InUse)
			return img, err
		}, `SELECT digest, in_use FROM node_images WHERE node = ?`, node)
		if err != nil {
			return err
		}
		for _, img := range rows {
			inUse[img.Digest] = img.InUse
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM node_images WHERE node = ?`, node); err != nil {
			return err
		}
		ins, err := tx.PrepareContext(ctx, `INSERT OR REPLACE INTO node_images(node, digest, config_digest, kind, names,
			size_bytes, complete, in_use, source) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer func() { _ = ins.Close() }()
		for _, img := range imgs {
			kind := img.Kind
			if kind == "" {
				kind = "manifest"
			}
			used, ok := inUse[img.Digest]
			if !ok {
				used = img.InUse
			}
			if _, err := ins.ExecContext(ctx, node, img.Digest, img.ConfigDigest, kind, stringsText(img.Names),
				img.SizeBytes, img.Complete, used, img.Source); err != nil {
				return err
			}
		}
		return nil
	})
}

// SetNodeImagesInUse marks node's cached images in use exactly when their digest or config digest
// is in digests.
func (s *Store) SetNodeImagesInUse(ctx context.Context, node string, digests []string) error {
	return setInUseTx(ctx, s.wdb, node, digests)
}

// HeldCompleteElsewhere reports whether a node other than except, with an agent report, holds image
// digest complete: a complete node_images row for the digest itself, for the manifest whose config
// digest it is, or for indexDigest when that is not "".
func (s *Store) HeldCompleteElsewhere(ctx context.Context, digest, indexDigest, except string) (bool, error) {
	var held bool
	err := s.rdb.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM node_images i JOIN nodes_agent a ON a.node = i.node
		WHERE i.node <> ? AND i.complete AND (i.digest = ? OR i.config_digest = ? OR (? <> '' AND i.digest = ?)))`,
		except, digest, digest, indexDigest, indexDigest).Scan(&held)
	return held, err
}

// SetImageStatusReason sets the status reason of an unresolvable image and reports whether it did.
// Images in any other status, and absent images, are left alone.
func (s *Store) SetImageStatusReason(ctx context.Context, digest, reason string) (bool, error) {
	res, err := s.wdb.ExecContext(ctx, `UPDATE images SET status_reason = ? WHERE digest = ? AND status = ?`,
		reason, digest, string(model.ImageUnresolvable))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// AgentProvenance records which node and agent version sent the SBOM stored for an image.
type AgentProvenance struct {
	Digest, Node, AgentVersion string
	ReceivedAt                 time.Time
}

// PutAgentProvenance stores p, replacing any earlier provenance of the digest. A zero ReceivedAt
// means now.
func (s *Store) PutAgentProvenance(ctx context.Context, p AgentProvenance) error {
	_, err := s.wdb.ExecContext(ctx, `INSERT OR REPLACE INTO agent_sboms(digest, node, agent_version, received_at)
		VALUES(?, ?, ?, ?)`, p.Digest, p.Node, p.AgentVersion, nanos(orNow(p.ReceivedAt)))
	return err
}

// AgentProvenanceOf returns the provenance of digest's agent SBOM; false when there is none.
func (s *Store) AgentProvenanceOf(ctx context.Context, digest string) (AgentProvenance, bool, error) {
	var (
		p        AgentProvenance
		received sql.NullInt64
	)
	err := s.rdb.QueryRowContext(ctx, `SELECT digest, node, agent_version, received_at FROM agent_sboms WHERE digest = ?`,
		digest).Scan(&p.Digest, &p.Node, &p.AgentVersion, &received)
	if errors.Is(err, sql.ErrNoRows) {
		return AgentProvenance{}, false, nil
	}
	if err != nil {
		return AgentProvenance{}, false, err
	}
	p.ReceivedAt = fromNanos(received)
	return p, true, nil
}

// ClearAgentProvenance deletes digest's provenance.
func (s *Store) ClearAgentProvenance(ctx context.Context, digest string) error {
	_, err := s.wdb.ExecContext(ctx, `DELETE FROM agent_sboms WHERE digest = ?`, digest)
	return err
}

// AgentJob is the poison-pill record of agent work on one key: an image digest, or
// "nodehost:<node>" for a node's host inventory.
type AgentJob struct {
	Digest                        string
	Attempts                      int // counted failures; never reset
	LastError, LastNode           string
	LastAttempt, QuarantinedUntil time.Time
}

const agentJobCols = `digest, attempts, last_error, last_node, last_attempt, quarantined_until`

func scanAgentJob(r scanner) (AgentJob, error) {
	var (
		j                 AgentJob
		last, quarantined sql.NullInt64
	)
	if err := r.Scan(&j.Digest, &j.Attempts, &j.LastError, &j.LastNode, &last, &quarantined); err != nil {
		return AgentJob{}, err
	}
	j.LastAttempt, j.QuarantinedUntil = fromNanos(last), fromNanos(quarantined)
	return j, nil
}

func agentJobOf(ctx context.Context, q querier, digest string) (AgentJob, bool, error) {
	j, err := scanAgentJob(q.QueryRowContext(ctx, `SELECT `+agentJobCols+` FROM agent_jobs WHERE digest = ?`, digest))
	if errors.Is(err, sql.ErrNoRows) {
		return AgentJob{}, false, nil
	}
	return j, err == nil, err
}

// AgentJobOf returns the agent job record of digest; false when there is none.
func (s *Store) AgentJobOf(ctx context.Context, digest string) (AgentJob, bool, error) {
	return agentJobOf(ctx, s.rdb, digest)
}

// RecordAgentJobFailure counts a failed attempt at digest by node at at (zero means now) and returns
// the stored record. Attempts never reset. The record is quarantined until at+quarantineFor
// whenever quarantineAfter > 0 and the attempts reach quarantineAfter, the acquirer's rule.
func (s *Store) RecordAgentJobFailure(ctx context.Context, digest, node, reason string, at time.Time,
	quarantineAfter int, quarantineFor time.Duration) (AgentJob, error) {
	at = orNow(at)
	var job AgentJob
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO agent_jobs(digest, attempts, last_error, last_node, last_attempt)
			VALUES(?, 1, ?, ?, ?) ON CONFLICT(digest) DO UPDATE SET attempts = attempts + 1,
			last_error = excluded.last_error, last_node = excluded.last_node, last_attempt = excluded.last_attempt`,
			digest, reason, node, nanos(at)); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE agent_jobs SET quarantined_until = ?
			WHERE digest = ? AND ? > 0 AND attempts >= ?`,
			nanos(at.Add(quarantineFor)), digest, quarantineAfter, quarantineAfter); err != nil {
			return err
		}
		var err error
		job, _, err = agentJobOf(ctx, tx, digest)
		return err
	})
	return job, err
}

// ClearAgentJob deletes digest's agent job record.
func (s *Store) ClearAgentJob(ctx context.Context, digest string) error {
	_, err := s.wdb.ExecContext(ctx, `DELETE FROM agent_jobs WHERE digest = ?`, digest)
	return err
}

// RuntimeOwnerKeys returns the keys of the stored cluster-level ContainerRuntime owners, sorted: a cheap
// check for owners the runtime cutover should have dropped.
func (s *Store) RuntimeOwnerKeys(ctx context.Context) ([]string, error) {
	prefix := model.OwnerKindContainerRuntime + "//"
	return queryAll(ctx, s.rdb, scanString, `SELECT key FROM owners WHERE substr(key, 1, ?) = ? ORDER BY key`, len(prefix), prefix)
}

// NodesState is the single node-agent state row.
type NodesState struct {
	AgentEnabled    bool      // the node agent is enabled
	RuntimeRetired  bool      // the ContainerRuntime owner is retired in favour of the Nodes owner
	NotFreshSince   time.Time // when the nodes stopped being all fresh while retired; zero when fresh
	ChangedAt       time.Time // the last cutover in either direction
	BaselineReadyAt time.Time // when the node baseline was ready: the node baseline notify reads
	// FirstReportAt is when a fresh agent report was first seen since the agent was enabled; the node
	// baseline's settle window starts there. Zero while none has been.
	FirstReportAt time.Time
	// FullReportOverdue is how old a reporting node's last full report may be before its host inventory
	// counts as not current (GapHostNotInventoried); 0 does not check it.
	FullReportOverdue time.Duration
	// Unsupported holds the nodes the agent DaemonSet does not schedule on, each with why
	// (GapNodeAgentUnsupported); nil when there are none.
	Unsupported map[string]string
}

// NodesState returns the stored node-agent state, the zero value when there is none.
func (s *Store) NodesState(ctx context.Context) (NodesState, error) {
	return nodesState(ctx, s.rdb)
}

func nodesState(ctx context.Context, q querier) (NodesState, error) {
	var (
		st                                          NodesState
		notFresh, changed, baselineReady, firstSeen sql.NullInt64
		overdue                                     int64
		unsupported                                 string
	)
	err := q.QueryRowContext(ctx, `SELECT agent_enabled, runtime_retired, not_fresh_since, changed_at, baseline_ready_at,
		first_report_at, full_report_overdue, unsupported FROM nodes_state WHERE id = 1`).Scan(&st.AgentEnabled, &st.RuntimeRetired,
		&notFresh, &changed, &baselineReady, &firstSeen, &overdue, &unsupported)
	if errors.Is(err, sql.ErrNoRows) {
		return NodesState{}, nil
	}
	if err != nil {
		return NodesState{}, err
	}
	st.NotFreshSince, st.ChangedAt, st.BaselineReadyAt = fromNanos(notFresh), fromNanos(changed), fromNanos(baselineReady)
	st.FirstReportAt, st.FullReportOverdue = fromNanos(firstSeen), time.Duration(overdue)
	if err := json.Unmarshal([]byte(unsupported), &st.Unsupported); err != nil {
		return NodesState{}, fmt.Errorf("nodes state unsupported: %w", err)
	}
	if len(st.Unsupported) == 0 {
		st.Unsupported = nil
	}
	return st, nil
}

// PutNodesState stores st as the single node-agent state row.
func (s *Store) PutNodesState(ctx context.Context, st NodesState) error {
	return putNodesState(ctx, s.wdb, st)
}

// execer is satisfied by *sql.DB and *sql.Tx.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func putNodesState(ctx context.Context, e execer, st NodesState) error {
	unsupported := "{}"
	if len(st.Unsupported) > 0 {
		var err error
		if unsupported, err = jsonText(st.Unsupported); err != nil {
			return err
		}
	}
	_, err := e.ExecContext(ctx, `INSERT OR REPLACE INTO nodes_state(id, agent_enabled, runtime_retired, not_fresh_since,
		changed_at, baseline_ready_at, first_report_at, full_report_overdue, unsupported) VALUES(1, ?, ?, ?, ?, ?, ?, ?, ?)`,
		st.AgentEnabled, st.RuntimeRetired, nanos(st.NotFreshSince), nanos(st.ChangedAt), nanos(st.BaselineReadyAt),
		nanos(st.FirstReportAt), int64(st.FullReportOverdue), unsupported)
	return err
}
