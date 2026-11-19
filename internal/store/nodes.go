package store

import (
	"context"
	"database/sql"
	"errors"

	"github.com/the-it-dept/ffs/internal/model"
)

const nodeCols = `name, os, arch, os_image, kernel_version, kubelet_version, container_runtime_version, ready, updated_at`

// ReplaceNodes replaces every stored node with nodes in one transaction.
func (s *Store) ReplaceNodes(ctx context.Context, nodes []model.Node) error {
	return s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM nodes`); err != nil {
			return err
		}
		ins, err := tx.PrepareContext(ctx, `INSERT OR REPLACE INTO nodes(`+nodeCols+`) VALUES(?,?,?,?,?,?,?,?,?)`)
		if err != nil {
			return err
		}
		defer func() { _ = ins.Close() }()
		for _, n := range nodes {
			if _, err := ins.ExecContext(ctx, n.Name, n.OS, n.Arch, n.OSImage, n.KernelVersion, n.KubeletVersion,
				n.ContainerRuntimeVersion, n.Ready, nanos(n.UpdatedAt)); err != nil {
				return err
			}
		}
		return nil
	})
}

// ListNodes returns every stored node, ordered by name.
func (s *Store) ListNodes(ctx context.Context) ([]model.Node, error) {
	return queryAll(ctx, s.rdb, func(r scanner) (model.Node, error) {
		var (
			n       model.Node
			updated sql.NullInt64
		)
		err := r.Scan(&n.Name, &n.OS, &n.Arch, &n.OSImage, &n.KernelVersion, &n.KubeletVersion, &n.ContainerRuntimeVersion,
			&n.Ready, &updated)
		n.UpdatedAt = fromNanos(updated)
		return n, err
	}, `SELECT `+nodeCols+` FROM nodes ORDER BY name`)
}

// PutClusterInfo stores the single cluster_info row.
func (s *Store) PutClusterInfo(ctx context.Context, ci model.ClusterInfo) error {
	_, err := s.wdb.ExecContext(ctx, `INSERT OR REPLACE INTO cluster_info(id, name, git_version, version, distribution,
		low_confidence, kube_proxy_version, updated_at) VALUES(1, ?, ?, ?, ?, ?, ?, ?)`,
		ci.Name, ci.GitVersion, ci.Version, ci.Distribution, ci.LowConfidence, ci.KubeProxyVersion, nanos(ci.UpdatedAt))
	return err
}

// GetClusterInfo returns the stored cluster_info row.
func (s *Store) GetClusterInfo(ctx context.Context) (model.ClusterInfo, bool, error) {
	var (
		ci      model.ClusterInfo
		updated sql.NullInt64
	)
	err := s.rdb.QueryRowContext(ctx, `SELECT name, git_version, version, distribution, low_confidence, kube_proxy_version,
		updated_at FROM cluster_info WHERE id = 1`).Scan(&ci.Name, &ci.GitVersion, &ci.Version, &ci.Distribution,
		&ci.LowConfidence, &ci.KubeProxyVersion, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return model.ClusterInfo{}, false, nil
	}
	if err != nil {
		return model.ClusterInfo{}, false, err
	}
	ci.UpdatedAt = fromNanos(updated)
	return ci, true, nil
}
