package model

import "time"

// Node is the inventory view of a cluster node, from its status.nodeInfo.
type Node struct {
	Name, OS, Arch, OSImage, KernelVersion  string
	KubeletVersion, ContainerRuntimeVersion string // raw: "v1.35.2+k3s1", "containerd://2.2.1"
	Ready                                   bool
	UpdatedAt                               time.Time
}

// ClusterInfo is the control-plane version and distribution.
type ClusterInfo struct {
	Name, GitVersion, Version, Distribution string // Version normalised "1.35.2"; Distribution "k3s"|"rke2"|"eks"|"gke"|""
	LowConfidence                           bool   // managed distributions (eks, gke)
	KubeProxyVersion                        string // normalised from the kube-system/kube-proxy DaemonSet image tag; "" if absent
	UpdatedAt                               time.Time
}
