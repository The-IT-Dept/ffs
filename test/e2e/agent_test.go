//go:build e2e

package e2e

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

const (
	cveHost       = "CVE-2026-90003" // Debian source package "ffs-e2e-host", fixed in 1.0-2
	agentNS       = "ffs-agent"
	agentDS       = "ffs-agent"
	sideloadedRef = "localhost:5001/e2e/sideloaded:1" // never pushed: the registry answers 404, so ffs offers it to the agent

	// runtimeOwner is the workload detail of the containerd ContainerRuntime owner: 404 while the node
	// agent owns the runtime findings, 200 otherwise.
	runtimeOwner = "/api/v1/workloads/ContainerRuntime/-/containerd"
)

// The parts of the UI API responses (api/openapi.yaml) the agent steps read.
type (
	nodeGroupsList struct {
		Groups []struct {
			ID      string `json:"id"`
			Kind    string `json:"kind"`
			Members int    `json:"members"`
		} `json:"groups"`
	}
	nodeGroupDetail struct {
		Group struct {
			PackageCount int `json:"packageCount"`
		} `json:"group"`
		Members []struct {
			Name string `json:"name"`
		} `json:"members"`
	}
	findingsPage struct {
		Total int `json:"total"`
		Rows  []struct {
			Workload struct {
				Kind      string `json:"kind"`
				Namespace string `json:"namespace"`
				Name      string `json:"name"`
			} `json:"workload"`
			Repo string `json:"repo"`
		} `json:"rows"`
	}
	imagesPage struct {
		Rows []struct {
			Digest string `json:"digest"`
			Repo   string `json:"repo"`
			Status string `json:"status"`
			Source string `json:"source"`
		} `json:"rows"`
	}
	imagePackagesPage struct {
		Total int `json:"total"`
	}
)

// kindBin is the kind binary: $KIND (make e2e sets it), else kind on the PATH.
func kindBin() string { return cmp.Or(os.Getenv("KIND"), "kind") }

// kindNodes returns the node container names of the ffs-e2e kind cluster.
func kindNodes(t *testing.T) []string {
	t.Helper()
	nodes := strings.Fields(run(t, kindBin(), "get", "nodes", "--name", "ffs-e2e"))
	require.NotEmpty(t, nodes, "the ffs-e2e kind cluster has no nodes")
	return nodes
}

// clusterNodes returns the names of the nodes the agent runs on: the kind nodes, or on k3s every
// node the API lists.
func clusterNodes(t *testing.T) []string {
	t.Helper()
	if !k3sMode() {
		return kindNodes(t)
	}
	list, err := kube.CoreV1().Nodes().List(t.Context(), metav1.ListOptions{})
	require.NoError(t, err)
	var names []string
	for _, n := range list.Items {
		names = append(names, n.Name)
	}
	require.NotEmpty(t, names, "the cluster has no nodes")
	return names
}

// nodeOSRelease returns the ID, VERSION_ID and VERSION_CODENAME of a kind node's /etc/os-release.
func nodeOSRelease(t *testing.T, node string) (id, versionID, codename string) {
	t.Helper()
	for line := range strings.Lines(run(t, "docker", "exec", node, "cat", "/etc/os-release")) {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"'`)
		switch k {
		case "ID":
			id = v
		case "VERSION_ID":
			versionID = v
		case "VERSION_CODENAME":
			codename = v
		}
	}
	return id, versionID, codename
}

// appendHostPackage appends hostStanza to /var/lib/dpkg/status on every kind node that does not list
// ffs-e2e-host yet, so a kept cluster (E2E_KEEP) gets it once.
func appendHostPackage(t *testing.T) {
	t.Helper()
	for _, node := range kindNodes(t) {
		c := exec.CommandContext(t.Context(), "docker", "exec", "-i", node, "sh", "-c", //nolint:gosec // G204: node is a kind node name
			"grep -qx 'Package: ffs-e2e-host' /var/lib/dpkg/status || cat >> /var/lib/dpkg/status")
		c.Stdin = strings.NewReader(hostStanza)
		out, err := c.CombinedOutput()
		require.NoError(t, err, "append the host package on %s: %s", node, out)
	}
}

// kindLoad writes img as a docker image archive tagged ref and loads it onto every kind node.
func kindLoad(t *testing.T, ref string, img v1.Image) {
	t.Helper()
	tag, err := name.NewTag(ref)
	require.NoError(t, err)
	archive := filepath.Join(t.TempDir(), "image.tar")
	require.NoError(t, tarball.WriteToFile(archive, tag, img))
	run(t, kindBin(), "load", "image-archive", archive, "--name", "ffs-e2e")
}

// apiStatus GETs an ffs API path through the step's port-forward and returns the status, without
// requiring 200; a request that gets no answer is 0.
func (s *suite) apiStatus(t *testing.T, path string) int {
	t.Helper()
	code, err := get(t.Context(), s.api+path, io.Discard)
	if err != nil {
		t.Logf("GET %s: %v", path, err)
		return 0
	}
	return code
}

// apiGet GETs an ffs API path through the step's port-forward and decodes its 200 JSON body into out.
func (s *suite) apiGet(t *testing.T, path string, out any) error {
	t.Helper()
	var body bytes.Buffer
	code, err := get(t.Context(), s.api+path, &body)
	if err != nil {
		return fmt.Errorf("GET %s: %w", path, err)
	}
	if code != http.StatusOK {
		return fmt.Errorf("GET %s: %d %s", path, code, body.String())
	}
	if err := json.Unmarshal(body.Bytes(), out); err != nil {
		return fmt.Errorf("GET %s: %w", path, err)
	}
	return nil
}

// agentReady waits until the agent DaemonSet runs an up-to-date, ready pod on every node.
func (s *suite) agentReady(t *testing.T) {
	nodes := clusterNodes(t)
	eventually(t, 3*time.Minute, func() (bool, string) {
		ds, err := kube.AppsV1().DaemonSets(agentNS).Get(t.Context(), agentDS, metav1.GetOptions{})
		if err != nil {
			return false, err.Error()
		}
		st := ds.Status
		return int(st.DesiredNumberScheduled) == len(nodes) && st.NumberReady == st.DesiredNumberScheduled &&
				st.UpdatedNumberScheduled == st.DesiredNumberScheduled,
			fmt.Sprintf("DaemonSet %s/%s desired %d, ready %d, updated %d; want %d", agentNS, agentDS,
				st.DesiredNumberScheduled, st.NumberReady, st.UpdatedNumberScheduled, len(nodes))
	})
}

// nodeGroup waits for the agent groups to cover every node, each with host packages, then for the
// cutover: the containerd ContainerRuntime owner goes once every agent reports. On kind every node
// is the same, so this is one group holding every node. s.agentGroup is the largest agent group.
func (s *suite) nodeGroup(t *testing.T) {
	nodes := clusterNodes(t)
	s.api = portForward(t)
	var groups []string
	eventually(t, 5*time.Minute, func() (bool, string) {
		var list nodeGroupsList
		if err := s.apiGet(t, "/api/v1/nodegroups", &list); err != nil {
			return false, err.Error()
		}
		groups, s.agentGroup = nil, ""
		members, most := 0, 0
		var seen []string
		for _, g := range list.Groups {
			seen = append(seen, fmt.Sprintf("%s %s (%d members)", g.Kind, g.ID, g.Members))
			if g.Kind != "agent" {
				continue
			}
			groups = append(groups, g.ID)
			members += g.Members
			if g.Members > most {
				s.agentGroup, most = g.ID, g.Members
			}
		}
		return members == len(nodes), fmt.Sprintf("agent groups hold %d of %d nodes; groups %v", members, len(nodes), seen)
	})

	var names []string
	for _, id := range groups {
		var d nodeGroupDetail
		require.NoError(t, s.apiGet(t, "/api/v1/nodegroups/"+url.PathEscape(id), &d))
		require.Positive(t, d.Group.PackageCount, "node group %s has no host packages", id)
		for _, m := range d.Members {
			names = append(names, m.Name)
		}
	}
	for _, n := range nodes {
		require.True(t, slices.Contains(names, n), "node %s is in no agent group; members %v", n, names)
	}

	eventually(t, 5*time.Minute, func() (bool, string) {
		code := s.apiStatus(t, runtimeOwner)
		return code == http.StatusNotFound, fmt.Sprintf("GET %s: %d, want 404 once every agent reports", runtimeOwner, code)
	})
}

// hostFinding publishes an advisory for the fixture host package in the node's own Debian release and
// waits for its finding on the Nodes owner, in the agent group.
func (s *suite) hostFinding(t *testing.T) {
	if k3sMode() {
		t.Skip("needs kind node access")
	}
	id, versionID, codename := nodeOSRelease(t, kindNodes(t)[0])
	require.Equal(t, "debian", id, "kind node os-release ID")
	require.NotEmpty(t, versionID, "kind node os-release VERSION_ID")
	at := time.Now()
	s.feeds.PublishOSV("Debian", "DEBIAN-"+cveHost,
		debianOSV("DEBIAN-"+cveHost, cveHost, "ffs-e2e-host", "1.0-2", versionID, codename, at), at)

	s.api = portForward(t)
	path := "/api/v1/findings?" + url.Values{"advisory": {cveHost}, "scope": {"nodegroup:" + s.agentGroup}}.Encode()
	eventually(t, 4*time.Minute, func() (bool, string) {
		var page findingsPage
		if err := s.apiGet(t, path, &page); err != nil {
			return false, err.Error()
		}
		for _, r := range page.Rows {
			if r.Workload.Kind == "Nodes" && r.Workload.Name == "e2e" && r.Repo == "host" {
				return page.Total >= 1, fmt.Sprintf("total %d", page.Total)
			}
		}
		return false, fmt.Sprintf("%s: total %d, rows %+v; want one on Nodes/e2e with repo host", path, page.Total, page.Rows)
	})
}

// sideloaded loads an image no registry has onto the nodes and runs it: ffs cannot resolve it, offers it to
// the agent, and the agent catalogues it from the node's content store.
func (s *suite) sideloaded(t *testing.T) {
	if k3sMode() {
		t.Skip("needs kind node access")
	}
	nodes, err := kube.CoreV1().Nodes().List(t.Context(), metav1.ListOptions{})
	require.NoError(t, err)
	require.NotEmpty(t, nodes.Items)
	kindLoad(t, sideloadedRef, sideloadImage(t, nodes.Items[0].Status.NodeInfo.Architecture))
	apply(t, "sideloaded.yaml", map[string]string{"SIDELOADED_IMAGE": sideloadedRef})
	run(t, "kubectl", "-n", "e2e", "rollout", "status", "deploy/sideloaded", "--timeout", "2m")

	ref, err := name.NewTag(sideloadedRef)
	require.NoError(t, err)
	s.api = portForward(t)
	path := "/api/v1/images?" + url.Values{"q": {ref.Context().Name()}}.Encode()
	eventually(t, 6*time.Minute, func() (bool, string) {
		var page imagesPage
		if err := s.apiGet(t, path, &page); err != nil {
			return false, err.Error()
		}
		var seen []string
		for _, r := range page.Rows {
			if r.Status != "catalogued" || r.Source != "agent" {
				seen = append(seen, fmt.Sprintf("%s %s status %q source %q", r.Repo, r.Digest, r.Status, r.Source))
				continue
			}
			var pkgs imagePackagesPage
			pkgPath := "/api/v1/images/" + url.PathEscape(r.Digest) + "/packages?q=libsideload1"
			if err := s.apiGet(t, pkgPath, &pkgs); err != nil {
				return false, err.Error()
			}
			return pkgs.Total >= 1, fmt.Sprintf("%s: total %d, want libsideload1", pkgPath, pkgs.Total)
		}
		return false, fmt.Sprintf("%s: no image catalogued by the agent; rows %v", path, seen)
	})
}

// agentDisabled checks the agent pods never restarted its collector, then turns the agent off: the
// DaemonSet goes, the containerd ContainerRuntime owner comes back, and on kind the host finding
// resolves.
func (s *suite) agentDisabled(t *testing.T) {
	pods, err := kube.CoreV1().Pods(agentNS).List(t.Context(), metav1.ListOptions{})
	require.NoError(t, err)
	require.NotEmpty(t, pods.Items, "no agent pods in %s", agentNS)
	for _, p := range pods.Items {
		for _, c := range p.Status.ContainerStatuses {
			if c.Name == "collector" {
				require.Zero(t, c.RestartCount, "pod %s container collector restarted", p.Name)
			} else if c.RestartCount > 0 {
				t.Logf("pod %s container %s restarted %d times", p.Name, c.Name, c.RestartCount)
			}
		}
	}

	na, ok := s.values["nodeAgent"].(map[string]any)
	require.True(t, ok, "values carry no nodeAgent map")
	na["enabled"] = false
	values, err := yaml.Marshal(s.values)
	require.NoError(t, err)
	helmInstall(t, values)
	eventually(t, 2*time.Minute, func() (bool, string) {
		_, err := kube.AppsV1().DaemonSets(agentNS).Get(t.Context(), agentDS, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return true, ""
		}
		return false, fmt.Sprintf("DaemonSet %s/%s still exists (err %v)", agentNS, agentDS, err)
	})

	// The new configuration restarted the controller, so forward to the new pod.
	s.api = portForward(t)
	eventually(t, 3*time.Minute, func() (bool, string) {
		code := s.apiStatus(t, runtimeOwner)
		return code == http.StatusOK, fmt.Sprintf("GET %s: %d, want 200 with the agent disabled", runtimeOwner, code)
	})
	if k3sMode() {
		return
	}
	path := "/api/v1/findings?" + url.Values{"advisory": {cveHost}, "state": {"resolved"}}.Encode()
	eventually(t, 3*time.Minute, func() (bool, string) {
		var page findingsPage
		if err := s.apiGet(t, path, &page); err != nil {
			return false, err.Error()
		}
		for _, r := range page.Rows {
			if r.Workload.Kind == "Nodes" {
				return true, ""
			}
		}
		return false, fmt.Sprintf("%s: total %d, rows %+v; want one on the Nodes owner", path, page.Total, page.Rows)
	})
}
