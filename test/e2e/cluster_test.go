//go:build e2e

package e2e

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/stretchr/testify/require"
	eventsv1 "k8s.io/api/events/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// kindContext is the kubeconfig context of the cluster hack/e2e-kind.sh creates.
const kindContext = "kind-ffs-e2e"

// kube talks to the cluster under test; TestMain sets it.
var kube kubernetes.Interface

// k3sMode reports a run against an existing cluster (FFS_E2E_KUBECONFIG) instead of kind.
func k3sMode() bool { return os.Getenv("FFS_E2E_KUBECONFIG") != "" }

// connect sets kube from the current kubeconfig context. On kind it refuses any context but the
// suite's own, since the suite installs into whatever cluster it is pointed at.
func connect() error {
	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(clientcmd.NewDefaultClientConfigLoadingRules(), &clientcmd.ConfigOverrides{})
	raw, err := cc.RawConfig()
	if err != nil {
		return err
	}
	if !k3sMode() && raw.CurrentContext != kindContext {
		return fmt.Errorf("the kubeconfig context is %q, not %q: run the suite with make e2e", raw.CurrentContext, kindContext)
	}
	rc, err := cc.ClientConfig()
	if err != nil {
		return err
	}
	kube, err = kubernetes.NewForConfig(rc)
	return err
}

// env is where the suite pushes images and where the cluster reaches the test host.
type env struct {
	RegistryPush      string // registry the test host pushes the app image to
	RegistryInCluster string // the same registry as ffs reaches it from the cluster
	HostAddr          string // test host address as pods reach it
	FFSImage          string // FFS_E2E_IMAGE (repository:tag) on k3s; "" for the kind-loaded e2e tag
}

func loadEnv(t *testing.T) env {
	t.Helper()
	if k3sMode() {
		e := env{RegistryPush: os.Getenv("FFS_E2E_REGISTRY"), HostAddr: os.Getenv("FFS_E2E_HOST_ADDR"), FFSImage: os.Getenv("FFS_E2E_IMAGE")}
		// ffs talks plain HTTP only to RFC 1918 and localhost registries, so a registry the test
		// host reaches on a public address can be given to ffs by a private one.
		e.RegistryInCluster = cmp.Or(os.Getenv("FFS_E2E_REGISTRY_IN_CLUSTER"), e.RegistryPush)
		require.True(t, e.RegistryPush != "" && e.HostAddr != "" && e.FFSImage != "",
			"FFS_E2E_KUBECONFIG needs FFS_E2E_REGISTRY, FFS_E2E_IMAGE and FFS_E2E_HOST_ADDR")
		return e
	}
	e := env{RegistryPush: "localhost:5001", HostAddr: os.Getenv("FFS_E2E_HOST_ADDR")}
	ip := strings.TrimSpace(run(t, "docker", "inspect", "-f", "{{.NetworkSettings.Networks.kind.IPAddress}}", "kind-registry"))
	_, err := netip.ParseAddr(ip)
	require.NoError(t, err, "kind-registry has no address on the kind network: run hack/e2e-kind.sh up")
	e.RegistryInCluster = ip + ":5000" // RFC 1918, so go-containerregistry uses plain HTTP
	if e.HostAddr == "" && runtime.GOOS == "darwin" {
		e.HostAddr = "host.docker.internal"
	}
	if e.HostAddr == "" {
		for _, gw := range strings.Fields(run(t, "docker", "network", "inspect", "kind", "-f", "{{range .IPAM.Config}}{{.Gateway}} {{end}}")) {
			if a, err := netip.ParseAddr(gw); err == nil && a.Is4() {
				e.HostAddr = gw
				break
			}
		}
		require.NotEmpty(t, e.HostAddr, "the kind network has no IPv4 gateway; set FFS_E2E_HOST_ADDR")
	}
	return e
}

// ffsImage returns the ffs image repository and tag the suite installs.
func (e env) ffsImage(t *testing.T) (repository, tag string) {
	t.Helper()
	if e.FFSImage == "" {
		return "ghcr.io/the-it-dept/ffs", "e2e"
	}
	ref, err := name.NewTag(e.FFSImage)
	require.NoError(t, err, "FFS_E2E_IMAGE")
	return ref.Context().Name(), ref.TagStr()
}

// run runs a command and returns its stdout, failing the test on error.
func run(t *testing.T, cmd string, args ...string) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	c := exec.CommandContext(t.Context(), cmd, args...) //nolint:gosec // G204: the suite's own kubectl, helm and docker invocations
	c.Stdout, c.Stderr = &stdout, &stderr
	require.NoError(t, c.Run(), "%s %s: %s", cmd, strings.Join(args, " "), stderr.String())
	return stdout.String()
}

func helmInstall(t *testing.T, valuesYAML []byte) string {
	t.Helper()
	values := filepath.Join(t.TempDir(), "values.yaml")
	require.NoError(t, os.WriteFile(values, valuesYAML, 0o600))
	return run(t, "helm", "upgrade", "--install", "ffs", "../../charts/ffs", "-n", "ffs", "--create-namespace",
		"-f", values, "--wait", "--timeout", "5m")
}

// apply expands ${VAR} in testdata/manifests/<manifest> from vars and server-side applies it, with
// strict field validation.
func apply(t *testing.T, manifest string, vars map[string]string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "manifests", manifest)) //nolint:gosec // G304: the suite's own manifests
	require.NoError(t, err)
	var missing []string
	doc := os.Expand(string(raw), func(k string) string {
		v, ok := vars[k]
		if !ok {
			missing = append(missing, k)
		}
		return v
	})
	require.Empty(t, missing, "%s: unset variables", manifest)
	c := exec.CommandContext(t.Context(), "kubectl", "apply", "--server-side", "--field-manager=e2e", "--validate=strict", "-f", "-")
	c.Stdin = strings.NewReader(doc)
	out, err := c.CombinedOutput()
	require.NoError(t, err, "apply %s: %s", manifest, out)
}

// findingPriority returns the PRIORITY column of a Finding as kubectl get shows it, and whether the
// Finding exists.
func findingPriority(ctx context.Context, ns, name string) (string, bool, error) {
	raw, err := kube.CoreV1().RESTClient().Get().
		AbsPath("/apis/ffs.theitdept.au/v1alpha1/namespaces", ns, "findings", name).
		SetHeader("Accept", "application/json;as=Table;v=v1;g=meta.k8s.io").
		DoRaw(ctx)
	if apierrors.IsNotFound(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	var tbl metav1.Table
	if err := json.Unmarshal(raw, &tbl); err != nil {
		return "", false, err
	}
	col := -1
	for i, c := range tbl.ColumnDefinitions {
		if strings.EqualFold(c.Name, "Priority") {
			col = i
		}
	}
	if col < 0 || len(tbl.Rows) != 1 || len(tbl.Rows[0].Cells) <= col {
		return "", true, fmt.Errorf("finding %s/%s: no Priority cell in %s", ns, name, raw)
	}
	p, _ := tbl.Rows[0].Cells[col].(string)
	return p, true, nil
}

// ownerEvents returns the events.k8s.io/v1 Events in ns regarding kind/name.
func ownerEvents(ctx context.Context, ns, kind, name string) ([]eventsv1.Event, error) {
	list, err := kube.EventsV1().Events(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	var out []eventsv1.Event
	for _, e := range list.Items {
		if e.Regarding.Kind == kind && e.Regarding.Name == name {
			out = append(out, e)
		}
	}
	return out, nil
}

// portForward forwards a free local port to the ffs pod's port 8080 and returns its base URL.
func portForward(t *testing.T) (base string) {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())

	ctx, cancel := context.WithCancel(context.Background())
	logFile, err := os.Create(filepath.Join(t.TempDir(), "port-forward.log"))
	require.NoError(t, err)
	c := exec.CommandContext(ctx, "kubectl", "-n", "ffs", "port-forward", "deploy/ffs", strconv.Itoa(port)+":8080") //nolint:gosec // G204: fixed command with a numeric port
	c.Stdout, c.Stderr = logFile, logFile
	require.NoError(t, c.Start())
	t.Cleanup(func() {
		cancel()
		_ = c.Wait()
		_ = logFile.Close()
	})

	base = "http://127.0.0.1:" + strconv.Itoa(port)
	eventually(t, 30*time.Second, func() (bool, string) {
		code, err := get(t.Context(), base+"/api/v1/feeds", io.Discard)
		if err != nil {
			return false, err.Error()
		}
		return code == http.StatusOK, fmt.Sprintf("GET /api/v1/feeds: %d", code)
	})
	return base
}

// get GETs url into w and returns the status code.
func get(ctx context.Context, url string, w io.Writer) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, err = io.Copy(w, resp.Body)
	return resp.StatusCode, err
}

// apiObjects GETs an ffs API path and returns every JSON object in the response, at any depth.
func apiObjects(t *testing.T, base, path string) []map[string]any {
	t.Helper()
	var body bytes.Buffer
	code, err := get(t.Context(), base+path, &body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, code, "GET %s: %s", path, body.String())
	var doc any
	require.NoError(t, json.Unmarshal(body.Bytes(), &doc), "GET %s", path)
	var out []map[string]any
	var walk func(any)
	walk = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			out = append(out, v)
			for _, e := range v {
				walk(e)
			}
		case []any:
			for _, e := range v {
				walk(e)
			}
		}
	}
	walk(doc)
	return out
}

// eventually polls cond every 2s until it holds, failing with its last message after timeout.
func eventually(t *testing.T, timeout time.Duration, cond func() (bool, string)) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		ok, msg := cond()
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("not true after %s: %s", timeout, msg)
		}
		select {
		case <-t.Context().Done():
			t.Fatalf("cancelled: %s", msg)
		case <-time.After(2 * time.Second):
		}
	}
}
