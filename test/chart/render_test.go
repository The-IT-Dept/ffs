// Package chart tests the rendered Helm chart.
package chart

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/yaml"
)

const (
	chartDir    = "../../charts/ffs"
	kubeVersion = "1.37.0"
)

type objs []*unstructured.Unstructured

func requireHelm(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		if os.Getenv("FFS_REQUIRE_HELM") != "" {
			t.Fatal("helm is required: ", err)
		}
		t.Skip("helm not installed")
	}
}

func helmTemplate(t *testing.T, sets ...string) (string, error) {
	t.Helper()
	var args []string
	for _, s := range sets {
		args = append(args, "--set", s)
	}
	return helmTemplateChart(t, chartDir, args...)
}

// helmTemplateChart renders the chart in dir as release ffs in namespace ffs, with extra helm arguments.
func helmTemplateChart(t *testing.T, dir string, extra ...string) (string, error) {
	t.Helper()
	requireHelm(t)
	args := append([]string{"template", "ffs", dir, "-n", "ffs", "--kube-version", kubeVersion}, extra...)
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(t.Context(), "helm", args...) //nolint:gosec // helm with arguments the tests build
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stderr.String(), fmt.Errorf("helm template: %w: %s", err, stderr.String())
	}
	return stdout.String(), nil
}

func renderErr(t *testing.T, sets ...string) (string, error) {
	t.Helper()
	return helmTemplate(t, sets...)
}

func render(t *testing.T, sets ...string) objs {
	t.Helper()
	out, err := helmTemplate(t, sets...)
	require.NoError(t, err, out)
	return decodeObjs(t, out)
}

// decodeObjs decodes a multi-document render.
func decodeObjs(t *testing.T, out string) objs {
	t.Helper()
	var o objs
	dec := yaml.NewYAMLOrJSONDecoder(bytes.NewReader([]byte(out)), 4096)
	for {
		u := &unstructured.Unstructured{}
		if err := dec.Decode(&u.Object); err != nil {
			if errors.Is(err, io.EOF) {
				return o
			}
			require.NoError(t, err)
		}
		if len(u.Object) == 0 {
			continue
		}
		o = append(o, u)
	}
}

func (o objs) find(kind, name string) *unstructured.Unstructured {
	for _, u := range o {
		if u.GetKind() == kind && u.GetName() == name {
			return u
		}
	}
	return nil
}

func (o objs) has(kind, name string) bool { return o.find(kind, name) != nil }

func (o objs) get(t *testing.T, kind, name string) *unstructured.Unstructured {
	t.Helper()
	u := o.find(kind, name)
	if u == nil {
		t.Fatalf("%s %q not rendered", kind, name)
	}
	return u
}

func as[T any](t *testing.T, u *unstructured.Unstructured) T {
	t.Helper()
	var v T
	require.NoError(t, runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, &v))
	return v
}

func renderedConfig(t *testing.T, o objs) string {
	t.Helper()
	s, ok, err := unstructured.NestedString(o.get(t, "ConfigMap", "ffs").Object, "data", "config.yaml")
	require.NoError(t, err)
	require.True(t, ok, "config.yaml missing")
	return s
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p) //nolint:gosec // test fixture path
	require.NoError(t, err)
	return string(b)
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	return p
}
