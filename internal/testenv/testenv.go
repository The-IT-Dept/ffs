// Package testenv starts a Kubernetes API server for envtest-based tests.
package testenv

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// Start starts envtest with the ffs CRDs plus any extra CRD paths.
// Binaries come from KUBEBUILDER_ASSETS, which `make test` sets.
func Start(extraCRDPaths ...string) (*envtest.Environment, *rest.Config, error) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		return nil, nil, errors.New("KUBEBUILDER_ASSETS is not set: run make test")
	}
	root, err := moduleRoot()
	if err != nil {
		return nil, nil, err
	}
	env := &envtest.Environment{
		CRDDirectoryPaths:     append([]string{filepath.Join(root, "config", "crd", "bases")}, extraCRDPaths...),
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := env.Start()
	if err != nil {
		return nil, nil, fmt.Errorf("start envtest: %w", err)
	}
	return env, cfg, nil
}

// moduleRoot walks up from the working directory to the directory holding go.mod.
func moduleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("go.mod not found above working directory")
		}
		dir = parent
	}
}
