// Package testenv starts a Kubernetes API server for envtest-based tests.
package testenv

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/the-it-dept/ffs/api/v1alpha1"
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

// Env is a running envtest API server with a direct client over the client-go and ffs types.
type Env struct {
	Env    *envtest.Environment
	Config *rest.Config
	Client client.Client // uncached: reads go straight to the API server
	Scheme *runtime.Scheme
}

// New starts envtest through Start and builds a scheme and an uncached client for it. It never
// downloads binaries: when KUBEBUILDER_ASSETS is unset, Start's error is returned as is.
func New(extraCRDPaths ...string) (*Env, error) {
	env, cfg, err := Start(extraCRDPaths...)
	if err != nil {
		return nil, err
	}
	s := runtime.NewScheme()
	if err := errors.Join(clientgoscheme.AddToScheme(s), v1alpha1.AddToScheme(s)); err != nil {
		return nil, errors.Join(fmt.Errorf("build scheme: %w", err), env.Stop())
	}
	c, err := client.New(cfg, client.Options{Scheme: s})
	if err != nil {
		return nil, errors.Join(fmt.Errorf("build client: %w", err), env.Stop())
	}
	return &Env{Env: env, Config: cfg, Client: c, Scheme: s}, nil
}

// Stop stops the API server.
func (e *Env) Stop() error { return e.Env.Stop() }

// EnsureNamespace creates the namespace unless it already exists.
func (e *Env) EnsureNamespace(ctx context.Context, name string) error {
	err := e.Client.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}})
	if apierrors.IsAlreadyExists(err) {
		return nil
	}
	return err
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
