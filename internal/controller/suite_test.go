package controller

import (
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/go-logr/logr"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/the-it-dept/ffs/internal/testenv"
)

var env *testenv.Env // nil under -short

func TestMain(m *testing.M) {
	flag.Parse()
	ctrllog.SetLogger(logr.Discard())
	if testing.Short() {
		os.Exit(m.Run())
	}
	e, err := testenv.New()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	env = e
	code := m.Run()
	if err := env.Stop(); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	os.Exit(code)
}

// needEnv skips tests that need the API server under -short.
func needEnv(t *testing.T) {
	t.Helper()
	if env == nil {
		t.Skip("envtest")
	}
}
