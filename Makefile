export GOFLAGS := -p=4
export CGO_ENABLED := 0
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse HEAD 2>/dev/null)
LDFLAGS := -s -w -X github.com/the-it-dept/ffs/internal/version.Version=$(VERSION) -X github.com/the-it-dept/ffs/internal/version.Commit=$(COMMIT)
CONTROLLER_GEN ?= go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.23.0
GOLANGCI_LINT  ?= go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0
PKGS ?= ./...
RUN  ?=
.PHONY: build test generate lint e2e
build:    ; go build -trimpath -ldflags '$(LDFLAGS)' -o bin/ffs ./cmd/ffs
SETUP_ENVTEST ?= go run sigs.k8s.io/controller-runtime/tools/setup-envtest@v0.25.3
ENVTEST_K8S_VERSION ?= 1.37.0
test: ; KUBEBUILDER_ASSETS="$$($(SETUP_ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(CURDIR)/bin/envtest -p path)" go test $(if $(RUN),-run '$(RUN)') $(PKGS)
generate: ; $(CONTROLLER_GEN) object:headerFile=hack/boilerplate.go.txt crd paths=./api/... output:crd:artifacts:config=config/crd/bases
lint:     ; $(GOLANGCI_LINT) run ./...
e2e:      ; go test -tags e2e -count=1 -timeout 30m ./test/e2e/...
