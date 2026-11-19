export GOFLAGS := -p=4
export CGO_ENABLED := 0
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse HEAD 2>/dev/null)
LDFLAGS := -s -w -X github.com/the-it-dept/ffs/internal/version.Version=$(VERSION) -X github.com/the-it-dept/ffs/internal/version.Commit=$(COMMIT)
CONTROLLER_GEN ?= go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.23.0
GOLANGCI_LINT  ?= go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0
PKGS ?= ./...
RUN  ?=
.PHONY: build test generate lint e2e golden chart-lint image licenses
build:    ; go build -trimpath -ldflags '$(LDFLAGS)' -o bin/ffs ./cmd/ffs
SETUP_ENVTEST ?= go run sigs.k8s.io/controller-runtime/tools/setup-envtest@v0.25.3
ENVTEST_K8S_VERSION ?= 1.37.0
test: ; KUBEBUILDER_ASSETS="$$($(SETUP_ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(CURDIR)/bin/envtest -p path)" go test $(if $(RUN),-run '$(RUN)') $(PKGS)
generate:
	$(CONTROLLER_GEN) object:headerFile=hack/boilerplate.go.txt crd paths=./api/... output:crd:artifacts:config=config/crd/bases
	rm -f charts/ffs/crds/*.yaml && cp config/crd/bases/*.yaml charts/ffs/crds/
lint:     ; $(GOLANGCI_LINT) run ./...
e2e:      ; go test -tags e2e -count=1 -timeout 30m ./test/e2e/...
golden:   ; hack/golden.sh fetch && FFS_GOLDEN_DB=$(CURDIR)/.cache/golden-db/6 go test -tags golden ./internal/match/grype -run TestGolden -count=1
chart-lint: ; helm lint --strict --kube-version 1.37.0 charts/ffs
image:   ; docker buildx build --platform linux/$(shell go env GOARCH) --build-arg VERSION=dev --build-arg COMMIT=$$(git rev-parse --short=7 HEAD) -t ghcr.io/the-it-dept/ffs:dev --load .

# Licence check of every package linked into the linux/amd64 and linux/arm64 binaries. It fails on
# forbidden (AGPL and similar), restricted (GPL, LGPL) and unidentified licences. Reviewed exceptions:
#   github.com/spdx/tools-golang        Apache-2.0 OR GPL-2.0-or-later; used under Apache-2.0.
#   github.com/deitch/magic             Apache-2.0; short-form notice the classifier does not identify.
#   github.com/in-toto/attestation      Apache-2.0; short-form notice the classifier does not identify.
#   github.com/openreports/reports-api  Apache-2.0 upstream; the v0.2.1 module ships no LICENSE file.
GO_LICENSES_VERSION := v2.0.1
LICENSE_EXCEPTIONS  := github.com/spdx/tools-golang github.com/deitch/magic github.com/in-toto/attestation github.com/openreports/reports-api
licenses:
	GOBIN=$(CURDIR)/bin go install github.com/google/go-licenses/v2@$(GO_LICENSES_VERSION)
	for arch in amd64 arm64; do \
	  GOOS=linux GOARCH=$$arch $(CURDIR)/bin/go-licenses check ./cmd/ffs --disallowed_types=forbidden,restricted \
	    $(addprefix --ignore ,$(LICENSE_EXCEPTIONS)) || exit 1; \
	done
