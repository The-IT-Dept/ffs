export GOFLAGS := -p=4
export CGO_ENABLED := 0
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse HEAD 2>/dev/null)
LDFLAGS := -s -w -X github.com/the-it-dept/ffs/internal/version.Version=$(VERSION) -X github.com/the-it-dept/ffs/internal/version.Commit=$(COMMIT)
CONTROLLER_GEN ?= go run sigs.k8s.io/controller-tools/cmd/controller-gen@v0.23.0
GOLANGCI_LINT  ?= go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0
OAPI_CODEGEN   ?= go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.2
PKGS ?= ./...
RUN  ?=
.PHONY: build test generate lint e2e golden chart-lint image licenses ui ui-test bench-api ui-e2e
build:    ; go build -trimpath -ldflags '$(LDFLAGS)' -o bin/ffs ./cmd/ffs
SETUP_ENVTEST ?= go run sigs.k8s.io/controller-runtime/tools/setup-envtest@v0.25.3
ENVTEST_K8S_VERSION ?= 1.37.0
test: ; KUBEBUILDER_ASSETS="$$($(SETUP_ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(CURDIR)/bin/envtest -p path)" go test $(if $(RUN),-run '$(RUN)') $(PKGS)
generate:
	$(CONTROLLER_GEN) object:headerFile=hack/boilerplate.go.txt crd paths=./api/... output:crd:artifacts:config=config/crd/bases
	rm -f charts/ffs/crds/*.yaml && cp config/crd/bases/*.yaml charts/ffs/crds/
	$(OAPI_CODEGEN) -config api/oapi-codegen.yaml api/openapi.yaml
	cd ui && npm run --silent generate:api
lint:     ; $(GOLANGCI_LINT) run ./...
golden:   ; hack/golden.sh fetch && FFS_GOLDEN_DB=$(CURDIR)/.cache/golden-db/6 go test -tags golden ./internal/match/grype -run TestGolden -count=1
chart-lint: ; helm lint --strict --kube-version 1.37.0 charts/ffs
ui:      ; cd ui && npm ci && npm run build
ui-test: ; cd ui && npm ci && npm run typecheck && npm test
# API latency gate (spec G8): p95 of every list, facet and aggregate operation on the 25,000-finding
# webtest.Scale fixture, in process.
bench-api: ; GOFLAGS=-p=4 go test -tags bench -run TestAPILatency_P95 -count=1 -v ./internal/web/apiserver/
# Playwright suite against hack/uiserve over the Small fixture. Needs `cd ui && npm ci` and a browser:
# `npx playwright install chromium`, or FFS_PW_CHANNEL=chrome to use an installed Chrome.
ui-e2e: ; cd ui && npm run e2e
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

# End-to-end suite. By default it runs on a kind cluster with a local registry (hack/e2e-kind.sh),
# deleted afterwards unless E2E_KEEP is set; the cluster's credentials go to E2E_KUBECONFIG, never
# ~/.kube/config. kind is pinned: releases before v0.27 cannot create Kubernetes 1.37 nodes. With
# FFS_E2E_KUBECONFIG it runs on that cluster instead (k3s), which also needs FFS_E2E_REGISTRY,
# FFS_E2E_IMAGE and FFS_E2E_HOST_ADDR (and FFS_E2E_REGISTRY_IN_CLUSTER when ffs must reach the
# registry by another address).
E2E_KUBECONFIG ?= $(CURDIR)/bin/e2e-kind.kubeconfig
KIND_VERSION   := v0.33.0
KIND           := $(CURDIR)/bin/kind
e2e:
ifeq ($(FFS_E2E_KUBECONFIG),)
	GOBIN=$(CURDIR)/bin go install sigs.k8s.io/kind@$(KIND_VERSION)
	mkdir -p $(dir $(E2E_KUBECONFIG))
	KIND=$(KIND) KUBECONFIG=$(E2E_KUBECONFIG) hack/e2e-kind.sh up
	docker build -t ghcr.io/the-it-dept/ffs:e2e --build-arg VERSION=e2e .
	$(KIND) load docker-image ghcr.io/the-it-dept/ffs:e2e --name ffs-e2e
	KUBECONFIG=$(E2E_KUBECONFIG) KIND=$(KIND) GOFLAGS=-p=4 go test -tags e2e -count=1 -timeout 30m -v ./test/e2e/... ; s=$$?; [ -n "$$E2E_KEEP" ] || KIND=$(KIND) KUBECONFIG=$(E2E_KUBECONFIG) hack/e2e-kind.sh down; exit $$s
else
	KUBECONFIG=$(FFS_E2E_KUBECONFIG) GOFLAGS=-p=4 go test -tags e2e -count=1 -timeout 30m -v ./test/e2e/...
endif
