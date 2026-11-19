# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.27.4-trixie@sha256:f18c3d73a184fb0582828510722e723b63a93f7188d11dd223d9be6f6880e65d AS build
ARG TARGETOS TARGETARCH VERSION=dev COMMIT=unknown
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -buildvcs=false \
    -ldflags="-s -w -X github.com/the-it-dept/ffs/internal/version.Version=${VERSION} -X github.com/the-it-dept/ffs/internal/version.Commit=${COMMIT}" \
    -o /out/ffs ./cmd/ffs

# Debian 12 regular support has ended, so the runtime base is Debian 13. The digest is from
# `crane digest gcr.io/distroless/static-debian13:nonroot`; re-run it (and `crane digest
# golang:1.27.1-trixie` for the builder) when bumping. Dependabot's docker ecosystem proposes bumps.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931
LABEL org.opencontainers.image.source=https://github.com/The-IT-Dept/ffs org.opencontainers.image.licenses=Apache-2.0
COPY --from=build /out/ffs /ffs
USER 65532:65532
ENTRYPOINT ["/ffs"]
