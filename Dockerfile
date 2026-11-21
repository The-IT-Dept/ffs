# syntax=docker/dockerfile:1
# The web UI. The Node version matches ui/.nvmrc and the engines field of ui/package.json
# (TestShipping_NodeVersionPinnedConsistently). The digest is from `crane digest
# node:26.13.1-trixie-slim`; re-run it when bumping. NODE_ENV stays unset: npm ci needs the devDependencies.
FROM --platform=$BUILDPLATFORM node:26.13.1-trixie-slim@sha256:e6bedef217677b276c591795e169840edd9096dbf13f29df8ef8d1856b8820bc AS ui
WORKDIR /src/ui
COPY ui/package.json ui/package-lock.json ui/.npmrc ./
RUN npm ci
COPY ui/ ./
COPY internal/web/ui/dist/.keep /src/internal/web/ui/dist/.keep
# The build lists the npm packages the bundle contains, from Vite's module graph, next to dist
# (ui/scripts/bundled.ts); manifests checks their licences and writes a package.json for each.
RUN npm run build && node scripts/prodtree.mjs manifests /out/ui-sbom

FROM --platform=$BUILDPLATFORM golang:1.27.3-trixie@sha256:af1bfc2614ebb1dbd31af514b78740fd678850e76498762b425ecee4c5c6ea80 AS build
ARG TARGETOS TARGETARCH VERSION=dev COMMIT=unknown
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=ui /src/internal/web/ui/dist ./internal/web/ui/dist
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -buildvcs=false \
    -ldflags="-s -w -X github.com/the-it-dept/ffs/internal/version.Version=${VERSION} -X github.com/the-it-dept/ffs/internal/version.Commit=${COMMIT}" \
    -o /out/ffs ./cmd/ffs

# Debian 12 regular support has ended, so the runtime base is Debian 13. The digest is from
# `crane digest gcr.io/distroless/static-debian13:nonroot`; re-run it (and `crane digest
# golang:1.27.1-trixie` for the builder) when bumping. Dependabot's docker ecosystem proposes bumps.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931
LABEL org.opencontainers.image.source=https://github.com/The-IT-Dept/ffs org.opencontainers.image.licenses=Apache-2.0
COPY --from=build /out/ffs /ffs
# package.json manifests of the npm packages bundled into the web UI, so SBOMs of this image list them.
COPY --from=ui /out/ui-sbom /usr/share/ffs/ui/
USER 65532:65532
ENTRYPOINT ["/ffs"]
