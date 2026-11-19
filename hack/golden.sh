#!/usr/bin/env bash
# Golden fixtures for the grype matcher (internal/match/grype/golden_test.go).
#
#   hack/golden.sh fetch   download and verify the pinned Grype DB, import it with the pinned grype
#                          CLI, and print the DB directory
#   hack/golden.sh regen   for every fixture image: catalogue it with the pinned syft CLI and match
#                          the SBOM with the pinned grype CLI (--by-cve), writing both outputs to
#                          internal/match/grype/testdata/golden/
#
# Pins live in hack/golden.env. An image without a GOLDEN_IMAGE_<NAME> pin is resolved and pinned
# (linux/amd64 manifest digest) the first time regen generates it. Needs curl, jq and go.
#
# The SBOMs are trimmed before grype sees them: syft's configuration (it holds local paths) and the
# file catalogue (grype matches packages only; it is most of the size) are dropped, with the
# relationships that pointed at files.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
env_file=hack/golden.env
# shellcheck source=golden.env
source "$env_file"

export GOFLAGS="${GOFLAGS:--p=4}"
export CGO_ENABLED=0

db_root=.cache/golden-db
out=internal/match/grype/testdata/golden
platform=linux/amd64
# keep artifacts and the relationships between them; drop syft's configuration and the files
trim='del(.descriptor.configuration, .files)
	| (reduce .artifacts[].id as $id ({}; .[$id] = true)) as $ids
	| .artifactRelationships |= map(select($ids[.parent] and $ids[.child]))'

# fixture name, then image reference; the pin variable is GOLDEN_IMAGE_<NAME> with - and . as _
fixtures=(
	"debian-12 debian:12"
	"ubuntu-24.04 ubuntu:24.04"
	"alpine-3.20 alpine:3.20"
	"ubi9 registry.access.redhat.com/ubi9/ubi-minimal:latest"
	"distroless gcr.io/distroless/base-debian12:latest"
	"python python:3.12-slim"
	"node node:20-slim"
	"go-binary ghcr.io/fluxcd/source-controller:v1.10.1"
)

log() { echo "golden: $*" >&2; }

sha256() {
	if command -v sha256sum >/dev/null; then
		sha256sum "$1" | cut -d' ' -f1
	else
		shasum -a 256 "$1" | cut -d' ' -f1
	fi
}

grype() {
	GRYPE_DB_CACHE_DIR="$db_root" GRYPE_DB_AUTO_UPDATE=false GRYPE_DB_VALIDATE_AGE=false GRYPE_CHECK_FOR_APP_UPDATE=false \
		go run "github.com/anchore/grype/cmd/grype@$GOLDEN_GRYPE_VERSION" "$@"
}

syft() {
	SYFT_CHECK_FOR_APP_UPDATE=false go run "github.com/anchore/syft/cmd/syft@$GOLDEN_SYFT_VERSION" "$@"
}

fetch() {
	mkdir -p "$db_root"
	local archive="$db_root/${GOLDEN_DB_URL##*/}" marker="$db_root/imported.sha256"
	if [[ ! -f "$archive" || "$(sha256 "$archive")" != "$GOLDEN_DB_SHA256" ]]; then
		log "downloading $GOLDEN_DB_URL"
		curl -fsSL --retry 3 -o "$archive.part" "$GOLDEN_DB_URL"
		mv "$archive.part" "$archive"
		local got
		got="$(sha256 "$archive")"
		if [[ "$got" != "$GOLDEN_DB_SHA256" ]]; then
			log "checksum mismatch: got $got, want $GOLDEN_DB_SHA256"
			rm -f "$archive"
			exit 1
		fi
	fi
	if [[ ! -f "$db_root/6/vulnerability.db" || "$(cat "$marker" 2>/dev/null)" != "$GOLDEN_DB_SHA256" ]]; then
		log "importing $archive"
		rm -f "$marker"
		grype db import "$archive" >&2
		echo "$GOLDEN_DB_SHA256" >"$marker"
	fi
	echo "$root/$db_root/6"
}

regen() {
	fetch >/dev/null
	mkdir -p "$out"
	local entry name ref var image sbom
	for entry in "${fixtures[@]}"; do
		read -r name ref <<<"$entry"
		var="GOLDEN_IMAGE_$(tr 'a-z.-' 'A-Z__' <<<"$name")"
		image="${!var:-}"
		sbom="$out/$name.syft.json"
		log "$name: cataloguing ${image:-$ref}"
		syft -q --platform "$platform" -o syft-json "registry:${image:-$ref}" | jq -c "$trim" >"$sbom"
		if [[ -z "$image" ]]; then
			image="$ref@$(jq -r '.source.metadata.manifestDigest' "$sbom")"
			echo "$var=$image" >>"$env_file"
			log "$name: pinned $image"
		fi
		log "$name: matching"
		grype -q -o json --by-cve "sbom:$sbom" >"$out/$name.grype.json"
	done
}

case "${1:-}" in
fetch) fetch ;;
regen) regen ;;
*)
	echo "usage: $0 fetch|regen" >&2
	exit 2
	;;
esac
