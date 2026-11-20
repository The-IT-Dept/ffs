# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub private vulnerability reporting:
<https://github.com/The-IT-Dept/ffs/security/advisories/new>

Do not open public issues for vulnerabilities.

## Supported versions

Only the latest release receives fixes.

## Scope

- The `ffs` binary and container image.
- The Helm chart.
- The release pipeline: the GitHub Actions workflows and the artefacts they publish.

## Verifying a release

Images and charts are signed with cosign keyless signing by the release workflow. Every image platform also has an SPDX SBOM attestation, and the image index, each platform image and the chart have SLSA build provenance in GitHub's attestation store. The commands below need `cosign`, `crane`, `jq`, `gh`, `helm` and `yq`.

```sh
TAG=v0.0.1 V=0.0.1   # the release to verify
ID="https://github.com/The-IT-Dept/ffs/.github/workflows/release.yml@refs/tags/$TAG"
ISS=https://token.actions.githubusercontent.com

# The image index (linux/amd64 and linux/arm64 from v0.0.2), then each platform image with its SBOM
# attestation and provenance. v0.0.1 is a single amd64 image, its own platform image.
D=$(crane digest ghcr.io/the-it-dept/ffs:$V)
cosign verify ghcr.io/the-it-dept/ffs@$D --certificate-identity "$ID" --certificate-oidc-issuer $ISS
gh attestation verify oci://ghcr.io/the-it-dept/ffs@$D -R The-IT-Dept/ffs --signer-workflow The-IT-Dept/ffs/.github/workflows/release.yml
for pd in $(crane manifest ghcr.io/the-it-dept/ffs@$D | jq -r --arg d "$D" '(.manifests // [{digest: $d}])[].digest'); do
  cosign verify ghcr.io/the-it-dept/ffs@$pd --certificate-identity "$ID" --certificate-oidc-issuer $ISS
  cosign verify-attestation --type spdxjson ghcr.io/the-it-dept/ffs@$pd --certificate-identity "$ID" --certificate-oidc-issuer $ISS
  gh attestation verify oci://ghcr.io/the-it-dept/ffs@$pd -R The-IT-Dept/ffs --signer-workflow The-IT-Dept/ffs/.github/workflows/release.yml
done

# The chart, and the image digest it pins.
CD=$(crane digest ghcr.io/the-it-dept/charts/ffs:$V)
cosign verify ghcr.io/the-it-dept/charts/ffs@$CD --certificate-identity "$ID" --certificate-oidc-issuer $ISS
gh attestation verify oci://ghcr.io/the-it-dept/charts/ffs@$CD -R The-IT-Dept/ffs
test "$(helm show values oci://ghcr.io/the-it-dept/charts/ffs --version $V | yq .image.digest)" = "$D" && echo pinned
```

Every command must succeed, and the last line prints `pinned`. Each release's notes repeat these commands with that release's digests.
