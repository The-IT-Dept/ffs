# ffs

Continuous vulnerability intelligence for Kubernetes.

## What it is

ffs is an open-source operator that runs inside the cluster it protects and answers three questions continuously: what is running here, exactly? Is anything that just dropped affecting us, and does it matter? What do we move to? It re-checks a live inventory of workloads, images, the software inside them, nodes and Kubernetes against new advisories within minutes of them reaching public feeds, ranks each finding by real exposure rather than CVSS alone, and names the nearest image tag or Kubernetes patch that fixes it. ffs delivers intelligence only: it never touches git, opens pull requests or changes workloads.

## Install

Releases are signed. Verify the chart before installing it (this needs `cosign` and `crane`):

```sh
V=0.0.1   # the release to install, without the leading v
CD=$(crane digest ghcr.io/the-it-dept/charts/ffs:$V)
cosign verify ghcr.io/the-it-dept/charts/ffs@$CD \
  --certificate-identity "https://github.com/The-IT-Dept/ffs/.github/workflows/release.yml@refs/tags/v$V" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Then install it:

```sh
helm install ffs oci://ghcr.io/the-it-dept/charts/ffs --version $V -n ffs --create-namespace
```

A node agent DaemonSet is installed by default, in the namespace `<namespace>-agent` (`ffs-agent` here), labelled for the privileged Pod Security level because it reads host paths. It reports each node's host packages, running kernel and cached images; [docs/node-agent.md](docs/node-agent.md) lists everything it reads and how to turn it off. On GKE Autopilot, add `--set nodeAgent.enabled=false`.

The chart pins the ffs image by digest. Every setting is described in [docs/configuration.md](docs/configuration.md).

## Quick start

```sh
kubectl -n ffs rollout status deploy/ffs
kubectl -n ffs port-forward deploy/ffs 8080
```

Then open http://127.0.0.1:8080 for the web UI. The first Grype database download takes several minutes; feed status is on the Feeds page.

Findings and advisories are also Kubernetes resources:

```sh
kubectl get ffs -A
```

The web UI and read-only API have no authentication. They listen on 127.0.0.1 inside the pod, so reaching them needs RBAC `pods/portforward` in the ffs namespace. To front them with your own authenticating proxy, set `config.listen: 0.0.0.0:8080`, `web.service.enabled: true`, `web.networkPolicy.from` to the proxy's pods and `config.allowedHosts` to the host name the proxy forwards; see [Exposing the web UI](docs/configuration.md#exposing-the-web-ui). The chart's NetworkPolicy for the ffs pod admits the port only from those peers. It is created while `nodeAgent.networkPolicy.enabled` is true (the default), with or without the node agent; with it false, restrict the port with a NetworkPolicy of your own.

The API is described in [docs/api.md](docs/api.md); its OpenAPI document is served at `/api/v1/openapi.yaml`.

## Custom resources

All kinds are in the API group `ffs.theitdept.au/v1alpha1` and the category `ffs`.

| Kind | Scope | Written by | `kubectl get` columns |
|---|---|---|---|
| `Finding` | Namespaced: the workload's namespace, or the ffs namespace for cluster-level findings | ffs | `ADVISORY SEVERITY PRIORITY PACKAGE INSTALLED FIX SUGGESTED AGE` |
| `Vulnerability` | Cluster | ffs | `SEVERITY PRIORITY KEV EPSS WORKLOADS FIX AGE` |
| `AlertTarget` | Cluster | admins | `TYPE PAUSED LAST DELIVERY AGE` |
| `Exception` | Namespaced | users | `EXPIRES MATCHED EXPIRED AGE` |

A `Finding` is one open finding at or above `config.crd.minPriority` (default `high`) for one workload. A `Vulnerability` summarises one advisory across the cluster. Everything, at every priority, is in the API and web UI.

The chart ships these roles:

| Role | Grants | How it applies |
|---|---|---|
| `ffs-view` | Read `Finding` and `Exception` | Aggregated into the built-in `view` role |
| `ffs-edit` | Create, update and delete `Exception` | Aggregated into the built-in `edit` and `admin` roles |
| `ffs-cluster-reader` | Read all four kinds, including `Vulnerability`, which lists workloads across namespaces | Bind it explicitly |
| `ffs-admin` | Manage `AlertTarget` and `Exception`; read `Finding` and `Vulnerability` | Bind it explicitly |

## Alerts

An `AlertTarget` delivers to Slack, Discord, Microsoft Teams or a signed webhook. By default it sends urgent findings immediately and everything else in a scheduled digest, and a finding never alerts twice at the same level. This example also sends `high` findings immediately, holding them overnight and at weekends:

```yaml
# The Secret lives in the ffs namespace. Its url key holds the Slack incoming webhook URL.
apiVersion: v1
kind: Secret
metadata:
  name: slack-security
  namespace: ffs
type: Opaque
stringData:
  url: https://hooks.slack.com/services/REPLACE/WITH/YOUR-WEBHOOK
---
apiVersion: ffs.theitdept.au/v1alpha1
kind: AlertTarget
metadata:
  name: slack-security
spec:
  type: slack
  secretRef:
    name: slack-security
  immediate:
    minPriority: high
  digest:
    schedule: "0 9 * * 1-5"
    timeZone: Australia/Sydney
    minPriority: medium
    includeResolved: true
  quietHours:
    intervals:
      - times:
          - startTime: "18:00"
            endTime: "24:00"
          - startTime: "00:00"
            endTime: "08:00"
        location: Australia/Sydney
      - weekdays: ["saturday:sunday"]
        location: Australia/Sydney
    allowUrgent: true
  notifyOnFeedStale: true
```

[docs/alerts.md](docs/alerts.md) covers every field, the alerting rules, the webhook format and signature verification.

## Exceptions

An `Exception` accepts a risk with a reason and an expiry. Matching findings become `excepted`: they stay visible in the API and web UI, but send no alerts and produce no resources or Events. When the Exception expires they reopen.

```yaml
# Applies to findings in its own namespace. Only Exceptions in the ffs namespace apply
# cluster-wide and can except urgent findings.
apiVersion: ffs.theitdept.au/v1alpha1
kind: Exception
metadata:
  name: php-cve-2026-41873
  namespace: shop
spec:
  advisories:
    - CVE-2026-41873
  imageRepositories:
    - docker.io/library/php
  reason: The affected extension is not built into this image. Reviewed by the platform team.
  expires: "2027-05-31T00:00:00Z"
  vexStatus: not_affected
  justification: vulnerable_code_not_present
```

An Exception matches on any combination of `advisories` (aliases included), `packages`, `imageRepositories` (globs) and `owners`; every list that is set must match. `reason` and `expires` are required, and `expires` can be at most one year away.

An Exception's `owners` entries are workload names or `Kind/Name`. A bare name matches only namespaced workloads. The cluster-level owners `Cluster/<cluster>`, `Nodes/<cluster>` and `ContainerRuntime/<runtime>` match only their `Kind/Name` form, so an Exception naming the cluster never excepts host or container runtime findings.

Only Exceptions in the ffs namespace can except `urgent` findings. An Exception in any other namespace leaves urgent findings open and alerting, and its status says so.

## Coverage

ffs never reports an image as clean when it could not see inside it. Images it cannot pull or resolve are shown as `unresolvable`, with the reason. Images with software the cataloguer cannot attribute, such as Rust binaries without cargo-auditable, are marked partial coverage. With the node agent, ffs also checks each node's host packages and the packages of its running kernel. [docs/coverage.md](docs/coverage.md) lists every blind spot and the supported environments.

## Data sources and attribution

ffs fetches this data at runtime from each source and never redistributes a merged database. The web UI's Feeds page shows the freshness and attribution of each.

- **Grype vulnerability database** by Anchore. The upstream sources it aggregates keep their own terms.
- **OSV.dev.** Licences are per source: GitHub Security Advisories, the Go vulnerability database and PyPA are CC-BY-4.0; Ubuntu and Alpine are CC-BY-SA-4.0.
- **CVE List V5**, under the CVE Program Terms of Use.
- **CISA Known Exploited Vulnerabilities**, CC0.
- **EPSS** by FIRST and Empirical Security, who ask for attribution.
- **endoflife.date**, MIT.

NVD and Chainguard OSV data (CC-BY-NC-ND-4.0) are off by default; NVD is not supported in this release.

## Security

- **Read-mostly RBAC.** ffs reads workloads, pods, nodes, services, ingresses, Gateway API routes, RBAC objects and Flux and Argo CD metadata. It writes only its own resources, `events.k8s.io` Events, OpenReports reports and its leader-election Lease (plus PolicyReports when enabled, TokenReviews that authenticate metrics scrapers and node agents, and SubjectAccessReviews that authorise metrics scrapers). It cannot exec into pods, create workloads or write to git.
- **Secrets.** Cluster-wide `get` only, never list or watch, used to read the pull secrets that pods and ServiceAccounts reference. Turn it off with `rbac.readPullSecrets: false`; ffs then reads Secrets only in its own namespace, for AlertTargets and registry credentials. Secret contents are used in memory only, and never logged, stored or returned by the API.
- **Node agent.** It mounts a fixed list of host paths, all read-only, and has no Kubernetes API permissions, no listening ports and no container runtime socket. The collector runs as UID 0 with every capability dropped; cataloguing runs as non-root in a separate container with no host mounts. See [docs/node-agent.md](docs/node-agent.md).
- **Runtime.** A distroless static image running as nonroot, with a read-only root filesystem, all capabilities dropped, no privilege escalation and the RuntimeDefault seccomp profile. The cataloguer runs in its own container with its own memory limit and no Kubernetes API token.
- **Supply chain.** Images and charts are keyless-signed with cosign. Every image platform has an SPDX SBOM attestation, images and charts have SLSA build provenance, and the chart pins the image by digest. Releases are immutable, and GitHub Actions are pinned by commit. The image also carries the package manifests of the npm packages bundled into the web UI, so its SBOMs list them.

To report a vulnerability or verify a release, see [SECURITY.md](SECURITY.md).

## Licence

Apache-2.0. See [LICENSE](LICENSE).
