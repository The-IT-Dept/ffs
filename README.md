# ffs

Continuous vulnerability intelligence for Kubernetes.

## What it is

ffs is an open-source operator that runs inside the cluster it protects and answers three questions continuously: what is running here, exactly? Is anything that just dropped affecting us, and does it matter? What do we move to? It re-checks a live inventory of workloads, images, the software inside them, nodes and Kubernetes against new advisories within minutes of them reaching public feeds, ranks each finding by real exposure rather than CVSS alone, and names the nearest image tag or Kubernetes patch that fixes it. ffs delivers intelligence only: it never touches git, opens pull requests or changes workloads.

## Install

Releases are signed. Verify the chart before installing it (this needs `cosign` and `crane`):

```sh
V=0.0.2   # the release to install, without the leading v
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

The web UI and read-only API have no authentication. They listen on 127.0.0.1 inside the pod, so reaching them needs RBAC `pods/portforward` in the ffs namespace. To front them with your own authenticating proxy, set `config.listen: 0.0.0.0:8080`, `web.service.enabled: true`, `web.networkPolicy.from` to the proxy's pods and `config.allowedHosts` to the host name the proxy forwards; see [Exposing the web UI](docs/configuration.md#exposing-the-web-ui). The chart's NetworkPolicy for the ffs pod admits the port only from those peers. It is created while `networkPolicy.enabled` is true (the default), with or without the node agent; with it false, restrict the port with a NetworkPolicy of your own.

The API is described in [docs/api.md](docs/api.md); its OpenAPI document is served at `/api/v1/openapi.yaml`.

## Upgrading

Helm installs the CustomResourceDefinitions in the chart's `crds/` directory on the first install only: `helm upgrade` never changes them, so a new release's schema changes would not reach the cluster. Verify the new chart as for an install, apply its CRDs, then upgrade with the values you installed with:

```sh
V=0.0.2   # the release to upgrade to, without the leading v
helm show crds oci://ghcr.io/the-it-dept/charts/ffs --version $V | kubectl apply --server-side --force-conflicts -f -
helm upgrade ffs oci://ghcr.io/the-it-dept/charts/ffs --version $V -n ffs -f values.yaml
```

### v0.0.2

Each change is explained further in [docs/upgrading.md](docs/upgrading.md#v002).

- **Upgrade with `-f`.** `helm upgrade --reuse-values` keeps v0.0.1's defaults, such as `nodeAgent.architectures: [amd64]` and the `2Gi` memory limit. Upgrade with `-f values.yaml` as above.
- **Rolling back.** v0.0.2 can be rolled back to v0.0.1 on the same volume.
- **NetworkPolicy value.** Move `nodeAgent.networkPolicy.enabled` to `networkPolicy.enabled` (default `true`). v0.0.2 still honours the old key, with a deprecation line in the install notes; v0.0.3 removes it. [More](docs/upgrading.md#v002-helm-values).
- **RBAC.** Flux and Argo CD read rules removed; ReferenceGrant read added.
- **arm64.** Images are published for linux/arm64 too, and `nodeAgent.architectures` defaults to `[amd64, arm64]`. To keep the agent off arm64 nodes, set `nodeAgent.architectures: [amd64]`.
- **Controller memory.** The limit defaults to `1Gi` (was `2Gi`), with `GOMEMLIMIT` at 90% of it; a limit you set is kept. First ingest of 8 nodes in 5 groups: about 180 MiB live heap (was about 800 MiB).
- **Shutdown.** The controller pod's termination grace period is 45 seconds (was 30).
- **ServiceMonitor.** It selects only the metrics Service, by that Service's new label `app.kubernetes.io/component: metrics`.
- **Logs.** client-go and leader-election messages are JSON lines like the rest. The new chart value `controller.logLevel` (`info` or `debug`) sets `--zap-log-level`.
- **Alert delivery.** A failing delivery is retried until 24 hours after its first attempt (was about 66 minutes). Messages queued together go out by priority. A target holds at most 1,000 queued messages; older ones are dropped and counted in `ffs_notify_deliveries_total{result="dropped"}`. [More](docs/upgrading.md#v002-alert-delivery).
- **Alert messages.** Messages list at most 200 items plus a count of the rest, and stored payloads are capped at 256 KiB. Summaries and digest titles count findings (was: advisories), and the webhook `summary` gains `findings`. Discord alerts never mention anyone, and Discord and Teams messages escape markdown in feed, image and advisory text.
- **Confirmed provisional findings** at or above `immediate.minPriority` are alerted when Grype confirms them, if nothing was sent for them yet (was: the digest only).
- **Alert targets.** The SSRF guard also refuses the nodes' pod CIDRs and the ranges in the new `config.alertTargets.blockedCIDRs`: add your Service CIDR there when it is globally routable, and the pod pools of a CNI that assigns addresses from pools of its own. Through an HTTPS proxy, the guard checks only endpoints given as IP addresses: limit what the proxy can reach. [More](docs/upgrading.md#v002-alert-targets).
- **Resolutions.** A target gets the resolution of every finding it was told about, whatever its namespace filters now say. At start, ffs closes what v0.0.1 left open in deleted namespaces, so those findings alert as reopened if they come back.
- **KEV.** An advisory is in KEV when any of its aliases is listed. The first KEV sync after the upgrade can turn findings `urgent`, with immediate alerts and Warning Events.
- **First inventory pass.** It recomputes every workload's findings once under v0.0.2's rules. It can bring back findings that a Grype not-affected verdict hid, and change fix versions, fix availability and priority, with transitions, Events and alerts. Recording each owner's apiVersion raises nothing by itself. [More](docs/upgrading.md#v002-findings).
- **Custom workload kinds.** Events and OpenReports reports also cover other workload kinds, such as Argo Rollouts, OpenKruise CloneSets, Strimzi pod sets and CloudNativePG clusters.
- **Grype precedence.** Grype no longer overrides upstream-runtime (CNA) or Kubernetes verdicts: php, node and python built from source keep the CNA's fix versions.
- **Advisories.** Advisories only Grype matches (RHEL and Amazon Linux ones, say) have titles and published dates. A vendor advisory's CVEs are no longer merged into one advisory. The Go standard library's fixed-in version is chosen per release branch.
- **EPSS thresholds.** A finding's priority drops at an EPSS threshold only once its score is below 90% of it (0.09 and 0.45 by default), so a score that hovers at a threshold no longer moves it back and forth. [More](docs/upgrading.md#v002-findings).
- **Transition history.** Open findings' history older than `config.retention.resolved` is pruned, keeping each finding's latest 20. Triggers are set per transition. [More](docs/upgrading.md#v002-findings).
- **Grype DB updates.** Below `config.feeds.grypedb.diffMinImages` (default 1000) catalogued SBOMs, a new database re-matches every SBOM with Grype. From it, a diff in a separate process picks the SBOMs: it needs room on the volume (`persistence.size`) and shares the controller's memory limit, so raise `controller.resources.limits.memory` on large clusters. [More](docs/upgrading.md#v002-feeds).
- **Grype DB updates re-run Grype only.** The OSV, upstream and Kubernetes matchers' results follow their own feeds. The first Grype DB update after this upgrade re-runs every matcher on every SBOM once.
- **Feed retries and staleness.** After a restart, a feed whose last sync failed is retried on its failure backoff (was: a whole interval later). A feed that never synced is stale `staleAfter` after its first attempt, across restarts. A sync may take twice its feed's interval, and at least an hour.
- **OSV.** The first sync quietly rehashes the cached records once. Rating-only changes reach findings within the poll interval. Records the bucket lists but does not serve are asked for again for a day. Skipped records are counted in `ffs_feed_skipped_total{feed="osv"}`. [More](docs/upgrading.md#v002-feeds).
- **CVE List.** A delta release over 64 MiB is skipped (was: the feed stopped) and counted in the new metric `ffs_feed_skipped_total{feed, reason}`, which starts at 0 for each feed and reason.
- **Gateway API routes** in other namespaces count towards a Service's exposure when a ReferenceGrant in the Service's namespace permits them.
- **Node taints.** A node with a `NoSchedule` or `NoExecute` taint that `nodeAgent.tolerations` does not tolerate shows `node_agent_unsupported` (was `node_agent_missing`), and its to-do mentions untolerated taints.
- **Workloads not running.** A finished standalone Job whose pods are gone counts as not running. A workload with no running pods is resolved at the platform its pod template pins (was: the cluster's majority platform).
- **Image cataloguing.** An image that fills the scratch space alone is quarantined for 24 hours at once. A cataloguer 400 is `unresolvable`, retried after 6 hours. A tag that does not resolve, named only by workloads that are not running, is looked up again with a backoff of up to 6 hours (was: on every inventory flush). [More](docs/upgrading.md#v002-inventory-and-coverage).
- **Suggested upgrades** name the target (`nginx:1.30.7`, `nginx:1.30.6 (new digest)`, `kubernetes v1.35.10`) in alerts, Events, Findings, OpenReports, best-fix labels and the API. Findings and reports with a suggestion are rewritten once. [More](docs/upgrading.md#v002-upgrade-suggestions).
- **Upgrade choice.** A candidate must fix more `urgent`, `high` and `medium` findings than it introduces, or leave `medium` and `low` no worse, to win over a further tier. Prereleases compare numerically. Some workloads get a different target after the upgrade, announced once. [More](docs/upgrading.md#v002-upgrade-suggestions).
- **Re-resolution.** A suggestion is re-resolved as soon as its findings are resolved, excepted or fall below `medium`, and owners queued when ffs restarts are resolved after the restart (was: at the daily pass).
- **`config.upgrades.overrides` keys** are normalised like image references (`postgres` means `docker.io/library/postgres`). A malformed glob, or two keys naming one repository, fails the configuration load. Among overlapping globs the longest literal prefix wins.
- **End of life.** Readable product names, and an upgrade suggestion's end of life is always set. CentOS Linux and CentOS Stream images and nodes get an end-of-life status; Azure Linux shows a lifecycle note. [More](docs/upgrading.md#v002-outputs-and-api).
- **Events, reports and Exceptions.** FeedStale Events repeat every 50 minutes while a feed stays stale. An invalid Exception is checked again hourly. OpenReports lists its reports at start and every 10 minutes. New metric `ffs_finding_cr_name_collisions`.
- **Search API.** `/api/v1/search` returns the Control plane and Nodes pages as hits of kinds `controlplane` and `nodes` (was: `workload` hits).
- **Node group links.** A link to an agentless node group that shares its name with an agent group names a member node (`<name>-nodeinfo@<node>`). Links from v0.0.1 still work.
- **Web UI.** The explorer's EPSS signal reads "EPSS bump". The image's UI package manifests (`/usr/share/ffs/ui`) list the npm packages in the bundle (was: the lockfile's production tree).

## Uninstalling

```sh
helm uninstall ffs -n ffs
```

This removes the controller, the node agent and the agent namespace (when the chart created it), and the PersistentVolumeClaim that holds the store and feed data (not one you named in `persistence.existingClaim`). Helm never deletes CustomResourceDefinitions, so every `Finding`, `Vulnerability`, `AlertTarget` and `Exception` stays in etcd. So does what ffs created while it ran: its OpenReports reports, its PolicyReports when `config.openReports.wgPolicy` was on, and its leader-election Lease in the release namespace. To remove them too:

```sh
kubectl delete reports.openreports.io -A -l app.kubernetes.io/managed-by=ffs
kubectl delete policyreports.wgpolicyk8s.io -A -l app.kubernetes.io/managed-by=ffs   # if config.openReports.wgPolicy was on
kubectl delete crd findings.ffs.theitdept.au vulnerabilities.ffs.theitdept.au alerttargets.ffs.theitdept.au exceptions.ffs.theitdept.au
kubectl delete namespace ffs
```

Deleting the CRDs deletes every resource of those kinds, your AlertTargets and Exceptions included. Keep a copy first if you may install ffs again: `kubectl get alerttargets,exceptions -A -o yaml > ffs-inputs.yaml`. Deleting the namespace also deletes the Lease, the Secrets you created there for alert targets and registry credentials, and the agent certificate Secret that cert-manager wrote, if any. Events that ffs recorded expire on their own.

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
  expires: "${EXPIRES}"
  vexStatus: not_affected
  justification: vulnerable_code_not_present
```

`expires` is filled in as you apply it, here 90 days out (the example is [docs/examples/exception.yaml](docs/examples/exception.yaml)):

```sh
EXPIRES=$(date -u -d '+90 days' +%Y-%m-%dT%H:%M:%SZ)   # macOS: date -u -v+90d +%Y-%m-%dT%H:%M:%SZ
sed "s/\${EXPIRES}/$EXPIRES/" docs/examples/exception.yaml | kubectl apply -f -
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

- **Read-mostly RBAC.** ffs reads workloads, pods, nodes, services, ingresses, Gateway API resources (gateways, routes and ReferenceGrants) and RBAC objects. It learns whether Flux or Argo CD manages a workload from the workload's labels and annotations, never from Flux or Argo CD resources, which can carry inline Helm values. It writes only its own resources, `events.k8s.io` Events, OpenReports reports and its leader-election Lease (plus PolicyReports when enabled, TokenReviews that authenticate metrics scrapers and node agents, and SubjectAccessReviews that authorise metrics scrapers). It cannot exec into pods, create workloads or write to git.
- **Secrets.** Cluster-wide `get` only, never list or watch, used to read the pull secrets that pods and ServiceAccounts reference. Turn it off with `rbac.readPullSecrets: false`; ffs then reads Secrets only in its own namespace, for AlertTargets and registry credentials. Secret contents are used in memory only, and never logged, stored or returned by the API.
- **Node agent.** It mounts a fixed list of host paths, all read-only, and has no Kubernetes API permissions, no listening ports and no container runtime socket. The collector runs as UID 0 with every capability dropped; cataloguing runs as non-root in a separate container with no host mounts. See [docs/node-agent.md](docs/node-agent.md).
- **Runtime.** A distroless static image running as nonroot, with a read-only root filesystem, all capabilities dropped, no privilege escalation and the RuntimeDefault seccomp profile. The cataloguer runs in its own container with its own memory limit and no Kubernetes API token.
- **Supply chain.** The image is published for linux/amd64 and linux/arm64, each built natively, as one index. Images and charts are keyless-signed with cosign. Every image platform has an SPDX SBOM attestation, the index, each platform image and the chart have SLSA build provenance, and the chart pins the image by digest. A release is published only from a commit on main or a release branch that passes the test suite, and only after the release workflow has verified its published signatures, attestations and chart pin. Releases are immutable, and GitHub Actions are pinned by commit. The image also carries the package manifests of the npm packages bundled into the web UI, so its SBOMs list them.

To report a vulnerability or verify a release, see [SECURITY.md](SECURITY.md).

## Licence

Apache-2.0. See [LICENSE](LICENSE).
