# Configuration

ffs reads its configuration from `/etc/ffs/config.yaml`. The Helm chart renders that file from the `config` block in `values.yaml`, so every key below is set as `config.<key>` in Helm values. For example, `catalog.concurrency` is `--set config.catalog.concurrency=4`.

Durations are Go duration strings (`90s`, `5m`, `48h`). Unknown keys are rejected at startup, and every invalid value is reported at once.

## ffs configuration

| Key | Default | Meaning |
|---|---|---|
| `clusterName` | `default` | Cluster name shown in findings, alerts, the API `cluster` field and the dashboard. |
| `namespace` | release namespace | The ffs install namespace. It holds the leader-election Lease, AlertTarget Secrets and the operator registry Secret. Exceptions in this namespace apply cluster-wide, and cluster-level Findings are written here. The chart sets it from the release; it is not a Helm value. |
| `deploymentName` | release name | The ffs Deployment. Feed-staleness, Finding-cap and cluster-level Events are attached to it. The chart sets it from the release; it is not a Helm value. |
| `storePath` | `/var/lib/ffs/ffs.db` | Path of the SQLite store. The chart requires it to be under `dataDir`, because only `dataDir` is on the persistent volume. |
| `dataDir` | `/var/lib/ffs` | Directory for the store and feed data, including the Grype database. The chart mounts the persistent volume here. |
| `listen` | `127.0.0.1:8080` | Listen address of the dashboard and read-only API. The default is reachable only through `kubectl port-forward`. See [Exposing the dashboard](#exposing-the-dashboard). |
| `allowedHosts` | `[]` | Host names the dashboard and API answer to besides `localhost` and IP addresses, for example the name your authenticating proxy forwards. Requests for any other host get `421 Misdirected Request`, which stops a web page from reading the API through DNS rebinding while you port-forward. Names only, without scheme or port. With `web.service.enabled`, the chart adds the Service's DNS names. |
| `dashboardURL` | `""` | External dashboard URL. When set, alerts link to `<dashboardURL>/vulnerabilities/<advisory-id>`. Must be an absolute http(s) URL. |
| `catalog.socket` | `/run/ffs/catalog.sock` | Unix socket between the controller and catalog containers. The chart mounts its directory in both. |
| `catalog.timeout` | `10m` | Time limit for cataloguing one image. |
| `catalog.maxImageBytes` | `10737418240` (10 GiB) | Largest image catalogued, measured as the total of its compressed layers. Larger images are not catalogued; they show `catalogFailed` with the reason. |
| `catalog.concurrency` | `2` | Images catalogued at once. The chart also passes it to the catalog container. |
| `registry.operatorSecret` | `""` | Name of a `kubernetes.io/dockerconfigjson` Secret in the ffs namespace. Its credentials are tried alongside anonymous access and the pull secrets of the pod and its ServiceAccount. Use it for registries whose credentials only the nodes hold. |
| `registry.mirrors` | `{}` | Registry mirror rewrite map, from registry host to mirror base, for example `docker.io: mirror.example.com/dockerhub`. Pulls for that registry go to the mirror; images keep their original names everywhere else. |
| `registry.readPullSecrets` | `true` | Whether ffs reads the pull secrets of pods and ServiceAccounts. The chart sets it from `rbac.readPullSecrets`; it is not set under `config`. When false, private images that need those secrets show as `unresolvable`. |
| `feeds.grypedb.enabled` | `true` | Use the Grype vulnerability database, the authority for matching. |
| `feeds.grypedb.url` | `https://grype.anchore.io/databases/v6/latest.json` | The database's `latest.json` URL. The download is checked against the sha256 it lists. |
| `feeds.grypedb.interval` | `1h` | How often to check for a new database. New builds appear about daily. |
| `feeds.grypedb.staleAfter` | `48h` | Age after which the feed is reported stale. Must be greater than `interval`. |
| `feeds.osv.enabled` | `true` | Use OSV.dev, the fast path for new and changed advisories. |
| `feeds.osv.url` | `https://osv-vulnerabilities.storage.googleapis.com` | Base URL of the OSV bucket. |
| `feeds.osv.interval` | `5m` | How often to poll for changed records, per ecosystem present in the inventory. |
| `feeds.osv.staleAfter` | `2h` | Age after which the feed is reported stale. |
| `feeds.cvelist.enabled` | `true` | Use the CVE List V5 hourly deltas for CNA severity and upstream-runtime version ranges. |
| `feeds.cvelist.url` | `https://github.com/CVEProject/cvelistV5/releases/download` | Base URL of the release assets. |
| `feeds.cvelist.interval` | `1h` | How often to fetch the delta. |
| `feeds.cvelist.staleAfter` | `6h` | Age after which the feed is reported stale. |
| `feeds.kev.enabled` | `true` | Use the CISA Known Exploited Vulnerabilities catalogue. |
| `feeds.kev.url` | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | Full URL of the catalogue. |
| `feeds.kev.interval` | `1h` | How often to check it, with a conditional GET. |
| `feeds.kev.staleAfter` | `24h` | Age after which the feed is reported stale. |
| `feeds.epss.enabled` | `true` | Use EPSS exploit-probability scores. |
| `feeds.epss.url` | `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` | Full URL of the daily scores file. |
| `feeds.epss.interval` | `24h` | How often to fetch it. |
| `feeds.epss.staleAfter` | `72h` | Age after which the feed is reported stale. |
| `feeds.eol.enabled` | `true` | Use endoflife.date for end-of-life status. |
| `feeds.eol.url` | `https://endoflife.date/api/v1` | Base URL of the endoflife.date API. |
| `feeds.eol.interval` | `24h` | How often to refresh it. |
| `feeds.eol.staleAfter` | `72h` | Age after which the feed is reported stale. |
| `feeds.nvd.enabled` | `false` | Reserved; not supported in v0.0.1. Setting it to `true` is rejected at startup. |
| `feeds.nvd.url` | `https://services.nvd.nist.gov/rest/json/cves/2.0` | Reserved; not supported in v0.0.1. |
| `feeds.nvd.interval` | `0s` | Reserved; not supported in v0.0.1. |
| `feeds.nvd.staleAfter` | `0s` | Reserved; not supported in v0.0.1. |
| `feeds.chainguardOSV.enabled` | `false` | Add the Chainguard and Wolfi OSV data to the OSV feed, on the OSV schedule. That data is licensed CC-BY-NC-ND-4.0; check its terms before enabling. Only `enabled` is read. |
| `feeds.chainguardOSV.url` | `https://packages.cgr.dev/chainguard/osv` | Not read; only `enabled` is read. |
| `feeds.chainguardOSV.interval` | `0s` | Not read; only `enabled` is read. |
| `feeds.chainguardOSV.staleAfter` | `0s` | Not read; only `enabled` is read. |
| `priority.epssHigh` | `0.5` | EPSS score at or above which a finding is ranked `high`. Modifiers such as won't-fix and not running still apply. |
| `priority.epssBump` | `0.1` | EPSS score at or above which a finding moves up one priority, but not above `high`. Must satisfy `0 < epssBump <= epssHigh <= 1`. |
| `exposure.internalIngressClasses` | `[]` | IngressClass names whose Ingresses do not count as exposure outside the cluster. |
| `exposure.internalGatewayClasses` | `[]` | GatewayClass names whose Gateways do not count as exposure outside the cluster. |
| `exposure.internalGateways` | `[]` | Gateways, as `namespace/name`, that do not count as exposure outside the cluster. |
| `exposure.internalLBAnnotations` | `{}` | Service annotations that mark a LoadBalancer as internal, as annotation key to value. The value `*` matches any value. |
| `crd.minPriority` | `high` | Lowest priority written as a `Finding` resource. Everything is still in the API and dashboard. |
| `crd.maxFindings` | `2000` | Most `Finding` resources kept; `0` is unlimited. Over the cap the lowest priorities are dropped first, and ffs reports it with an Event and a metric. |
| `events.minPriority` | `high` | Lowest priority whose transitions emit Kubernetes Events. |
| `openReports.mode` | `auto` | OpenReports output: `auto` writes reports when the `openreports.io` CRD exists, `on` always writes them, `off` never does. |
| `openReports.maxResults` | `100` | Most results in one report. |
| `openReports.wgPolicy` | `false` | Also write `wgpolicyk8s.io` PolicyReports. The chart grants the extra RBAC only when this is true. |
| `exceptions.maxDuration` | `8760h` | Longest an Exception may run, from now to its `expires`. At most `8760h` (one year). |
| `retention.resolved` | `2160h` | How long resolved findings, their history and the alert delivery log are kept. |
| `upgrades.enabled` | `true` | Look for image upgrades that fix findings. |
| `upgrades.maxCandidatesPerRepo` | `4` | Candidate tags scored per image repository and pass, from 1 to 4. |
| `upgrades.dailyAt` | `03:00` | Time of the daily upgrade pass, `HH:MM` in UTC. |
| `upgrades.overrides` | `{}` | Per-repository tag parsing, keyed by normalised repository (for example `docker.io/bitnami/postgresql`). Each entry has `pattern`, a regular expression with a named group `version` and optional `suffix` and `revision`, and `ignore`, a list of tag globs dropped before parsing. |
| `upgrades.kubernetesReleaseURL` | `""` | Base URL for Kubernetes patch releases. Empty means `https://dl.k8s.io/release`. |

## Helm-only values

These values configure the chart itself and are not part of `config.yaml`.

| Value | Default | Meaning |
|---|---|---|
| `image.repository` | `ghcr.io/the-it-dept/ffs` | Image repository. |
| `image.tag` | `""` | Image tag. Empty uses the chart's `appVersion`. |
| `image.digest` | set by the release | Image digest. When set it replaces the tag. Released charts pin it. |
| `image.pullPolicy` | `IfNotPresent` | Image pull policy. |
| `imagePullSecrets` | `[]` | Pull secrets for the ffs image itself. |
| `rbac.readPullSecrets` | `true` | Grant cluster-wide `get` on Secrets so pull secrets of pods and ServiceAccounts can be read. When false, private images that need them show as `unresolvable`. |
| `controller.resources` | requests `200m` CPU and `512Mi` memory, limit `1Gi` memory | Controller container resources. |
| `controller.tmpSizeLimit` | `1Gi` | Size limit of the controller's `/tmp` volume. |
| `catalog.resources` | requests `100m` CPU and `256Mi` memory, limit `2Gi` memory | Catalog container resources. |
| `catalog.scratchSizeLimit` | `20Gi` | Size limit of the catalog container's scratch volume. |
| `catalog.scratchLimit` | `19327352832` (18 GiB) | Scratch space the catalogue jobs may use together, as a byte count or a quantity such as `18Gi`. It must be greater than 0 and below `catalog.scratchSizeLimit`, so a job is refused before the kubelet evicts the pod; the chart refuses to render otherwise. |
| `persistence.size` | `20Gi` | Size of the volume for the store and feed data. |
| `persistence.storageClass` | `""` | Storage class; empty uses the cluster default. |
| `persistence.existingClaim` | `""` | Use an existing PersistentVolumeClaim instead of creating one. |
| `podAnnotations` | `{}` | Extra pod annotations. |
| `podLabels` | `{}` | Extra pod labels. |
| `nodeSelector` | `{}` | Pod node selector. |
| `tolerations` | `[]` | Pod tolerations. |
| `affinity` | `{}` | Pod affinity. |
| `priorityClassName` | `""` | Pod priority class. |
| `web.service.enabled` | `false` | Create a ClusterIP Service for the dashboard. Requires `config.listen` bound beyond loopback. |
| `web.service.port` | `8080` | Port of the dashboard Service. |
| `metrics.service.enabled` | `false` | Create the metrics Service. |
| `metrics.service.port` | `8443` | Port of the metrics Service. |
| `metrics.serviceMonitor.enabled` | `false` | Create a Prometheus Operator ServiceMonitor (and the metrics Service). |
| `metrics.serviceMonitor.interval` | `60s` | Scrape interval. |
| `metrics.serviceMonitor.labels` | `{}` | Extra ServiceMonitor labels. |
| `prometheusRule.enabled` | `false` | Create a PrometheusRule with the ffs alert rules. |
| `prometheusRule.labels` | `{}` | Extra PrometheusRule labels. |
| `grafanaDashboard.enabled` | `false` | Create a ConfigMap holding the Grafana dashboard. |
| `grafanaDashboard.namespace` | `""` | Namespace of the dashboard ConfigMap; empty uses the release namespace. |
| `grafanaDashboard.labels` | `grafana_dashboard: "1"` | Dashboard ConfigMap labels, including the one the Grafana sidecar selects on. |
| `grafanaDashboard.annotations` | `{}` | Extra dashboard ConfigMap annotations. |

Metrics are served on port 8443 behind Kubernetes authentication and authorisation. A scraper needs `get` on the `/metrics` non-resource URL, which the chart's ClusterRole `ffs-metrics-reader` grants; bind it to the scraper's ServiceAccount.

## Exposing the dashboard

The dashboard and API have no authentication. By default they listen on `127.0.0.1:8080` inside the pod, so they are reachable only through `kubectl -n ffs port-forward deploy/ffs 8080`, which needs RBAC `pods/portforward` in the ffs namespace.

To serve them to more people, put your own authenticating proxy (for example oauth2-proxy) in front:

```yaml
config:
  listen: 0.0.0.0:8080
  allowedHosts:
    - ffs.example.com
web:
  service:
    enabled: true
```

The dashboard answers only requests addressed to `localhost`, an IP address, or a name in `config.allowedHosts`. The chart adds the Service's own names (`ffs-web`, `ffs-web.<namespace>`, `ffs-web.<namespace>.svc` and `ffs-web.<namespace>.svc.cluster.local`). If your proxy forwards the original host name, as oauth2-proxy does by default, list that name in `allowedHosts`.

This creates the ClusterIP Service `ffs-web`. Anything that can reach that Service can read everything the dashboard shows, so restrict it with a NetworkPolicy to the proxy alone, and do not expose the Service directly through an Ingress or Gateway.
