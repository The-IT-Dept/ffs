# Node agent

The chart installs a small agent on every Linux node by default: a DaemonSet named `ffs-agent` in the namespace `<release namespace>-agent` (`ffs-agent` for a release in `ffs`). It reports each node's host packages, running kernel, known host binaries and cached images to the ffs controller. ffs then:

- groups identical nodes into node groups;
- matches host packages like image packages, with one finding per advisory across all nodes, on the owner `Nodes/<cluster>`;
- catalogues side-loaded images (`kind load`, `ctr import`, airgap tarballs) from a node's containerd content store, so they are no longer `unresolvable`;
- once every node reports, replaces the container runtime versions it otherwise reads from node status.

The web UI shows node groups and each node's agent status. The API serves them at `/api/v1/nodegroups` and `/api/v1/nodes/{name}`, and an image catalogued by the agent has `source` `agent`.

The agent pod has two containers. The collector reads a fixed list of read-only host paths and copies what it needs into a scratch volume. The cataloguer, the same `ffs catalog` server the controller uses, runs as non-root with no host mounts and produces the SBOMs from those copies. The collector sends reports to the controller over TLS on port 8444.

## What it reads

Every host path is mounted read-only, without mount propagation, into the collector only, under `/host`.

| Host path | Distributions | Why |
|---|---|---|
| `/etc/os-release` | all | The OS name and version, for the package ecosystem and the node group name. A symlink to `/usr/lib/os-release` is followed. |
| `/usr/bin` | all | Known host binaries. |
| `/usr/sbin` | all | Known host binaries. |
| `/usr/local/bin` | all, except image-based OSes | Known host binaries installed outside the package manager. |
| `/var/lib/dpkg` | Debian and Ubuntu nodes | The dpkg package database. |
| `/var/lib/rpm` | RHEL-like, Fedora, SUSE, Amazon Linux and Azure Linux nodes | The rpm package database. |
| `/lib/apk/db` | Alpine nodes | The apk package database. |
| `/var/lib/rancher/k3s/data` | k3s | The k3s binaries (`current/bin` and `current/bin/aux`). |
| `/var/lib/rancher/rke2/bin` | RKE2 | The RKE2 binaries: RKE2's link to the `bin` directory of its current data directory. |
| `/var/lib/containerd/io.containerd.content.v1.content` | containerd | Cached images. |
| `/var/lib/rancher/k3s/agent/containerd/io.containerd.content.v1.content` | k3s | Cached images. |
| `/var/lib/rancher/rke2/agent/containerd/io.containerd.content.v1.content` | RKE2 | Cached images. |
| `<nodeAgent.hostPaths.containerdRoot>/io.containerd.content.v1.content` | when set | Cached images, in place of the distribution's content store. |
| each `nodeAgent.hostPaths.extraBinDirs` entry | when listed | Known host binaries in other directories, each under `/usr` or `/opt`. |

In the bin directories the agent looks only for these binaries: `containerd`, `containerd-shim-runc-v2`, `runc`, `kubelet`, `k3s`, `rke2`, `crictl` and `crio`. Their Go modules are what ffs matches.

The kernel release and boot ID come from `/proc`, with no mount. The content store is read only to list cached images and to copy out the layers of a side-loaded image that ffs asks for.

Only the running kernel's packages are matched. Other installed kernels are left out of the node's inventory, and a newer one shows the node as reboot pending: `installed kernel <release> is newer than the running kernel <release>`.

A node whose agent reports but whose host inventory is not stored, or not current, shows the `host_not_inventoried` coverage gap with the reason: not inventoried yet, a host inventory that could not be read or stored, a quarantined host inventory, or no full report for longer than `nodeAgent.reportInterval` (with its jitter) plus `nodeAgent.staleAfter`. It is counted apart from fully reporting nodes.

## What it never does

- It has no Kubernetes API access. Its ServiceAccount has no Role or ClusterRole bindings; on OpenShift it has only permission to use its own SecurityContextConstraints. Its only credential is a projected token for the audience `ffs-agent`, which the Kubernetes API server does not accept.
- It never writes to the host: every mount is read-only.
- It does not exec into containers, open listening ports or use a container runtime socket. It is not `privileged` and adds no capabilities.
- It never reads container root filesystems, and never mounts `/`, `/var/lib/kubelet` or the k3s and RKE2 server directories.

The collector runs as UID 0 with every capability dropped, a read-only root filesystem, no privilege escalation and the RuntimeDefault seccomp profile, so it can read root-owned files but nothing else. The cataloguer runs as UID 65532 with no host mounts. The liveness probe runs `ffs agent check` in the collector and needs no port.

The two containers share only the directory of the cataloguer's socket. The collector stages host inputs and images into its own volume, which the cataloguer mounts read-only; the cataloguer unpacks images into a volume of its own, which is also its workers' temporary directory; and the collector keeps its heartbeat on a small volume the cataloguer does not mount.

## Why a privileged namespace

The baseline and restricted Pod Security Standards forbid `hostPath` volumes, and restricted also forbids UID 0. The agent namespace is therefore labelled `pod-security.kubernetes.io/enforce: privileged` (and `audit` and `warn`). It holds only the agent, and the ffs namespace stays restricted.

With `nodeAgent.createNamespace: false`, create the namespace yourself with those labels. `nodeAgent.namespace` must differ from the release namespace.

Treat the agent namespace like `kube-system`. Anyone who can create pods in it, directly or through a Deployment, Job or other controller, can get root on the node, because Pod Security admission there allows privileged pods and any hostPath volume. On OpenShift, such a pod can also name the agent ServiceAccount and so use the agent's SecurityContextConstraints, which allows any hostPath volume, any user and any SELinux type. Grant no one but cluster administrators rights to create pods or workloads in the agent namespace.

## Footprint

| Container | Requests | Limits |
|---|---|---|
| collector | 10m CPU, 32Mi memory | 100m CPU, 128Mi memory |
| cataloguer | 10m CPU, 32Mi memory | 400m CPU, 640Mi memory |

The limits total 500m CPU and 768Mi memory per pod, and the steady-state target is under 256Mi of memory per pod. Beyond that:

- 4 GiB of scratch space (`nodeAgent.scratchSizeLimit`), cleaned after every job: a staging volume of `nodeAgent.maxImageBytes` or 512Mi, whichever is larger, plus 256Mi, and the cataloguer's volume for the rest;
- a request for 1 GiB of ephemeral storage on the collector (`nodeAgent.scratchRequest`), so the scheduler places the agent only where staging fits and the kubelet counts it before evicting other pods for disk pressure;
- one small report every 5 minutes, and a full report with the host SBOM every 6 hours;
- one image catalogued at a time, at nice 10;
- upgrades that replace a tenth of the agent pods at a time (`nodeAgent.updateStrategy`), so a rollout across hundreds of nodes finishes within `helm --wait` and GitOps timeouts.

The collector never holds an SBOM in memory. It streams the cataloguer's answer into a file on the scratch volume, checking on the way that it is JSON, and streams the report or SBOM result to the controller from that file, which it then deletes. Its memory use does not grow with the SBOM, which the cataloguer caps at 65 MiB (the controller's 64 MiB SBOM limit plus 1 MiB). `GOMEMLIMIT` is 90% of each container's memory limit, and the cataloguer's workers get its limit less 128Mi, which the catalog server keeps for itself. A full report over `nodeAgent.maxReportBytes` is sent without its host SBOM. Images larger than `nodeAgent.maxImageBytes` are not catalogued by the agent.

Before each full report the collector checks that the controller answers, and stages and catalogues the host only when it does. When a full report is not stored (the controller is down, answers with a server error, asks for the host again, or answers `429` with `Retry-After` because it is busy), the collector keeps the host inventory it collected and resends it, after a growing, jittered backoff or at least the `Retry-After` time, without staging or cataloguing the host again. Images reports have their own backoff. While the controller is starting (connection refused, `503`), these retries are logged at Info, and as errors only once a full report interval has passed without an answer.

The liveness probe checks a heartbeat file the collector touches every minute while its loop is making progress: while it sleeps between reports, sends a report or runs a job, for as long as that step may take. A loop that stops making progress stops touching it, and the probe restarts the collector once the heartbeat is 15 minutes old. Jobs run one at a time, and the collector sends any images report that has fallen due between them.

## Turning it off

Install or upgrade with `--set nodeAgent.enabled=false`. No agent objects are installed, and the controller's agent API is not served. The chart still creates the ffs pod's NetworkPolicy, without its agent API rule (see [Trust](#trust)). What you lose:

- host package and kernel findings resolve;
- the container runtime findings that ffs reads from node status return at once;
- side-loaded images that are not catalogued yet stay `unresolvable`;
- every node shows the `node_agent_missing` coverage gap.

containerd and cri-o findings move between the `ContainerRuntime` owner and `Nodes/<cluster>` with no transitions, so they do not alert again. runc findings re-detect after an agent outage longer than `nodeAgent.runtimeGrace` (2 hours), or after you disable and re-enable the agent: node status never reports runc, so switching back resolves findings on `Nodes/<cluster>` that only runc has, and the next switch to the agent detects and alerts them again.

Exceptions written for the container runtime (owner `ContainerRuntime/containerd` or repository `containerd`) keep applying when its findings move to `Nodes/<cluster>` and back, so neither switch reopens an excepted finding.

The first agent data on a cluster is a baseline: each AlertTarget gets one summary of the node findings instead of one alert per finding. The baseline waits until every node the agent runs on is in a matched node group, or until 10 minutes (at most `nodeAgent.staleAfter`) after the first agent report, so node pools that report minutes apart share one summary. Re-enabling the agent baselines again.

## Distributions

`nodeAgent.distribution` selects the host paths: `containerd`, `k3s`, `rke2` or `crio`. The default, `auto`, looks up the cluster's Nodes when the chart is installed: a kubelet version with `+k3s` means k3s, `+rke2` means RKE2, a `cri-o://` container runtime means CRI-O, and anything else is containerd. Without Node lookup data (for example `helm template`), `auto` means containerd.

- **containerd**: `/var/lib/containerd`.
- **k3s**: the binaries under `/var/lib/rancher/k3s/data` and the content store under `/var/lib/rancher/k3s/agent/containerd`.
- **RKE2**: the binaries through `/var/lib/rancher/rke2/bin`, RKE2's link to its current data directory, and the content store under `/var/lib/rancher/rke2/agent/containerd`. The link is mounted as a hostPath of type `Directory`, so it must exist: RKE2 creates it before it starts the kubelet, and on a node without it the agent pod does not start. The link is followed once, when the collector container starts. After an in-place RKE2 upgrade or rollback, the node keeps reporting the binaries of the data directory the link pointed to when the collector started, so restart the agent pods afterwards: `kubectl rollout restart daemonset/ffs-agent -n ffs-agent`.
- **CRI-O** (`crio`): nodes report host packages and binaries, but there is no containerd content store, so side-loaded images cannot be catalogued from them. Each node shows `no containerd content store on this node; side-loaded images cannot be catalogued from it`.
- **Other containerd roots.** k0s, MicroK8s and custom installs keep containerd elsewhere. The content store mount must exist, or the agent pods never start, so set `nodeAgent.hostPaths.containerdRoot` to containerd's root directory (the agent reads `io.containerd.content.v1.content` under it):
  - k0s: `--set nodeAgent.hostPaths.containerdRoot=/var/lib/k0s/containerd`. k0s reports a `+k0s` kubelet version, which `auto` reads as containerd.
  - MicroK8s: `--set nodeAgent.hostPaths.containerdRoot=/var/snap/microk8s/common/var/lib/containerd`.

  The path must be absolute, and the chart refuses system directories such as `/run` and `/var/lib/kubelet`. It applies to every node the DaemonSet runs on, and not to `crio`.

In a cluster with mixed distributions, `auto` uses the most common one, and the content store and binary directory mounts (the k3s data directory, the RKE2 `bin` link) must exist on every node the DaemonSet runs on. Set `nodeAgent.distribution` and `nodeAgent.nodeSelector` to match one kind of node, or install one release per node pool.

## Platforms

- **GKE Autopilot** does not allow `hostPath` volumes. Install with `--set nodeAgent.enabled=false`.
- **Managed nodes** that run no DaemonSets, such as EKS Fargate and virtual nodes, are not covered. They show the `node_agent_missing` gap.
- **Other architectures.** Published images are amd64 and arm64, so `nodeAgent.architectures` is `[amd64, arm64]` and nodes of other architectures are not scheduled. Nodes outside `nodeAgent.architectures` or `nodeAgent.nodeSelector` (Windows nodes, for example), and nodes with a `NoSchedule` or `NoExecute` taint that `nodeAgent.tolerations` does not tolerate, show `not scheduled by the node agent: <reason>` (`node_agent_unsupported`), and do not hold back the switch from node status to the agent.
- **SELinux.** On SELinux-enforcing nodes the agent shows `node agent cannot read <path>: permission denied` until `nodeAgent.seLinuxType: spc_t` is set, which runs the collector, and only the collector, with that SELinux type.
- **OpenShift** needs `nodeAgent.openshift.scc: true`, which creates a SecurityContextConstraints for the agent and lets its ServiceAccount use it, and `nodeAgent.seLinuxType: spc_t`: Red Hat CoreOS enforces SELinux, so without it every node shows `node agent cannot read <path>: permission denied`.
- **Image-based OSes** (Talos, Flatcar, Container-Optimized OS, Bottlerocket) have no package database. Their nodes show `no package database (image-based OS)`, never a clean empty package list. Set `nodeAgent.packageDatabases: []` when every node runs one. A node of any other OS whose package database the agent cannot find shows `package database not mounted; set nodeAgent.packageDatabases`.
- **Private registries.** The agent pods use the top-level `imagePullSecrets`, and those Secrets must also exist in the agent namespace.

## Package database mounts

`/var/lib/dpkg` and `/var/lib/rpm` are mounted without a type check, so a node that lacks one still starts the agent. With `nodeAgent.packageDatabases: auto`, the chart mounts only the families it finds in the Nodes' OS images. Without Node lookup data (for example `helm template`) it mounts both, and the kubelet may create an empty directory under `/var/lib` on nodes that lack one. Set `nodeAgent.packageDatabases` to the families you run (for example `[dpkg]`) to avoid that.

On Fedora, RHEL 10 and SUSE, `/var/lib/rpm` is a link to `/usr/lib/sysimage/rpm`, and the mount follows the link. A host whose rpm database exists only under /usr/lib/sysimage/rpm, with no /var/lib/rpm link, shows as having no package database.

## Trust

- **TLS.** Without cert-manager, the chart generates a CA and a certificate for the agent API Service, valid for 3650 days: the Secret `ffs-agent-tls` in the release namespace and the ConfigMap `ffs-agent-ca` in the agent namespace. On upgrade it looks both up and re-emits them unchanged while the certificate has more than 30 days left (the Secret's `ffs.theitdept.au/not-after` annotation, in unix seconds), and generates a new pair otherwise. Renderers without `lookup`, such as Argo CD and `helm template`, would generate a new pair on every render, so use `nodeAgent.tls.certManager.enabled` with `nodeAgent.tls.certManager.issuerRef` and `nodeAgent.tls.caBundle` there. With cert-manager, the Certificate `ffs-agent-tls` writes a Secret of its own, `ffs-agent-cert-manager-tls`, so `nodeAgent.tls.certManager.enabled` can be switched either way: Helm and cert-manager never claim the same Secret. After you switch cert-manager off, delete `ffs-agent-cert-manager-tls` if cert-manager left it behind.
- **Authentication.** The controller checks each agent's token with a TokenReview: the audience `ffs-agent`, the agent ServiceAccount, and the node the agent pod runs on, which must match the report.
- **Which SBOMs are accepted.** An agent SBOM is accepted only as the answer to a request the controller made to that node, until 2 minutes after the request's deadline, which is `nodeAgent.workTimeout` after the request was made. The controller asks one node at a time, and only a node that runs the image in a pod and holds it complete. Its provenance (node, agent version and time) is recorded, and an image catalogued from one node's SBOM is never replaced by another node's. The agent answers every request it reaches: with the image's SBOM, a cataloguing failure (a failure of the image), or why it cannot catalogue the image (`not_found`, `layers_discarded` or `too_large`). When it does not attempt one, because too little of its time is left, its cataloguer is busy, its scratch volume cannot take the image, or the agent is stopping, it answers `skipped`, and the image is asked for again and never counted. When the controller does not take an answer (no answer, `429` or a `5xx`), the agent sends it again after about 5, 15 and then every 45 seconds, for as long as it would be accepted. A request with no answer at all by then counts as a failure of the image (the agent most likely died cataloguing it), and after two failures the image is not asked for again for 24 hours. The agent works through its requests one at a time, in order, so requests queued behind an unanswered one are not counted. A node holds at most `nodeAgent.workPerReport` requests at a time.
- **Registry first.** When the registry becomes reachable, a registry SBOM replaces the agent's; ffs retries at most every 6 hours.
- **Node groups.** Nodes share a group, and with it one stored host SBOM, only when every package field ffs matches on is the same: names, versions and architectures, the distribution, source packages, package URLs and CPEs. A host inventory that differs in any of them gets a group of its own.
- **Residual risk.** A compromised node can under-report the packages of its own host, and of an image the controller asks it to catalogue, because it controls those bytes. Its kubelet can also claim that a pod on it runs any image, so it can be the node asked. It cannot replace an image SBOM that another node or a registry supplied, or change the host inventory of nodes that report their own.

The NetworkPolicy `ffs` (`networkPolicy.enabled`, formerly `nodeAgent.networkPolicy.enabled`) selects the ffs pod, with or without the node agent, and allows:

- the agent API port, only from the agent pods, while `nodeAgent.enabled` is true;
- the metrics and health ports, from anywhere: metrics answers only requests that pass Kubernetes authentication and authorisation, and health serves only the kubelet's probes;
- the web UI and API port (the port of `config.listen`), only from the peers in `web.networkPolicy.from`, and only when `config.listen` is bound beyond loopback. The list is empty by default, so no other pod reaches the web UI; `kubectl port-forward` is not affected. See [Exposing the web UI](configuration.md#exposing-the-web-ui).

If your cluster also uses another policy engine, allow the agent namespace to reach the controller on port 8444.

**Upgrading from 0.0.1-rc.8 or earlier.**

- Release candidates rc.5 to rc.8 admitted the web UI port from every source in this NetworkPolicy, then named `ffs-agent-api` and created only with the node agent, and earlier ones created no NetworkPolicy for the ffs pod. It is now `ffs`, and the chart creates it with `nodeAgent.enabled: false` too. If you serve the web UI beyond `kubectl port-forward`, set `web.networkPolicy.from` to your proxy's pods before you upgrade: with `web.service.enabled` the chart refuses to render without it, and with a Service of your own the web UI stops answering other pods.
- Agents from rc.6 or earlier do not tell their processes apart. Until the upgrade has replaced them, the controller accounts their image requests per node rather than per agent process: after such an agent restarts, a request it was given while a request of its previous process was still open is not counted against the image if the agent dies on it.
- In rc.5 to rc.8, cert-manager wrote the agent API certificate to the Secret `ffs-agent-tls`. After the upgrade it issues `ffs-agent-cert-manager-tls` instead, and agents cannot connect until it has (the certificate volume stays empty until then), so expect a short gap in agent reports. Once the new Secret exists, the old `ffs-agent-tls` is unused and can be deleted. Delete the old `ffs-agent-tls` Secret before you set `nodeAgent.tls.certManager.enabled: false`, because Helm does not take over a Secret it did not create.

## Monitoring

The controller exports:

- `ffs_node_agent_nodes{state}`: nodes by agent state, `reporting`, `reporting_without_inventory` (reporting, but with the `host_not_inventoried` gap), `stale`, `never`, `disabled` or `unsupported` (not scheduled by the DaemonSet);
- `ffs_node_groups{kind}`: node groups by kind, `agent` or `nodeinfo`;
- `ffs_agent_reports_total{result,reason}`: reports received, `applied`, `duplicate`, `deferred` or `rejected`. Rejected reports and SBOM results carry a `reason`: `unauthenticated`, `rate_limited`, `forbidden`, `bad_request` or `too_large`;
- `ffs_agent_ingest_bytes_in_flight`: bytes of node agent report and SBOM result bodies being read and handled now.

The controller reads at most 192 MiB of reports and, separately, 64 MiB of SBOM results at once (`ffs_agent_ingest_bytes_in_flight` shows the bytes being read and handled), so `nodeAgent.maxReportBytes` is at most 192 MiB. Past that, a report waits up to 2 seconds and is then answered 429 with a `Retry-After` of 10 to 60 seconds (`deferred`), and the agent sends it again later without cataloguing the host again. An SBOM result waits while the request it answers still takes a result, and at most 9 minutes, within the agent's 10-minute request timeout; past that it is answered 503, that request is not counted against its image, and the agent sends the result again while the request takes one. A full report the controller refuses (400, 401, 403 or 413), or one the collector cannot send because it cannot read its token, the CA bundle or the spooled host SBOM, is not resent as it was: the next full report collects the host again.

With `prometheusRule.enabled`, the alert `FFSNodeAgentNotReporting` fires when node agents have stopped reporting (state `stale`) for 30 minutes. Nodes the DaemonSet does not schedule (other architectures, or a `nodeAgent.nodeSelector` mismatch) are `unsupported`, never `stale`, and do not fire it. `FFSNodeAgentNeverReported` fires when no agent has reported for an hour while nodes wait for their first report, as when the agent pods cannot pull their image, are refused by Pod Security admission, cannot mount a host path or cannot reach the controller.

## Chart values

These are top-level Helm values. The ones the controller also reads are in [configuration.md](configuration.md).

| Value | Default | Meaning |
|---|---|---|
| `nodeAgent.enabled` | `true` | Install the node agent. |
| `nodeAgent.namespace` | `""` | The agent namespace; empty means `<release namespace>-agent`. |
| `nodeAgent.createNamespace` | `true` | Create the agent namespace with the privileged Pod Security labels. |
| `nodeAgent.distribution` | `auto` | Host path layout: `auto`, `containerd`, `k3s`, `rke2` or `crio`. |
| `nodeAgent.packageDatabases` | `auto` | Package databases to mount: `auto`, or a list of `dpkg`, `rpm` and `apk`. An empty list means an image-based OS. |
| `nodeAgent.hostPaths.extraBinDirs` | `[]` | Extra host directories searched for the known binaries, each under `/usr` or `/opt`, listed once, and not `/usr/bin`, `/usr/sbin` or `/usr/local/bin`, which are searched already. |
| `nodeAgent.hostPaths.containerdRoot` | `""` | containerd's root directory, for k0s, MicroK8s or a custom root, such as `/var/lib/k0s/containerd`; the content store under it replaces the distribution's. Empty uses the distribution's. See [Distributions](#distributions). |
| `nodeAgent.architectures` | `[amd64, arm64]` | Node architectures the DaemonSet schedules on; at least one. Published images are amd64 and arm64. |
| `nodeAgent.nodeSelector` | `{kubernetes.io/os: linux}` | Node selector of the agent pods. |
| `nodeAgent.tolerations` | `[{operator: Exists}]` | Tolerations of the agent pods; the default runs on every node. Nodes with a taint they do not tolerate show as not scheduled by the node agent. |
| `nodeAgent.priorityClassName` | `""` | Priority class of the agent pods. |
| `nodeAgent.resources` | see [Footprint](#footprint) | Requests and limits of the `collector` and `catalog` containers. Memory limits are byte counts or quantities such as `640Mi` or `1.5Gi`: `GOMEMLIMIT` is 90% of each, and the cataloguer's workers get its limit less 128Mi, so it must be at least 192Mi. |
| `nodeAgent.scratchSizeLimit` | `4Gi` | Total size limit of the agent's scratch volumes. The staging volume takes `nodeAgent.maxImageBytes` or 512Mi, whichever is larger, plus 256Mi, and the cataloguer's volume the rest, which must be at least 512Mi. |
| `nodeAgent.scratchRequest` | `1Gi` | Ephemeral storage the collector requests for the scratch volumes. An `ephemeral-storage` request in `nodeAgent.resources.collector` takes precedence; empty requests none. |
| `nodeAgent.updateStrategy` | `{type: RollingUpdate, rollingUpdate: {maxUnavailable: 10%}}` | Update strategy of the agent DaemonSet. |
| `nodeAgent.maxImageBytes` | `1Gi` | Largest image the agent catalogues. |
| `nodeAgent.port` | `8444` | Port of the agent API on the controller; not the port of `config.listen` (8080 by default), 8081 or 8443. |
| `nodeAgent.exposedNodes` | `""` | Node label selector; host findings on matching nodes count as exposed. |
| `nodeAgent.reportInterval` | `6h` | Time between full host reports per node. |
| `nodeAgent.imageListInterval` | `5m` | Time between cached-image checks, which are also the heartbeat. |
| `nodeAgent.staleAfter` | `30m` | Time without a report before a node shows `node agent not reporting since <time>`. |
| `nodeAgent.runtimeGrace` | `2h` | How long nodes must lack fresh reports before container runtime findings move back to the node-status owner. |
| `nodeAgent.maxReportBytes` | `33554432` | Largest agent report accepted (32 MiB), at most 192 MiB; also a quantity such as `32Mi`. |
| `nodeAgent.workPerReport` | `3` | Image SBOM requests handed out with each report, 0 to 10. |
| `nodeAgent.workTimeout` | `20m` | How long a request stays with the node it was offered to. With `nodeAgent.imageListInterval` it must be shorter than `nodeAgent.staleAfter`: the agent reports between jobs, not during one. |
| `nodeAgent.tls.certManager.enabled` | `false` | Issue the agent API certificate with cert-manager instead of the chart. |
| `nodeAgent.tls.certManager.issuerRef` | `{}` | The cert-manager issuer reference. |
| `nodeAgent.tls.caBundle` | `""` | PEM CA bundle the agents trust; required with cert-manager. |
| `nodeAgent.seLinuxType` | `""` | SELinux type of the collector container, for example `spc_t`. |
| `nodeAgent.openshift.scc` | `false` | Create a SecurityContextConstraints for the agent and bind its ServiceAccount to it. |
| `nodeAgent.networkPolicy.enabled` | unset | Deprecated: use the top-level `networkPolicy.enabled` ([configuration.md](configuration.md#helm-only-values)). When set, v0.0.2 still uses it in place of `networkPolicy.enabled` and the install notes say it is deprecated; v0.0.3 removes it. See [Trust](#trust). |
