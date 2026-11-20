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
| `/var/lib/rancher/rke2/data` | RKE2 | The RKE2 binaries (the newest `*/bin`). |
| `/var/lib/containerd/io.containerd.content.v1.content` | containerd | Cached images. |
| `/var/lib/rancher/k3s/agent/containerd/io.containerd.content.v1.content` | k3s | Cached images. |
| `/var/lib/rancher/rke2/agent/containerd/io.containerd.content.v1.content` | RKE2 | Cached images. |
| each `nodeAgent.hostPaths.extraBinDirs` entry | when listed | Known host binaries in other directories, each under `/usr` or `/opt`. |

In the bin directories the agent looks only for these binaries: `containerd`, `containerd-shim-runc-v2`, `runc`, `kubelet`, `k3s`, `rke2`, `crictl` and `crio`. Their Go modules are what ffs matches.

The kernel release and boot ID come from `/proc`, with no mount. The content store is read only to list cached images and to copy out the layers of a side-loaded image that ffs asks for.

Only the running kernel's packages are matched. Other installed kernels are left out of the node's inventory, and a newer one shows the node as reboot pending: `installed kernel <release> is newer than the running kernel <release>`.

## What it never does

- It has no Kubernetes API access. Its ServiceAccount has no Role or ClusterRole bindings; on OpenShift it has only permission to use its own SecurityContextConstraints. Its only credential is a projected token for the audience `ffs-agent`, which the Kubernetes API server does not accept.
- It never writes to the host: every mount is read-only.
- It does not exec into containers, open listening ports or use a container runtime socket. It is not `privileged` and adds no capabilities.
- It never reads container root filesystems, and never mounts `/`, `/var/lib/kubelet` or the k3s and RKE2 server directories.

The collector runs as UID 0 with every capability dropped, a read-only root filesystem, no privilege escalation and the RuntimeDefault seccomp profile, so it can read root-owned files but nothing else. The cataloguer runs as UID 65532 with no host mounts. The liveness probe runs `ffs agent check` in the collector and needs no port.

## Why a privileged namespace

The baseline and restricted Pod Security Standards forbid `hostPath` volumes, and restricted also forbids UID 0. The agent namespace is therefore labelled `pod-security.kubernetes.io/enforce: privileged` (and `audit` and `warn`). It holds only the agent, and the ffs namespace stays restricted.

With `nodeAgent.createNamespace: false`, create the namespace yourself with those labels. `nodeAgent.namespace` must differ from the release namespace.

## Footprint

| Container | Requests | Limits |
|---|---|---|
| collector | 10m CPU, 32Mi memory | 100m CPU, 128Mi memory |
| cataloguer | 10m CPU, 32Mi memory | 400m CPU, 640Mi memory |

The limits total 500m CPU and 768Mi memory per pod, and the steady-state target is under 256Mi of memory per pod. Beyond that:

- a 4 GiB scratch volume (`nodeAgent.scratchSizeLimit`), cleaned after every job;
- one small report every 5 minutes, and a full report with the host SBOM every 6 hours;
- one image catalogued at a time, at nice 10.

The collector holds each SBOM once. It decodes the cataloguer's answer in one pass and sends the report or SBOM result without a second copy. The cataloguer's answer is capped at 65 MiB (the controller's 64 MiB SBOM limit plus 1 MiB), so a forwarded image SBOM stays inside the collector's 128Mi limit. A full report over `nodeAgent.maxReportBytes` is sent without its host SBOM. Images larger than `nodeAgent.maxImageBytes` are not catalogued by the agent.

## Turning it off

Install or upgrade with `--set nodeAgent.enabled=false`. No agent objects are installed, and the controller's agent API is not served. What you lose:

- host package and kernel findings resolve;
- the container runtime findings that ffs reads from node status return at once;
- side-loaded images that are not catalogued yet stay `unresolvable`;
- every node shows the `node_agent_missing` coverage gap.

containerd and cri-o findings move between the `ContainerRuntime` owner and `Nodes/<cluster>` with no transitions, so they do not alert again. runc findings re-detect after an agent outage longer than `nodeAgent.runtimeGrace` (2 hours), or after you disable and re-enable the agent: node status never reports runc, so switching back resolves findings on `Nodes/<cluster>` that only runc has, and the next switch to the agent detects and alerts them again.

Exceptions written for the container runtime (owner `ContainerRuntime/containerd` or repository `containerd`) keep applying when its findings move to `Nodes/<cluster>` and back, so neither switch reopens an excepted finding.

The first agent data on a cluster is a baseline: each AlertTarget gets one summary of the node findings instead of one alert per finding. Re-enabling the agent baselines again.

## Distributions

`nodeAgent.distribution` selects the host paths: `containerd`, `k3s`, `rke2` or `crio`. The default, `auto`, looks up the cluster's Nodes when the chart is installed: a kubelet version with `+k3s` means k3s, `+rke2` means RKE2, a `cri-o://` container runtime means CRI-O, and anything else is containerd. Without Node lookup data (for example `helm template`), `auto` means containerd.

- **containerd**: `/var/lib/containerd`.
- **k3s**: the binaries under `/var/lib/rancher/k3s/data` and the content store under `/var/lib/rancher/k3s/agent/containerd`.
- **RKE2**: the binaries under `/var/lib/rancher/rke2/data` and the content store under `/var/lib/rancher/rke2/agent/containerd`.
- **CRI-O** (`crio`): nodes report host packages and binaries, but there is no containerd content store, so side-loaded images cannot be catalogued from them. Each node shows `no containerd content store on this node; side-loaded images cannot be catalogued from it`.

In a cluster with mixed distributions, `auto` uses the most common one, and the content store and data directory mounts must exist on every node the DaemonSet runs on. Set `nodeAgent.distribution` and `nodeAgent.nodeSelector` to match one kind of node, or install one release per node pool.

## Platforms

- **GKE Autopilot** does not allow `hostPath` volumes. Install with `--set nodeAgent.enabled=false`.
- **Managed nodes** that run no DaemonSets, such as EKS Fargate, virtual nodes and Windows nodes, are not covered. They show the `node_agent_missing` gap.
- **Other architectures.** Published images are amd64, so `nodeAgent.architectures` is `[amd64]` and other nodes are not scheduled.
- **SELinux.** On SELinux-enforcing nodes the agent shows `node agent cannot read <path>: permission denied` until `nodeAgent.seLinuxType: spc_t` is set, which runs the collector, and only the collector, with that SELinux type.
- **OpenShift** needs `nodeAgent.openshift.scc: true`, which creates a SecurityContextConstraints for the agent and lets its ServiceAccount use it.
- **Image-based OSes** (Talos, Flatcar, Container-Optimized OS, Bottlerocket) have no package database. Their nodes show `no package database (image-based OS)`, never a clean empty package list. Set `nodeAgent.packageDatabases: []` when every node runs one.
- **Private registries.** The agent pods use the top-level `imagePullSecrets`, and those Secrets must also exist in the agent namespace.

## Package database mounts

`/var/lib/dpkg` and `/var/lib/rpm` are mounted without a type check, so a node that lacks one still starts the agent. With `nodeAgent.packageDatabases: auto`, the chart mounts only the families it finds in the Nodes' OS images. Without Node lookup data (for example `helm template`) it mounts both, and the kubelet may create an empty directory under `/var/lib` on nodes that lack one. Set `nodeAgent.packageDatabases` to the families you run (for example `[dpkg]`) to avoid that.

On Fedora, RHEL 10 and SUSE, `/var/lib/rpm` is a link to `/usr/lib/sysimage/rpm`, and the mount follows the link. A host whose rpm database exists only under /usr/lib/sysimage/rpm, with no /var/lib/rpm link, shows as having no package database.

## Trust

- **TLS.** Without cert-manager, the chart generates a CA and a certificate for the agent API Service, valid for 3650 days: the Secret `ffs-agent-tls` in the release namespace and the ConfigMap `ffs-agent-ca` in the agent namespace. On upgrade it looks both up and re-emits them unchanged while the certificate has more than 30 days left (the Secret's `ffs.theitdept.au/not-after` annotation, in unix seconds), and generates a new pair otherwise. Renderers without `lookup`, such as Argo CD and `helm template`, would generate a new pair on every render, so use `nodeAgent.tls.certManager.enabled` with `nodeAgent.tls.certManager.issuerRef` and `nodeAgent.tls.caBundle` there.
- **Authentication.** The controller checks each agent's token with a TokenReview: the audience `ffs-agent`, the agent ServiceAccount, and the node the agent pod runs on, which must match the report.
- **Which SBOMs are accepted.** An agent SBOM is accepted only for an image that a pod on that node runs. Its provenance (node, agent version and time) is recorded.
- **Registry first.** When the registry becomes reachable, a registry SBOM replaces the agent's; ffs retries at most every 6 hours.
- **Residual risk.** A compromised node can under-report the packages of images that only it runs, and of its own host, because it controls those bytes. It cannot change the inventory of images that other nodes or a registry supply.

The NetworkPolicy `ffs-agent-api` (`nodeAgent.networkPolicy.enabled`) allows the agent API port only from the agent pods. The web UI, metrics and health ports stay open as before. If your cluster also uses another policy engine, allow the agent namespace to reach the controller on port 8444.

## Monitoring

The controller exports:

- `ffs_node_agent_nodes{state}`: nodes by agent state, `reporting`, `stale`, `never` or `disabled`;
- `ffs_node_groups{kind}`: node groups by kind, `agent` or `nodeinfo`;
- `ffs_agent_reports_total{result}`: reports received, `applied`, `duplicate` or `rejected`.

With `prometheusRule.enabled`, the alert `FFSNodeAgentNotReporting` fires when node agents have stopped reporting (state `stale`) for 30 minutes. Nodes the DaemonSet never schedules (other architectures, Windows or virtual nodes) stay `never`. They show in the gauge and in the node coverage gap, and do not fire the alert.

## Chart values

These are top-level Helm values. The ones the controller also reads are in [configuration.md](configuration.md).

| Value | Default | Meaning |
|---|---|---|
| `nodeAgent.enabled` | `true` | Install the node agent. |
| `nodeAgent.namespace` | `""` | The agent namespace; empty means `<release namespace>-agent`. |
| `nodeAgent.createNamespace` | `true` | Create the agent namespace with the privileged Pod Security labels. |
| `nodeAgent.distribution` | `auto` | Host path layout: `auto`, `containerd`, `k3s`, `rke2` or `crio`. |
| `nodeAgent.packageDatabases` | `auto` | Package databases to mount: `auto`, or a list of `dpkg`, `rpm` and `apk`. An empty list means an image-based OS. |
| `nodeAgent.hostPaths.extraBinDirs` | `[]` | Extra host directories searched for the known binaries, each under `/usr` or `/opt`. |
| `nodeAgent.architectures` | `[amd64]` | Node architectures the DaemonSet schedules on. |
| `nodeAgent.nodeSelector` | `{kubernetes.io/os: linux}` | Node selector of the agent pods. |
| `nodeAgent.tolerations` | `[{operator: Exists}]` | Tolerations of the agent pods; the default runs on every node. |
| `nodeAgent.priorityClassName` | `""` | Priority class of the agent pods. |
| `nodeAgent.resources` | see [Footprint](#footprint) | Requests and limits of the `collector` and `catalog` containers. |
| `nodeAgent.scratchSizeLimit` | `4Gi` | Size limit of the scratch volume; at least 1Gi, and more than `nodeAgent.maxImageBytes` plus 256Mi. |
| `nodeAgent.maxImageBytes` | `1Gi` | Largest image the agent catalogues. |
| `nodeAgent.port` | `8444` | Port of the agent API on the controller; not 8080, 8081 or 8443. |
| `nodeAgent.exposedNodes` | `""` | Node label selector; host findings on matching nodes count as exposed. |
| `nodeAgent.reportInterval` | `6h` | Time between full host reports per node. |
| `nodeAgent.imageListInterval` | `5m` | Time between cached-image checks, which are also the heartbeat. |
| `nodeAgent.staleAfter` | `30m` | Time without a report before a node shows `node agent not reporting since <time>`. |
| `nodeAgent.runtimeGrace` | `2h` | How long nodes must lack fresh reports before container runtime findings move back to the node-status owner. |
| `nodeAgent.maxReportBytes` | `33554432` | Largest agent report accepted (32 MiB); also a quantity such as `32Mi`. |
| `nodeAgent.workPerReport` | `3` | Image SBOM requests handed out with each report, 0 to 10. |
| `nodeAgent.workTimeout` | `30m` | How long a request stays with the node it was offered to. |
| `nodeAgent.tls.certManager.enabled` | `false` | Issue the agent API certificate with cert-manager instead of the chart. |
| `nodeAgent.tls.certManager.issuerRef` | `{}` | The cert-manager issuer reference. |
| `nodeAgent.tls.caBundle` | `""` | PEM CA bundle the agents trust; required with cert-manager. |
| `nodeAgent.seLinuxType` | `""` | SELinux type of the collector container, for example `spc_t`. |
| `nodeAgent.openshift.scc` | `false` | Create a SecurityContextConstraints for the agent and bind its ServiceAccount to it. |
| `nodeAgent.networkPolicy.enabled` | `true` | Create the NetworkPolicy that limits the agent API to the agent pods. |
