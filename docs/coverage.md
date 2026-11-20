# Coverage

ffs never reports an image as clean when it could not see inside it. Every image has a status (`pending`, `catalogued`, `unresolvable` or `catalogFailed`) with a reason, and a coverage class: `full` when it is catalogued with nothing ffs knows it missed, `partial` when it is catalogued with known gaps, and `none` when ffs could not see into it. The API returns these as `status`, `statusReason`, `coverage` and `gaps` on every image. The web UI shows how many images in use it sees in full detail next to every count, marks what it cannot see with a hatched pattern, and lists every gap with what to do on its Coverage page.

This page lists what ffs cannot see, and what it shows when it meets it.

## Gaps and what to do

The Coverage page and the API (`/api/v1/coverage`) report each gap with a code and a remedy:

| Gap code | Gap | Remedy | What to do |
|---|---|---|---|
| `pending` | not catalogued yet | `wait` | Queued; ffs catalogues it shortly. |
| `unresolvable_auth` | registry refused access | `add_pull_secret` | Give ffs a pull secret that can read this repository. |
| `unresolvable_sideloaded` | loaded onto nodes, not in a registry | `enable_node_agent` | The node agent catalogues side-loaded images from the node. |
| `unresolvable_notfound` | not found in the registry | `enable_node_agent` | Push it to a registry ffs can reach, or let the node agent catalogue it. |
| `unresolvable_unreachable` | registry not reachable | `check_network` | Allow ffs to reach the registry, or configure a mirror. |
| `unresolvable_other` | could not be resolved | `check_reference` | Check the image reference; the reason is shown. |
| `layers_discarded` | layers discarded on every node | `repull_image` | Pull the image again on a node, or push it to a registry. |
| `catalog_failed` | cataloguing failed | `retry_later` | ffs retries after the quarantine; the reason is shown. |
| `attestation_partial` | attested SBOM lists no executables | `informational` | Executables were not measured; ffs relies on the attested package list. |
| `unattributed_executables` | executables without package metadata | `informational` | Copied-in binaries carry no package metadata, so ffs cannot match them. |
| `rust_no_auditable` | Rust binaries without cargo-auditable | `build_with_auditable` | Build Rust binaries with cargo-auditable so their crates can be matched. |
| `cpe_only_classifier` | daily, CPE-based coverage only | `informational` | Matched daily against CPE data; the fast path does not cover the software listed. |
| `node_agent_missing` | kernel and host packages not inventoried | `enable_node_agent` | Enable the node agent, or check why it is not reporting. |
| `node_agent_blocked` | node agent cannot read host paths | `check_host_permissions` | Allow the node agent to read its host paths (SELinux or policy). |
| `no_package_database` | no package database (image-based OS) | `informational` | Host packages are not inventoried on image-based operating systems. |
| `content_store_unreadable` | no containerd content store | `informational` | Side-loaded images on this node cannot be catalogued from it. |
| `feed_stale` | feed out of date | `check_feed_access` | Check that ffs can reach the feed; the last error is shown. |

## Blind spots

### Software the cataloguer cannot attribute

Rust binaries built without cargo-auditable, bundled or minified JavaScript, copied-in binaries that no classifier recognises, runtimes installed by hand, UPX-packed Go binaries, and the main module of Go binaries built with `-buildvcs=false` (it has no version).

**What ffs shows:** the image is marked partial coverage, with notes such as `3 executables not attributed to any package` and `1 Rust binaries built without cargo-auditable`. No findings for that software does not mean it has no vulnerabilities.

### Images only the kubelet can pull

Images whose credentials only the kubelet holds, through a credential-provider plugin or KEP-4412 service-account tokens; images pulled through a node-level registry mirror that the mirror map does not cover; and side-loaded images (`ctr import`, `kind load`, k3s airgap tarballs), whose image ID is a node-local config digest.

**What ffs shows:** the image is `unresolvable`, with the reason, for example `image ID is a node-local config digest and the container image has no tag to look up in a registry`. A registry that ffs itself cannot reach (DNS, refused or timed-out connections, blocked egress) gives `registry not reachable from ffs for <repository>: <problem>` after about five minutes of failures, and is retried hourly. It is never shown as clean, and it is retried periodically. Two settings narrow the gap:
- `registry.operatorSecret` supplies registry credentials that otherwise only the nodes hold;
- `registry.mirrors` is a registry mirror rewrite map, so pulls go where the nodes pull from.

The node agent closes most of the rest. When a side-loaded image, or one ffs cannot pull, is held complete in the containerd content store of a node whose pods run it, ffs asks that node's agent to catalogue it there. The image is then `catalogued` with `source` `agent`, until a registry SBOM replaces it. What remains `unresolvable`:
- images whose layers containerd discarded after unpacking them, shown as `image layers were discarded by containerd on every node that holds the image`;
- images on CRI-O nodes, which have no containerd content store;
- every such image while the node agent is disabled.

### Managed control planes and node components

Managed control-plane internals (etcd and scheduler versions), CNI plugins and firmware.

**What ffs shows:** Kubernetes advisories are matched against the control-plane and kubelet versions, with low confidence on managed distributions and the note `version normalised from <version>; vendor builds may include backported fixes`. The node agent inventories the runc, containerd, kubelet, k3s and RKE2 binaries on each node and matches their Go modules. CNI plugins, firmware and managed control-plane components are not inventoried.

### The kernel and bundled components

Kernel packages that are installed but not running, components bundled into k3s and RKE2 that are not separate binaries (flannel), and nodes the node agent cannot read.

**What ffs shows:** with the node agent, only the running kernel's distro packages are matched; a newer installed kernel shows the node as reboot pending, with `installed kernel <release> is newer than the running kernel <release>`. The embedded containerd and runc of k3s and RKE2 are matched through their Go modules. A node the agent cannot fully read shows a coverage gap instead of a clean result:
- `no package database (image-based OS)` on Talos, Flatcar, Container-Optimized OS and Bottlerocket;
- `node agent not reporting since <time>` or `node agent has not reported` (`node_agent_missing`);
- `node agent cannot read <path>: permission denied`, for example under SELinux;
- `no containerd content store on this node; side-loaded images cannot be catalogued from it`.

Without the node agent, the cluster entry keeps the note `kernel, runc and other bundled components (flannel) are not inventoried`. Node OS and Kubernetes versions get end-of-life status either way.

### Node inventory from a compromised node

A node's agent supplies its host inventory, and the SBOMs of images catalogued from its content store. ffs accepts an image SBOM only from a node that runs the image, and records which node sent it.

**What ffs shows:** a compromised node can under-report the packages of its own host and of images that only it runs, because it controls those bytes. A registry SBOM replaces an agent SBOM as soon as the registry is reachable. See [node-agent.md](node-agent.md#trust).

### "Deferred" fix states

Ubuntu and Debian fix states of "deferred" are not told apart from "needs triage": the vulnerability database records both as not fixed, so those findings keep their normal priority.

**What ffs shows:** the finding's fix state is not fixed, as for any other unfixed vulnerability.

### Software found only by binary classifier

Software that the cataloguer identifies from a binary (for example a runtime built from source) but that is outside ffs's upstream-runtime map. That map gives php, node, python, ruby, nginx, httpd, haproxy, redis, valkey, postgresql, mysql, mariadb, openssl, curl and busybox a minutes-latency path through OSV and the CVE List. Anything else is matched only by the Grype database through CPE, about daily.

**What ffs shows:** the image note `daily, CPE-based coverage only: <names>`, and the image is marked partial coverage.

### Private images that need cloud workload identity

Private images on EKS, GKE or AKS that the nodes pull with cloud workload identity (ECR, Artifact Registry, ACR) rather than pull secrets.

**What ffs shows:** the image is `unresolvable` with the registry's reason. Cloud workload identity credentials are not supported yet; a pull secret or `registry.operatorSecret` works instead.

### Whether a LoadBalancer or Ingress is internet-facing

ffs cannot tell whether a LoadBalancer, NodePort, Ingress or Gateway is reachable from the internet. It assumes it is. NetworkPolicy is not taken into account.

**What ffs shows:** the reason names the path, for example `exposed via HTTPRoute shop/web on Gateway edge/external`. Internal paths can be excluded with `exposure.internalIngressClasses`, `exposure.internalGatewayClasses`, `exposure.internalGateways` and `exposure.internalLBAnnotations`.

### Upstream triage delay

Most of the time between a vulnerability becoming known and a finding appearing is spent upstream: advisory databases and distributions triage before they publish.

**What ffs shows:** every finding has four timestamps: `published` (by the advisory source), `observed` (when ffs first saw the advisory), `matched` (when the finding was created) and `lastSeen`. The gap between them shows where any delay came from. Feed freshness is on the Feeds page, and a stale feed raises a `FeedStale` Event.

## SBOM sources

ffs catalogues every image itself: the cataloguer pulls the image and runs Syft on it. SBOM attestations published with an image are not used in its place, because SPDX and CycloneDX do not carry what Syft's binary classifiers find. A runtime built from source, such as php in the official `php` images, would lose the identification that its minutes-latency matching depends on.

Attestations are used only for an image the cataloguer refuses as too large (`catalog.maxImageBytes`):

- ffs tries, in order, the OCI referrers API, BuildKit attestation manifests in the image index, the `sha256-<digest>` referrers tag, and cosign `.att` tags.
- Only SPDX or CycloneDX attestations created by Syft are used. They must cover the image's platform digest, list packages and include the image's OS packages; an SBOM of a source directory is not taken as the image's inventory.
- Attestation signatures are not verified. The image publisher already controls the image itself, so a signature adds no trust about its contents.
- These images carry the note `inventory from a build attestation; executables not attributed to a package were not measured`.

An image whose SBOM is larger than 64 MiB is shown as `catalogFailed` with the reason, rather than decoded in the controller.

## Environments

ffs supports the current upstream Kubernetes minor and the three before it.

| Support | Environments |
|---|---|
| Tested | kind, k3s, kubeadm |
| Best-effort | EKS, GKE, AKS, CRI-O and OpenShift, Talos |

Best-effort environments are expected to work, but have no dedicated test infrastructure. On any of them, cloud workload identity registry credentials are unsupported, so private images that depend on them show as `unresolvable`.

GKE Autopilot is supported only with `nodeAgent.enabled: false`, because it does not allow the node agent's `hostPath` volumes. Node-specific platforms are covered in [node-agent.md](node-agent.md#platforms).
