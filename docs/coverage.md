# Coverage

ffs never reports an image as clean when it could not see inside it. Every image has a status (`pending`, `catalogued`, `unresolvable` or `catalogFailed`) with a reason, and images with known gaps are marked partial coverage and list coverage notes. The API returns these as `status`, `statusReason`, `partialCoverage` and `coverage.notes`; the dashboard shows them on the Images page and on each workload.

This page lists what ffs cannot see, and what it shows when it meets it.

## Blind spots

### Software the cataloguer cannot attribute

Rust binaries built without cargo-auditable, bundled or minified JavaScript, copied-in binaries that no classifier recognises, runtimes installed by hand, UPX-packed Go binaries, and the main module of Go binaries built with `-buildvcs=false` (it has no version).

**What ffs shows:** the image is marked partial coverage, with notes such as `3 executables not attributed to any package` and `1 Rust binaries built without cargo-auditable`. No findings for that software does not mean it has no vulnerabilities.

### Images only the kubelet can pull

Images whose credentials only the kubelet holds, through a credential-provider plugin or KEP-4412 service-account tokens; images pulled through a node-level registry mirror that the mirror map does not cover; and side-loaded images (`ctr import`, `kind load`, k3s airgap tarballs), whose image ID is a node-local config digest.

**What ffs shows:** the image is `unresolvable`, with the reason, for example `image ID is a node-local config digest and the container image has no tag to look up in a registry`. It is never shown as clean, and it is retried periodically. Two settings narrow the gap:
- `registry.operatorSecret` supplies registry credentials that otherwise only the nodes hold;
- `registry.mirrors` is a registry mirror rewrite map, so pulls go where the nodes pull from.

A later node agent will catalogue these images from the node.

### Managed control planes and node components

Managed control-plane internals (etcd and scheduler versions), and the versions of runc, CNI plugins and firmware.

**What ffs shows:** Kubernetes advisories are matched against the control-plane and kubelet versions, with low confidence on managed distributions and the note `version normalised from <version>; vendor builds may include backported fixes`. The other components are not inventoried.

### The kernel and bundled components

Kernel vulnerabilities, and components bundled into k3s and RKE2 (embedded containerd, runc, flannel).

**What ffs shows:** the cluster entry carries the note `kernel, runc and other bundled components (flannel) are not inventoried`. Node OS and Kubernetes versions get end-of-life status. A later node agent will cover the kernel and bundled components.

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

For each image, ffs first looks for an SBOM attestation published with the image, without pulling its layers. It tries, in order, the OCI referrers API, BuildKit attestation manifests in the image index, the `sha256-<digest>` referrers tag, and cosign `.att` tags.

- SPDX or CycloneDX attestations created by Syft are used as the primary input. They must cover the image's platform digest and list packages.
- Attestations from other tools fall through to the cataloguer, which pulls the image and catalogues it.
- Attestation signatures are not verified. The image publisher already controls the image itself, so a signature adds no trust about its contents.
- For attested images, executables not attributed to a package are not measured. These images carry the note `inventory from a build attestation; executables not attributed to a package were not measured`.

## Environments

ffs supports the current upstream Kubernetes minor and the three before it.

| Support | Environments |
|---|---|
| Tested | kind, k3s, kubeadm |
| Best-effort | EKS, GKE, AKS, CRI-O and OpenShift, Talos |

Best-effort environments are expected to work, but have no dedicated test infrastructure. On any of them, cloud workload identity registry credentials are unsupported, so private images that depend on them show as `unresolvable`.
