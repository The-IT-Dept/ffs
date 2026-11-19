#!/usr/bin/env bash
# kind cluster and local registry for the end-to-end suite (make e2e), following kind's documented
# local-registry setup: https://kind.sigs.k8s.io/docs/user/local-registry/
#
#   hack/e2e-kind.sh up     start the registry on 127.0.0.1:5001 and create the ffs-e2e cluster
#   hack/e2e-kind.sh down   delete the cluster and the registry
#
# kind writes the cluster's credentials to $KUBECONFIG when it is set (make e2e sets it), otherwise
# to ~/.kube/config. KIND overrides the kind binary.
set -euo pipefail

kind=${KIND:-kind}
cluster='ffs-e2e'
reg_name='kind-registry'
reg_port=5001
reg_image='registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e'
node_image='kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5'

up() {
  # 1. The registry container, unless it is already running.
  if [ "$(docker inspect -f '{{.State.Running}}' "$reg_name" 2>/dev/null || true)" != 'true' ]; then
    docker rm -f "$reg_name" >/dev/null 2>&1 || true
    docker run -d --restart=always -p "127.0.0.1:${reg_port}:5000" --network bridge --name "$reg_name" "$reg_image"
  fi

  # 2. The cluster. Node images from kind v0.27 on read /etc/containerd/certs.d without a patch.
  if ! "$kind" get clusters 2>/dev/null | grep -qx "$cluster"; then
    "$kind" create cluster --name "$cluster" --image "$node_image" --wait 2m
  fi

  # 3. localhost:5001 on each node is the registry container: localhost inside a node is the node.
  local dir="/etc/containerd/certs.d/localhost:${reg_port}"
  for node in $("$kind" get nodes --name "$cluster"); do
    docker exec "$node" mkdir -p "$dir"
    printf '[host."http://%s:5000"]\n' "$reg_name" | docker exec -i "$node" cp /dev/stdin "$dir/hosts.toml"
  done

  # 4. The registry joins the kind network, so nodes and pods reach it by name and address.
  if [ "$(docker inspect -f '{{json .NetworkSettings.Networks.kind}}' "$reg_name")" = 'null' ]; then
    docker network connect kind "$reg_name"
  fi

  # 5. Document the local registry (KEP-1755).
  kubectl --context "kind-${cluster}" apply -f - <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: local-registry-hosting
  namespace: kube-public
data:
  localRegistryHosting.v1: |
    host: "localhost:${reg_port}"
    help: "https://kind.sigs.k8s.io/docs/user/local-registry/"
EOF
}

down() {
  "$kind" delete cluster --name "$cluster"
  docker rm -f "$reg_name" >/dev/null 2>&1 || true
}

case "${1:-}" in
  up) up ;;
  down) down ;;
  *)
    echo "usage: $0 up|down" >&2
    exit 2
    ;;
esac
