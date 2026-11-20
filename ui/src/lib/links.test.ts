import { createMemoryHistory } from '@tanstack/react-router'
import { expect, test } from 'vitest'
import { createQueryClient } from '@/api/client'
import { createAppRouter } from '@/router'
import { copy } from './copy'
import {
  advisoryPath,
  coverageHref,
  explorerHref,
  hitPath,
  imagePath,
  nodeGroupPath,
  ownerHref,
  ownerLabel,
  relatedHref,
  scopePath,
  viewHref,
  workloadPath,
} from './links'
import { CLUSTER, parseScope } from './scope'

// Review Focus 2
test('keeps a placeholder image ID in one path segment', async () => {
  const id = 'unknown:ghcr.io/example/private:1.0'
  expect(imagePath(id)).toBe('/images/unknown%3Aghcr.io%2Fexample%2Fprivate%3A1.0')
  const router = createAppRouter({ queryClient: createQueryClient(), history: createMemoryHistory({ initialEntries: [imagePath(id)] }) })
  await router.load()
  const leaf = router.state.matches[router.state.matches.length - 1]
  expect(leaf.routeId).toBe('/images/$digest')
  expect(leaf.params).toEqual({ digest: id })
  expect(router.state.location.pathname).toBe('/images/unknown%3Aghcr.io%2Fexample%2Fprivate%3A1.0')
})

test('maps workloads, scopes, explorers and search hits to their pages', () => {
  expect(workloadPath('Deployment', '', 'web')).toBe('/workloads/Deployment/-/web')
  expect(scopePath(parseScope('workload:Deployment/shop/web'))).toBe('/workloads/Deployment/shop/web')
  expect(scopePath(parseScope('namespace:shop'))).toBe('/namespaces/shop')
  expect(scopePath(parseScope('nodegroup:g1'))).toBe('/nodegroups/g1')
  expect(scopePath(parseScope('node:worker-1'))).toBe('/nodes/worker-1')
  expect(scopePath(parseScope('controlplane'))).toBe('/controlplane')
  expect(scopePath(CLUSTER)).toBe('/')
  expect(imagePath('sha256:abc', 'workload:Deployment/shop/web')).toBe('/images/sha256%3Aabc?from=workload:Deployment/shop/web')
  expect(explorerHref('findings', { scope: 'workload:Deployment/shop/web', fixKey: 'none' })).toBe('/vulnerabilities?scope=workload:Deployment/shop/web&fixKey=none')
  expect(advisoryPath('CVE-2026-0001')).toBe('/vulnerabilities/CVE-2026-0001')
  expect(hitPath({ kind: 'advisory', id: 'CVE-2026-0001', label: 'CVE-2026-0001' })).toBe('/vulnerabilities/CVE-2026-0001')
  expect(hitPath({ kind: 'package', id: 'deb/openssl', label: 'openssl' })).toBe('/packages?ecosystem=deb&q=openssl')
  expect(hitPath({ kind: 'workload', id: 'Deployment/shop/web', label: 'web' })).toBe('/workloads/Deployment/shop/web')
  expect(hitPath({ kind: 'image', id: 'unknown:ghcr.io/example/private:1.0', label: 'x' })).toBe('/images/unknown%3Aghcr.io%2Fexample%2Fprivate%3A1.0')
})

test('cluster-level owners link to their own pages, never to a workload page', () => {
  expect(ownerHref({ kind: 'Nodes', namespace: '', name: 'test' })).toBe('/nodes')
  expect(ownerLabel({ kind: 'Nodes', namespace: '', name: 'test' })).toBe('Nodes (host packages)')
  expect(ownerHref({ kind: 'Cluster', namespace: '', name: 'test' })).toBe('/controlplane')
  expect(ownerLabel({ kind: 'Cluster', namespace: '', name: 'test' })).toBe('Control plane')
  expect(ownerHref({ kind: 'ContainerRuntime', namespace: '', name: 'containerd' })).toBe('/controlplane')
  expect(ownerLabel({ kind: 'ContainerRuntime', namespace: '', name: 'containerd' })).toBe('Control plane')
  // A namespaced custom resource of kind Cluster is a workload.
  expect(ownerHref({ kind: 'Cluster', namespace: 'payments', name: 'db' })).toBe('/workloads/Cluster/payments/db')
  expect(ownerLabel({ kind: 'Cluster', namespace: 'payments', name: 'db' })).toBe('db')
  expect(ownerHref({ kind: 'Deployment', namespace: 'shop', name: 'web' })).toBe('/workloads/Deployment/shop/web')
  // Scope pages and search hits go through the same mapping.
  expect(scopePath(parseScope('workload:Nodes//test'))).toBe('/nodes')
  expect(scopePath(parseScope('workload:ContainerRuntime//containerd'))).toBe('/controlplane')
})

test('node group keys are used as they are: path-encoded in links, whole in scopes', async () => {
  for (const [key, path] of [
    ['ubuntu-24.04-k6.8', '/nodegroups/ubuntu-24.04-k6.8'],
    ['ubuntu-24.04-k6.8-arm64', '/nodegroups/ubuntu-24.04-k6.8-arm64'],
    ['ubuntu-24.04-k6.8-nodeinfo', '/nodegroups/ubuntu-24.04-k6.8-nodeinfo'],
    ['ubuntu-24.04-k6.8-nodeinfo@worker-9', '/nodegroups/ubuntu-24.04-k6.8-nodeinfo%40worker-9'],
    ['ubuntu-24.04-k6.8@worker-1', '/nodegroups/ubuntu-24.04-k6.8%40worker-1'],
  ] as const) {
    expect(nodeGroupPath(key)).toBe(path)
    const scope = parseScope(`nodegroup:${key}`)
    expect(scope.value).toBe(key)
    expect(scopePath(scope)).toBe(path)
    expect(viewHref(scope, 'members')).toBe(`${path}?view=members`)
    expect(relatedHref(scope, 'members')).toBe(`${path}?view=members`)
    expect(hitPath({ kind: 'nodegroup', id: key, label: key, scope: `nodegroup:${key}` })).toBe(path)
    expect(hitPath({ kind: 'nodegroup', id: key, label: key })).toBe(path)
  }
  // The router reads the key back whole.
  const router = createAppRouter({ queryClient: createQueryClient(), history: createMemoryHistory({ initialEntries: [nodeGroupPath('ubuntu-24.04-k6.8@worker-1')] }) })
  await router.load()
  const leaf = router.state.matches[router.state.matches.length - 1]
  expect(leaf.routeId).toBe('/nodegroups/$id')
  expect(leaf.params).toEqual({ id: 'ubuntu-24.04-k6.8@worker-1' })
})

test('search hits for the control plane and Nodes open their pages and read by what they hold', () => {
  // The hits are of their own kinds, with the cluster name as id. The Nodes hit has no scope; the
  // control plane hit carries the controlplane scope, and goes to its page without it too.
  const nodes = { kind: 'nodes', id: 'test', label: 'Nodes', detail: '3 nodes' } as const
  const cp = { kind: 'controlplane', id: 'test', label: 'Control plane', detail: 'Kubernetes 1.35.1', scope: 'controlplane' } as const
  expect(hitPath(nodes)).toBe('/nodes')
  expect(hitPath(cp)).toBe('/controlplane')
  expect(hitPath({ kind: 'controlplane', id: 'test', label: 'Control plane' })).toBe('/controlplane')
  expect(copy.command.kind[nodes.kind]).toBe('Nodes (host packages)')
  expect(copy.command.kind[cp.kind]).toBe('Control plane')
  // A workload hit opens its workload page; a namespaced custom resource of kind Cluster is a workload.
  const db = { kind: 'workload', id: 'Cluster/payments/db', label: 'db', scope: 'workload:Cluster/payments/db' } as const
  expect(hitPath(db)).toBe('/workloads/Cluster/payments/db')
  expect(hitPath({ kind: 'workload', id: 'Deployment/shop/web', label: 'web' })).toBe('/workloads/Deployment/shop/web')
  expect(copy.command.kind[db.kind]).toBe('Workload')
  expect(copy.command.kind.nodegroup).toBe('Node group')
})

test('the coverage page of a scope keeps the scopes it covers', () => {
  expect(coverageHref()).toBe('/coverage')
  expect(coverageHref(CLUSTER)).toBe('/coverage')
  expect(coverageHref(parseScope('namespace:shop'))).toBe('/coverage?scope=namespace:shop')
  expect(coverageHref(parseScope('workload:Deployment/shop/web'))).toBe('/coverage?scope=workload:Deployment/shop/web')
  expect(coverageHref(parseScope('image:sha256:abc'))).toBe('/coverage')
})

test('the rail used-by "+ N more" opens the SBOM view, where Used by is listed', () => {
  expect(relatedHref(parseScope('image:sha256:abc'), 'usedBy')).toBe('/images/sha256%3Aabc?view=sbom')
  expect(relatedHref(CLUSTER, 'usedBy')).toBeUndefined()
})
