import { createMemoryHistory } from '@tanstack/react-router'
import { expect, test } from 'vitest'
import { createQueryClient } from '@/api/client'
import { createAppRouter } from '@/router'
import { advisoryPath, coverageHref, explorerHref, hitPath, imagePath, nodeGroupLinkIds, ownerHref, ownerLabel, scopePath, workloadPath } from './links'
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
  expect(hitPath({ kind: 'workload', id: 'Cluster//test', label: 'test' })).toBe('/controlplane')
})

test('node groups link by stable name unless another listed group shares it', () => {
  const ids = nodeGroupLinkIds([
    { id: 'a1', name: 'ubuntu-24.04-k6.8' },
    { id: 'b2', name: 'rocky-9-k5.14' },
    { id: 'c3', name: 'rocky-9-k5.14' },
    { id: 'd4', name: '' },
  ])
  expect(ids.get('a1')).toBe('ubuntu-24.04-k6.8')
  expect(ids.get('b2')).toBe('b2')
  expect(ids.get('c3')).toBe('c3')
  expect(ids.get('d4')).toBe('d4')
})

test('the coverage page of a scope keeps the scopes it covers', () => {
  expect(coverageHref()).toBe('/coverage')
  expect(coverageHref(CLUSTER)).toBe('/coverage')
  expect(coverageHref(parseScope('namespace:shop'))).toBe('/coverage?scope=namespace:shop')
  expect(coverageHref(parseScope('workload:Deployment/shop/web'))).toBe('/coverage?scope=workload:Deployment/shop/web')
  expect(coverageHref(parseScope('image:sha256:abc'))).toBe('/coverage')
})
