import { createMemoryHistory } from '@tanstack/react-router'
import { expect, test } from 'vitest'
import { createQueryClient } from '@/api/client'
import { createAppRouter } from '@/router'
import { advisoryPath, explorerHref, hitPath, imagePath, scopePath, workloadPath } from './links'
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
