import { expect, test } from 'vitest'
import { CLUSTER } from '@/lib/scope'
import { routeScope } from './routescope'

test('maps every route to the scope and view the rail shows', () => {
  expect(routeScope('/', {}, {})).toEqual({ scope: CLUSTER, view: 'exposure' })
  expect(routeScope('/vulnerabilities', {}, { scope: 'namespace:shop' })).toEqual({ scope: { kind: 'namespace', value: 'shop' }, view: 'vulnerabilities' })
  expect(routeScope('/vulnerabilities', {}, { scope: 'workload:Deployment/shop/web' }).view).toBe('findings')
  expect(routeScope('/workloads', {}, {})).toEqual({ scope: CLUSTER, view: 'workloads' })
  expect(routeScope('/workloads/$kind/$namespace/$name', { kind: 'CronJob', namespace: '-', name: 'backup' }, { view: 'history' })).toEqual({
    scope: { kind: 'workload', value: 'CronJob//backup' },
    view: 'history',
  })
  expect(routeScope('/images/$digest', { digest: 'unknown:ghcr.io/example/private:1.0' }, { from: 'workload:CronJob/ops/report' })).toEqual({
    scope: { kind: 'image', value: 'unknown:ghcr.io/example/private:1.0' },
    view: 'findings',
    from: 'workload:CronJob/ops/report',
  })
  expect(routeScope('/nodegroups/$id', { id: 'g1' }, { view: 'kernel' })).toEqual({ scope: { kind: 'nodegroup', value: 'g1' }, view: 'kernel' })
  expect(routeScope('/nodes/$name', { name: 'worker-1' }, {})).toEqual({ scope: { kind: 'node', value: 'worker-1' } })
  expect(routeScope('/coverage', {}, { scope: 'namespace:ops' })).toEqual({ scope: { kind: 'namespace', value: 'ops' }, view: 'coverage' })
  expect(routeScope('/controlplane', {}, {})).toEqual({ scope: { kind: 'controlplane', value: '' } })
  expect(routeScope('/vulnerabilities/$id', { id: 'CVE-2026-0001' }, {})).toEqual({ scope: CLUSTER, view: 'vulnerabilities' })
  expect(routeScope('__root__', {}, {})).toEqual({ scope: CLUSTER })
})
