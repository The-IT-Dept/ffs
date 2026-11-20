import { expect, test } from 'vitest'
import { CLUSTER, formatScope, parseScope, ScopeError, workloadScope } from './scope'

test('parses scopes exactly as the server does', () => {
  for (const s of [undefined, '', 'cluster']) expect(parseScope(s)).toEqual(CLUSTER)
  expect(parseScope('controlplane')).toEqual({ kind: 'controlplane', value: '' })
  expect(parseScope('workload:Deployment//web')).toEqual({ kind: 'workload', value: 'Deployment//web' })
  expect(parseScope('image:unknown:ghcr.io/example/private:1.0')).toEqual({ kind: 'image', value: 'unknown:ghcr.io/example/private:1.0' })
  for (const bad of ['namespace:', 'workload:Deployment/shop', 'workload:/shop/web', 'workload:Deployment/shop/', 'pod:x', 'controlplane:x', 'cluster:x'])
    expect(() => parseScope(bad)).toThrow(ScopeError)
  expect(formatScope(parseScope('node:worker-1'))).toBe('node:worker-1')
  expect(formatScope(CLUSTER)).toBe('cluster')
  expect(workloadScope('CronJob', '-', 'backup')).toEqual({ kind: 'workload', value: 'CronJob//backup' })
})
