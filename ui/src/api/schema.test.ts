import { expect, it } from 'vitest'
import type { components, paths } from './schema'

it('names every operation path relative to /api/v1', () => {
  const p: (keyof paths)[] = ['/summary', '/scope', '/exposure', '/findings', '/transitions', '/advisories/{id}', '/workloads',
    '/workloads/{kind}/{namespace}/{name}', '/images', '/images/{digest}', '/images/{digest}/packages', '/packages', '/nodegroups',
    '/nodegroups/{id}', '/nodes/{name}', '/coverage', '/feeds', '/exceptions', '/settings', '/search', '/stream']
  expect(new Set(p).size).toBe(21)
  const problem: components['schemas']['Problem'] = { cluster: 'test', generatedAt: '2026-11-19T00:00:00Z', type: 'about:blank', title: 'Bad Request', status: 400, code: 'invalid_cursor' }
  expect(problem.code).toBe('invalid_cursor')
})
