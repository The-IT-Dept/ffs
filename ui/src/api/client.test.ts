import { expect, test } from 'vitest'
import { mockApi, problem } from '@/test/api'
import { findingsPage } from '@/test/fixtures'
import { ApiProblem, apiFetch, apiQuery, createQueryClient } from './client'

test('apiQuery keys by path and params and serialises arrays comma-joined', async () => {
  const api = mockApi().on('/findings', findingsPage())
  const o = apiQuery('/findings', { query: { priority: ['urgent', 'high'], scope: 'workload:Deployment/shop/web' } })
  expect(o.queryKey).toEqual(['api', '/findings', { query: { priority: ['urgent', 'high'], scope: 'workload:Deployment/shop/web' } }])
  await createQueryClient({ retry: false }).fetchQuery(o)
  const url = api.calls('/findings')[0]
  expect(url.pathname).toBe('/api/v1/findings')
  expect(url.search).toContain('priority=urgent,high')
  expect(url.searchParams.get('scope')).toBe('workload:Deployment/shop/web')
})

test('a problem response becomes an ApiProblem with its code', async () => {
  mockApi().on('/findings', problem(400, 'invalid_cursor', 'cursor belongs to another query'))
  const err = await apiFetch('/findings', { query: { cursor: 'x' } }).catch((e: unknown) => e)
  expect(err).toBeInstanceOf(ApiProblem)
  expect(err).toMatchObject({ status: 400, code: 'invalid_cursor', detail: 'cursor belongs to another query' })
})

test('an error body that is not a problem becomes an internal ApiProblem', async () => {
  mockApi().on('/findings', new Response('bad gateway', { status: 502, statusText: 'Bad Gateway' }))
  await expect(apiFetch('/findings', {})).rejects.toMatchObject({ status: 502, code: 'internal' })
})
