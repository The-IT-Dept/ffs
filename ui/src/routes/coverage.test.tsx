import { screen, within } from '@testing-library/react'
import { expect, test } from 'vitest'
import { mockApi } from '@/test/api'
import { coverageBody, gap } from '@/test/fixtures'
import { renderApp } from '@/test/render'

test('the funnel shows every step and hatches what ffs cannot see', async () => {
  mockApi().on('/coverage', coverageBody({ funnel: { pods: 12, images: 7, catalogued: 5, fullDetail: 4, feedsFresh: 2, feedsTotal: 3 } }))
  renderApp('/coverage')
  const main = await screen.findByRole('main')
  for (const t of ['Pods', 'Distinct images', 'Catalogued', 'Full detail', 'Feeds fresh', '12', '2/3']) expect(await within(main).findByText(t)).toBeInTheDocument()
  expect(main.querySelectorAll('.hatched').length).toBeGreaterThanOrEqual(3)
})

test('the gaps table maps codes to the contract copy', async () => {
  mockApi().on(
    '/coverage',
    coverageBody({
      totalGaps: 4,
      gaps: [
        gap({
          code: 'unresolvable_auth',
          remedy: 'add_pull_secret',
          what: 'ghcr.io/example/private:1.0',
          detail: '401 Unauthorized',
          target: { scope: 'workload:CronJob/ops/report', kind: 'workload', label: 'report' },
          affects: { workloads: 2, images: 1, nodes: 0 },
        }),
        gap({ code: 'feed_stale', remedy: 'check_feed_access', what: 'kev', detail: 'dial tcp: timeout', affects: { workloads: 0, images: 0, nodes: 0 } }),
        gap({ code: 'cpe_only_classifier', remedy: 'informational', what: 'ghcr.io/example/web', detail: 'php', affects: { workloads: 1, images: 1, nodes: 0 } }),
      ],
    }),
  )
  renderApp('/coverage')
  expect((await screen.findByText('registry refused access')).closest('.hatched')).not.toBeNull()
  expect(screen.getByText('Give ffs a pull secret that can read this repository.')).toBeInTheDocument()
  expect(screen.getByText('2 workloads · 1 image')).toBeInTheDocument()
  expect(screen.getByRole('link', { name: /ghcr\.io\/example\/private:1\.0/ })).toHaveAttribute('href', '/workloads/CronJob/ops/report')
  expect(screen.getByText('Check that ffs can reach the kev feed; the last error is shown.')).toBeInTheDocument()
  expect(screen.getByText('dial tcp: timeout')).toBeInTheDocument()
  expect(screen.getByText('Matched daily against CPE data; the fast path does not cover php.')).toBeInTheDocument()
  expect(screen.getByText('Showing 3 of 4 gaps')).toBeInTheDocument()
})

test('unknown pods show —, and the scope travels to the API', async () => {
  const api = mockApi().on('/coverage', coverageBody({ funnel: { pods: null, images: 1, catalogued: 1, fullDetail: 1, feedsFresh: 3, feedsTotal: 3 } }))
  renderApp('/coverage?scope=namespace:ops')
  expect(await screen.findByText('—')).toBeInTheDocument()
  expect(api.calls('/coverage')[0].searchParams.get('scope')).toBe('namespace:ops')
})
