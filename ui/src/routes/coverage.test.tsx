import { screen, within } from '@testing-library/react'
import { expect, test } from 'vitest'
import { copy } from '@/lib/copy'
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

test('node gaps for agents that report without a host inventory, or do not run, have their own copy', async () => {
  mockApi().on(
    '/coverage',
    coverageBody({
      totalGaps: 2,
      gaps: [
        gap({ code: 'host_not_inventoried', remedy: 'check_node_agent', what: '2 nodes', detail: 'host inventory quarantined', affects: { workloads: 0, images: 0, nodes: 2 } }),
        gap({ code: 'node_agent_unsupported', remedy: 'informational', what: 'worker-1', detail: '', affects: { workloads: 0, images: 0, nodes: 1 } }),
      ],
    }),
  )
  renderApp('/coverage')
  expect((await screen.findByText('host packages not inventoried yet')).closest('.hatched')).not.toBeNull()
  expect(screen.getByText("Check the node agent's logs on these nodes; the last error is shown.")).toBeInTheDocument()
  expect(screen.getByText('host inventory quarantined')).toBeInTheDocument()
  expect(screen.getByText('not scheduled by the node agent').closest('.hatched')).not.toBeNull()
  expect(screen.getByText(/a taint the agent does not tolerate excludes this node from the node agent\. To cover it, add it to nodeAgent\.architectures, nodeAgent\.nodeSelector or nodeAgent\.tolerations\./)).toBeInTheDocument()
})

test('no gaps says so, not that nothing needs attention', async () => {
  mockApi().on('/coverage', coverageBody())
  renderApp('/coverage')
  expect(await screen.findByText(copy.emptyList.gaps)).toBeInTheDocument()
  expect(screen.queryByText(copy.empty)).toBeNull()
})
