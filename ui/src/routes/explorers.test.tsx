import { screen, waitFor, within } from '@testing-library/react'
import { expect, test, vi } from 'vitest'
import { copy } from '@/lib/copy'
import { mockApi } from '@/test/api'
import {
  counts,
  coverageFigure,
  feedFreshness,
  findingRow,
  findingsPage,
  fixAction,
  groupRow,
  imagesPage,
  packagesPage,
  scopeCard,
  workloadRef,
  workloadRow,
  workloadsPage,
} from '@/test/fixtures'
import { renderApp } from '@/test/render'

test('the images explorer links a placeholder image as one path segment and hatches what it cannot see', async () => {
  mockApi().on(
    '/images',
    imagesPage({
      total: 1,
      rows: [
        {
          digest: 'unknown:ghcr.io/example/private:1.0',
          repo: 'ghcr.io/example/private',
          platform: '',
          status: 'unresolvable',
          statusReason: 'registry refused access',
          source: '',
          coverage: 'none',
          gaps: ['unresolvable_auth'],
          workloads: 1,
          counts: counts(),
          fixable: 0,
        },
      ],
    }),
  )
  renderApp('/images')
  const link = await screen.findByRole('link', { name: /ghcr\.io\/example\/private/ })
  expect(link).toHaveAttribute('href', '/images/unknown%3Aghcr.io%2Fexample%2Fprivate%3A1.0')
  expect(screen.getByText('unresolvable').closest('.hatched')).not.toBeNull()
})

test('the workloads explorer shows — for unknown pods and sorts on the server', async () => {
  const api = mockApi().on('/workloads', workloadsPage({ total: 1, rows: [workloadRow({ pods: null, bestFix: fixAction() })] }))
  const { router, user } = renderApp('/workloads')
  expect(within(await screen.findByRole('row', { name: /web/ })).getByText('—')).toBeInTheDocument()
  await user.click(screen.getByRole('button', { name: 'Workload' }))
  expect(router.state.location.search).toEqual({ sort: 'name' })
  await waitFor(() => expect(api.calls('/workloads').at(-1)!.searchParams.get('sort')).toBe('name'))
})

test('the packages explorer links a package to its findings in its own ecosystem', async () => {
  mockApi().on(
    '/packages',
    packagesPage({ total: 1, rows: [{ ecosystem: 'deb', name: 'openssl', version: '3.5.1-1', images: 2, workloads: 3, counts: counts({ high: 2 }), worst: 'high' }] }),
  )
  renderApp('/packages')
  expect(await screen.findByRole('link', { name: /openssl/ })).toHaveAttribute('href', '/vulnerabilities?package=openssl&ecosystem=deb')
})

test('a scoped packages explorer links a package to its findings in the same scope', async () => {
  mockApi().on(
    '/packages',
    packagesPage({ total: 1, rows: [{ ecosystem: 'deb', name: 'openssl', version: '3.5.1-1', images: 2, workloads: 3, counts: counts({ high: 2 }), worst: 'high' }] }),
  )
  renderApp('/packages?scope=namespace:shop')
  expect(await screen.findByRole('link', { name: /openssl/ })).toHaveAttribute('href', '/vulnerabilities?scope=namespace:shop&package=openssl&ecosystem=deb')
})

test('explorers never send parameters their endpoint does not take', async () => {
  const api = mockApi().on('/workloads', workloadsPage())
  renderApp('/workloads?state=open&group=advisory&kind=Deployment')
  await waitFor(() => expect(api.calls('/workloads')).toHaveLength(1))
  const sp = api.calls('/workloads')[0].searchParams
  expect(sp.has('state')).toBe(false)
  expect(sp.has('group')).toBe(false)
  expect(sp.get('kind')).toBe('Deployment')
})

test('the explorer header puts full detail first and seen-into second', async () => {
  mockApi()
    .on('/findings', findingsPage({ total: 1, findings: 1, rows: [findingRow()] }))
    .on('/scope', scopeCard({ trust: { feeds: feedFreshness(), coverage: coverageFigure({ inUse: 6, seenInto: 5, full: 4 }), settings: true } }))
  renderApp('/vulnerabilities')
  const main = await screen.findByRole('main')
  const sub = await within(main).findByText(/images in full detail/)
  await waitFor(() => expect(sub.parentElement?.textContent).toBe('1 finding · 4/6 images in full detail · 5 seen into'))
})

test('an empty explorer leads with a stale matching feed from the scope trust', async () => {
  mockApi()
    .on('/findings', findingsPage())
    .on('/scope', scopeCard({ trust: { feeds: feedFreshness({ fresh: false, stale: ['grypedb'], oldestSuccess: null }), coverage: coverageFigure(), settings: true } }))
  renderApp('/vulnerabilities')
  expect(await screen.findByText('feed out of date: grypedb')).toBeInTheDocument()
  expect(screen.getByRole('link', { name: 'Feeds' })).toHaveAttribute('href', '/feeds')
  expect(screen.queryByText(copy.empty)).toBeNull()
})

test('an empty explorer does not read clean before the scope trust has answered', async () => {
  mockApi().on('/findings', findingsPage())
  // The rail's /scope answer is held until the test releases it.
  let release = () => {}
  const held = new Promise<void>((r) => {
    release = r
  })
  const answer = globalThis.fetch
  vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
    if (new URL(input instanceof Request ? input.url : String(input)).pathname === '/api/v1/scope') await held
    return answer(input, init)
  })
  renderApp('/vulnerabilities')
  const main = await screen.findByRole('main')
  expect(await within(main).findByText('0 findings')).toBeInTheDocument()
  expect(main.querySelector('.border-dashed [data-slot="skeleton"]')).not.toBeNull()
  expect(within(main).queryByText(copy.empty)).toBeNull()
  release()
  expect(await within(main).findByText(copy.empty)).toBeInTheDocument()
  expect(main.querySelector('.border-dashed [data-slot="skeleton"]')).toBeNull()
})

test('host and control-plane findings link to their own pages and name the node groups a host finding affects', async () => {
  mockApi().on(
    '/findings',
    findingsPage({
      total: 2,
      findings: 2,
      rows: [
        findingRow({
          id: 'f1',
          workload: workloadRef('Nodes', '', 'test'),
          nodeGroups: [
            { id: 'ubuntu-24.04-k6.8', label: 'ubuntu-24.04-k6.8-3f9c1a', nodes: 3, versions: [{ package: 'openssl', version: '3.0.13-0ubuntu3' }] },
            { id: 'debian-13-k6.12', label: 'debian-13-k6.12-a1b2c3', nodes: 1, versions: [{ package: 'openssl', version: '3.5.1-1' }] },
          ],
        }),
        findingRow({ id: 'f2', workload: workloadRef('Cluster', '', 'test') }),
      ],
    }),
  )
  renderApp('/vulnerabilities')
  const host = await screen.findByRole('link', { name: 'Nodes (host packages)' })
  expect(host).toHaveAttribute('href', '/nodes')
  const row = host.closest('tr')!
  expect(within(row).getByRole('link', { name: 'ubuntu-24.04-k6.8-3f9c1a' })).toHaveAttribute('href', '/nodegroups/ubuntu-24.04-k6.8')
  expect(within(row).getByText('3 nodes')).toBeInTheDocument()
  expect(within(row).getByText('3.0.13-0ubuntu3')).toBeInTheDocument()
  expect(within(row).getByRole('link', { name: 'debian-13-k6.12-a1b2c3' })).toHaveAttribute('href', '/nodegroups/debian-13-k6.12')
  expect(screen.getByRole('link', { name: 'Control plane' })).toHaveAttribute('href', '/controlplane')
  expect(screen.queryByRole('link', { name: 'test' })).toBeNull()
})

test('grouped by workload, a cluster-level owner opens its own page', async () => {
  mockApi().on(
    '/findings',
    findingsPage({ total: 1, groups: 1, findings: 4, groupRows: [groupRow({ key: 'Nodes//test', label: 'test', findings: 4, distinct: 2 })] }),
  )
  renderApp('/vulnerabilities?group=workload')
  expect(await screen.findByRole('link', { name: 'Nodes (host packages)' })).toHaveAttribute('href', '/nodes')
})
