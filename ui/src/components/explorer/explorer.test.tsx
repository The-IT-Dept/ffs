import { screen, waitFor, within } from '@testing-library/react'
import { expect, test } from 'vitest'
import { mockApi, problem } from '@/test/api'
import { counts, coverageFigure, facet, feedFreshness, findingRow, findingsPage, groupRow, scopeCard } from '@/test/fixtures'
import { renderApp } from '@/test/render'

const page1 = findingsPage({
  total: 120,
  findings: 120,
  next: 'c2',
  rows: [findingRow({ id: 'f1', advisory: { id: 'CVE-2026-0001', title: 'Example', kev: false, epss: 0.004 } })],
  facets: {
    priority: facet([
      ['urgent', 401, true],
      ['high', 1356],
      ['medium', 5016],
    ]),
    state: facet([
      ['open', 6773, true],
      ['excepted', 12],
      ['resolved', 40],
    ]),
  },
})

// Review Focus 4
test('drops a rejected cursor and loads page one', async () => {
  const api = mockApi().on('/findings', (u) => (u.searchParams.has('cursor') ? problem(400, 'invalid_cursor') : page1))
  const { router } = renderApp('/vulnerabilities?priority=urgent&cursor=stale')
  const main = await screen.findByRole('main')
  expect(await within(main).findByText('CVE-2026-0001', { exact: true })).toBeInTheDocument()
  expect(router.state.location.search).toEqual({ priority: ['urgent'] })
  expect(within(main).queryByRole('alert')).toBeNull()
  expect(api.calls('/findings').at(-1)!.searchParams.has('cursor')).toBe(false)
})

test('a facet click writes the URL, drops the cursor and asks the server', async () => {
  const api = mockApi().on('/findings', page1)
  const { router, user } = renderApp('/vulnerabilities?priority=urgent&cursor=c1')
  const high = await screen.findByRole('checkbox', { name: /^high\b/ })
  expect(high).not.toBeChecked()
  expect(screen.getByRole('checkbox', { name: /^urgent\b/ })).toBeChecked()
  await user.click(high)
  expect(router.state.location.href).toBe('/vulnerabilities?priority=urgent,high')
  await waitFor(() => expect(api.calls('/findings').at(-1)!.searchParams.get('priority')).toBe('urgent,high'))
  expect(api.calls('/findings').at(-1)!.searchParams.get('facets')).toBe('state,priority,fix,signal,ecosystem,namespace,kind')
})

test('shows the server facet counts, never its own', async () => {
  mockApi().on('/findings', page1)
  renderApp('/vulnerabilities')
  expect(await screen.findByRole('checkbox', { name: /^urgent\s*401$/ })).toBeInTheDocument()
  expect(screen.getByRole('checkbox', { name: /^open\b/ })).toBeChecked() // default state, from the URL rule
  expect(screen.getByText('120 findings')).toBeInTheDocument() // total, with one row on the page
  expect(within(screen.getByRole('main')).getByText('6/6')).toBeInTheDocument() // coverage beside the count (default scopeCard)
})

test('chips remove one value and keep the rest', async () => {
  mockApi().on('/findings', page1)
  const { router, user } = renderApp('/vulnerabilities?priority=urgent,high&namespace=shop')
  await user.click(await screen.findByRole('button', { name: 'Remove Priority: high' }))
  expect(router.state.location.search).toEqual({ priority: ['urgent'], namespace: ['shop'] })
})

test('the grouped view shows findings and distinct counts', async () => {
  const api = mockApi().on(
    '/findings',
    findingsPage({
      total: 2,
      groups: 2,
      findings: 17,
      groupRows: [
        groupRow({ key: 'CVE-2026-0001', label: 'Example', findings: 14, distinct: 3, counts: counts({ urgent: 14 }), worst: 'urgent' }),
        groupRow({ key: 'CVE-2026-0002', label: 'Other', findings: 3, distinct: 1, worst: 'high' }),
      ],
    }),
  )
  const { user } = renderApp('/vulnerabilities')
  await user.click(await screen.findByRole('radio', { name: 'Advisory' }))
  expect(await screen.findByText('14 findings · 3 workloads')).toBeInTheDocument()
  expect(screen.getByText('17 findings · 2 advisories')).toBeInTheDocument()
  expect(screen.getByRole('link', { name: /CVE-2026-0001/ })).toHaveAttribute('href', '/vulnerabilities/CVE-2026-0001')
  expect(api.calls('/findings').at(-1)!.searchParams.get('group')).toBe('advisory')
  expect(document.querySelectorAll('[data-slot="table-body"] > [data-slot="table-row"]')).toHaveLength(2)
})

test('the pager walks forward with next and back through the cursor stack', async () => {
  mockApi().on('/findings', (u) => (u.searchParams.get('cursor') === 'c2' ? findingsPage({ ...page1, next: 'c3' }) : page1))
  const { router, user } = renderApp('/vulnerabilities')
  expect(await screen.findByText('Page 1 of 3')).toBeInTheDocument()
  await user.click(screen.getByRole('button', { name: 'Next' }))
  expect(router.state.location.search).toEqual({ cursor: 'c2' })
  expect(await screen.findByText('Page 2 of 3')).toBeInTheDocument()
  await user.click(screen.getByRole('button', { name: 'Previous' }))
  expect(router.state.location.search).toEqual({})
  expect(await screen.findByText('Page 1 of 3')).toBeInTheDocument()
})

test('a shared cursor shows the page count and a way back to the first page', async () => {
  mockApi().on('/findings', page1)
  const { router, user } = renderApp('/vulnerabilities?cursor=c9')
  expect(await screen.findByText('3 pages')).toBeInTheDocument()
  await user.click(screen.getByRole('button', { name: 'First page' }))
  expect(router.state.location.search).toEqual({})
})

test('an empty result leads with coverage on a fresh install', async () => {
  mockApi()
    .on('/findings', findingsPage())
    .on('/scope', scopeCard({ trust: { feeds: feedFreshness(), coverage: coverageFigure({ inUse: 4, seenInto: 0, full: 0 }), settings: true } }))
  renderApp('/vulnerabilities')
  expect(await screen.findByText('ffs cannot see into 4 of 4 images yet, so this may not be everything.')).toBeInTheDocument()
})

test('the kind facet and its chips read cluster-level owners by the label the server gives them', async () => {
  mockApi().on(
    '/findings',
    findingsPage({
      total: 1,
      findings: 1,
      rows: [findingRow({ id: 'f1' })],
      facets: {
        kind: [
          { value: 'Deployment', count: 5, selected: false },
          { value: 'cluster-level:Nodes', count: 3, selected: true, label: 'Nodes (host packages)' },
          { value: 'cluster-level:Cluster', count: 1, selected: false, label: 'Kubernetes (control plane)' },
        ],
      },
    }),
  )
  renderApp('/vulnerabilities?kind=cluster-level:Nodes')
  expect(await screen.findByRole('checkbox', { name: /^Nodes \(host packages\)\s*3$/ })).toBeChecked()
  expect(screen.getByRole('checkbox', { name: /^Kubernetes \(control plane\)\s*1$/ })).not.toBeChecked()
  expect(screen.getByRole('checkbox', { name: /^Deployment\s*5$/ })).toBeInTheDocument()
  expect(screen.queryByText('cluster-level:Nodes')).toBeNull()
  expect(screen.getByRole('button', { name: 'Remove Kind: Nodes (host packages)' })).toBeInTheDocument()
})
