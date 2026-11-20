import { readFileSync } from 'node:fs'
import { act, screen, waitFor, within } from '@testing-library/react'
import { expect, test } from 'vitest'
import { keepWhileGroup } from '@/components/explorer/params'
import { copy } from '@/lib/copy'
import { workloadPath } from '@/lib/links'
import { advisoryRoute, controlPlaneRoute, imageRoute, namespaceRoute, nodeGroupRoute, nodeRoute, workloadRoute } from '@/routes/lazy'
import { mockApi } from '@/test/api'
import { advisoryDetail, findingsPage, groupRow, transitionsPage, workloadDetail, workloadRef } from '@/test/fixtures'
import { renderApp } from '@/test/render'
import { documentTitle } from './root'

test('a new page starts #main at the top; back and forward restore it', async () => {
  mockApi().on('/findings', findingsPage())
  const { router } = renderApp('/vulnerabilities')
  expect(router.options.scrollRestoration).toBe(true)
  expect(router.options.scrollToTopSelectors).toEqual(['#main'])
  expect(await screen.findByRole('main')).toHaveAttribute('id', 'main')
})

test('placeholder rows are kept only while the grouping is unchanged', () => {
  const prev = { rows: ['old'] }
  const key = (group?: string) => ['api', '/findings', { query: group ? { group } : {} }] as const
  expect(keepWhileGroup('advisory')(prev, { queryKey: key('advisory') })).toBe(prev)
  expect(keepWhileGroup('workload')(prev, { queryKey: key('advisory') })).toBeUndefined()
  expect(keepWhileGroup(undefined)(prev, { queryKey: key() })).toBe(prev)
  expect(keepWhileGroup(undefined)(prev, { queryKey: key('namespace') })).toBeUndefined()
  expect(keepWhileGroup('advisory')(prev, undefined)).toBeUndefined()
})

test('package groups link and preview within their ecosystem', async () => {
  const api = mockApi().on('/findings', (u) =>
    u.searchParams.get('group') === 'package'
      ? findingsPage({ total: 1, groups: 1, findings: 3, groupRows: [groupRow({ key: 'deb/openssl@3.5.1-1', label: 'openssl 3.5.1-1', findings: 3 })] })
      : findingsPage(),
  )
  renderApp('/vulnerabilities?group=package')
  expect(await screen.findByRole('link', { name: 'openssl 3.5.1-1' })).toHaveAttribute('href', '/vulnerabilities?package=openssl&ecosystem=deb')
  expect(api.calls('/findings').at(-1)!.searchParams.get('group')).toBe('package')
})

test('an open package group asks for its findings within its ecosystem', async () => {
  const api = mockApi()
    .on('/workloads/{kind}/{namespace}/{name}', workloadDetail())
    .on('/findings', (u) =>
      u.searchParams.get('group') === 'package'
        ? findingsPage({ total: 1, groups: 1, findings: 3, groupRows: [groupRow({ key: 'deb/openssl@3.5.1-1', label: 'openssl 3.5.1-1', findings: 3 })] })
        : findingsPage(),
    )
  renderApp(`${workloadPath('Deployment', 'shop', 'web')}?group=package`)
  await waitFor(() =>
    expect(api.calls('/findings').some((u) => u.searchParams.get('package') === 'openssl' && u.searchParams.get('ecosystem') === 'deb' && u.searchParams.get('limit') === '10')).toBe(true),
  )
})

test('history reads a created finding as new and names its trigger', async () => {
  mockApi()
    .on('/workloads/{kind}/{namespace}/{name}', workloadDetail())
    .on(
      '/transitions',
      transitionsPage({
        rows: [
          {
            id: 1,
            at: '2026-11-18T00:00:00Z',
            advisory: 'CVE-2026-0001',
            workload: workloadRef('Deployment', 'shop', 'web'),
            fromState: '',
            toState: 'open',
            fromPriority: 'none',
            toPriority: 'high',
            trigger: 'InventoryChange',
            provisional: false,
          },
        ],
      }),
    )
  renderApp(`${workloadPath('Deployment', 'shop', 'web')}?view=history`)
  const row = await screen.findByRole('row', { name: /CVE-2026-0001/ })
  expect(within(row).getByText('new → open')).toBeInTheDocument()
  expect(within(row).getByText('Inventory changed')).toBeInTheDocument()
  expect(within(row).queryByText('InventoryChange')).toBeNull()
})

test('every transition trigger has a label', () => {
  // model.Trigger
  for (const t of ['NewAdvisory', 'InventoryChange', 'PriorityChange', 'FixAvailable', 'ExceptionExpired', 'Withdrawn', 'UpgradeAvailable']) {
    expect(copy.workload.trigger[t], t).toMatch(/^[A-Z][a-z]+( [a-z]+)*$/)
  }
})

test('advisory references link only over http and https', async () => {
  mockApi().on(
    '/advisories/{id}',
    advisoryDetail({ links: ['https://security.example.com/CVE-2026-0001', 'http://lists.example.com/1', 'javascript:alert(1)', 'ftp://ftp.example.com/x'] }),
  )
  renderApp('/vulnerabilities/CVE-2026-0001')
  expect(await screen.findByRole('link', { name: 'https://security.example.com/CVE-2026-0001' })).toHaveAttribute('href', 'https://security.example.com/CVE-2026-0001')
  expect(screen.getByRole('link', { name: 'http://lists.example.com/1' })).toBeInTheDocument()
  expect(screen.getByText('javascript:alert(1)').closest('a')).toBeNull()
  expect(screen.getByText('ftp://ftp.example.com/x').closest('a')).toBeNull()
})

test('the tab title names the page', async () => {
  mockApi().on('/findings', findingsPage()).on('/workloads/{kind}/{namespace}/{name}', workloadDetail())
  const { router } = renderApp('/vulnerabilities')
  await waitFor(() => expect(document.title).toBe('Vulnerabilities · ffs'))
  await act(() => router.navigate({ href: workloadPath('Deployment', 'shop', 'web') }))
  await waitFor(() => expect(document.title).toBe('Workload · ffs'))
  expect(documentTitle('/')).toBe('Exposure · ffs')
  expect(documentTitle('__root__')).toBe('Not found · ffs')
})

test('an unknown path is titled not found', async () => {
  mockApi()
  renderApp('/no/such/page')
  await waitFor(() => expect(document.title).toBe('Not found · ffs'))
})

test('high text is a darker orange than high fills, and the dark theme declares its colour scheme', () => {
  // Vitest runs from ui/.
  const css = readFileSync('src/styles.css', 'utf8')
  expect(css).toMatch(/:root \{[^}]*--high: #ea580c;[^}]*--high-text: #c2410c;/)
  expect(css).toMatch(/\.dark \{\s*color-scheme: dark;/)
})

test('the detail pages load their code on first visit', async () => {
  for (const r of [advisoryRoute, workloadRoute, imageRoute, namespaceRoute, nodeGroupRoute, nodeRoute, controlPlaneRoute]) {
    expect(typeof r.lazyFn, r.id).toBe('function')
  }
  mockApi().on('/advisories/{id}', advisoryDetail())
  renderApp('/vulnerabilities/CVE-2026-0001')
  expect(await screen.findByRole('heading', { level: 1, name: 'CVE-2026-0001' })).toBeInTheDocument()
})
