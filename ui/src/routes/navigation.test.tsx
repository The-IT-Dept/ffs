import { readFileSync } from 'node:fs'
import { act, fireEvent, screen, waitFor, within } from '@testing-library/react'
import { expect, test, vi } from 'vitest'
import { keepWhileGroup } from '@/components/explorer/params'
import { copy } from '@/lib/copy'
import { workloadPath } from '@/lib/links'
import { advisoryRoute, controlPlaneRoute, imageRoute, namespaceRoute, nodeGroupRoute, nodeRoute, workloadRoute } from '@/routes/lazy'
import { mockApi } from '@/test/api'
import { advisoryDetail, findingsPage, groupRow, transitionsPage, workloadDetail, workloadRef } from '@/test/fixtures'
import { renderApp } from '@/test/render'
import { documentTitle } from './root'

test('a new page starts #main at the top; back and forward restore it', async () => {
  mockApi().on('/findings', findingsPage()).on('/workloads/{kind}/{namespace}/{name}', workloadDetail())
  const { router } = renderApp('/vulnerabilities')
  const main = await screen.findByRole('main')
  expect(main).toHaveAttribute('id', 'main')
  // jsdom lays nothing out, so #main's offset is held here: the router reads it when it leaves a
  // page, sets it when it comes back, and scrolls #main to the top of a new page.
  let top = 0
  Object.defineProperty(main, 'scrollTop', {
    configurable: true,
    get: () => top,
    set: (v: number) => {
      top = v
    },
  })
  const scrollTo = vi.fn((o?: ScrollToOptions) => {
    top = o?.top ?? top
  })
  main.scrollTo = scrollTo as typeof main.scrollTo
  const scroll = (y: number) => {
    top = y
    fireEvent.scroll(main)
  }

  scroll(480)
  await act(() => router.navigate({ href: workloadPath('Deployment', 'shop', 'web') }))
  await waitFor(() => expect(router.state.location.pathname).toBe(workloadPath('Deployment', 'shop', 'web')))
  expect(scrollTo).toHaveBeenLastCalledWith(expect.objectContaining({ top: 0, left: 0 }))
  expect(top).toBe(0)

  scroll(120)
  scrollTo.mockClear()
  await act(() => router.history.back())
  await waitFor(() => expect(router.state.location.pathname).toBe('/vulnerabilities'))
  await waitFor(() => expect(top).toBe(480))
  expect(scrollTo).not.toHaveBeenCalled()

  await act(() => router.history.forward())
  await waitFor(() => expect(router.state.location.pathname).toBe(workloadPath('Deployment', 'shop', 'web')))
  await waitFor(() => expect(top).toBe(120))
  expect(scrollTo).not.toHaveBeenCalled()
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
