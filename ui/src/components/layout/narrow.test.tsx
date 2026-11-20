import { act, screen, waitFor, within } from '@testing-library/react'
import { afterEach, expect, test, vi } from 'vitest'
import { mockApi } from '@/test/api'
import { facet, findingRow, findingsPage, scopeCard } from '@/test/fixtures'
import { renderApp } from '@/test/render'

// The window's width is the one input here: useMediaQuery answers WIDE ((min-width: 1024px)) from
// media.wide, and every other query as no match.
const media = vi.hoisted(() => ({ wide: true, asked: [] as string[] }))
vi.mock('@/lib/hooks', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/hooks')>()
  return {
    ...actual,
    useMediaQuery: (query: string) => {
      media.asked.push(query)
      return query === actual.WIDE ? media.wide : false
    },
  }
})

afterEach(() => {
  media.wide = true
  media.asked = []
})

const card = scopeCard({
  views: [
    { id: 'exposure', count: 2, gap: false },
    { id: 'vulnerabilities', count: null, gap: true },
  ],
})

test('from 1024 px the rail sits inline and there is no menu button', async () => {
  media.wide = true
  mockApi().on('/scope', card)
  renderApp('/')
  const rail = await screen.findByRole('complementary', { name: 'Scope' })
  expect(await within(rail).findByText('Kubernetes 1.35.0 · 3 nodes · 4 namespaces')).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: 'Open navigation' })).toBeNull()
  // jsdom reports no platform, so the hint is the one for every platform but Apple's.
  expect(screen.getByRole('button', { name: /^Search/ })).toHaveTextContent('Ctrl K')
  expect(media.asked).toContain('(min-width: 1024px)')
})

test('below 1024 px the rail is a drawer behind a menu button that names the scope', async () => {
  media.wide = false
  mockApi().on('/scope', card)
  renderApp('/')
  const menu = await screen.findByRole('button', { name: 'Open navigation' })
  await waitFor(() => expect(menu).toHaveTextContent('Clustertest'))
  expect(menu).toHaveAttribute('title', 'Cluster: test')
  expect(screen.queryByRole('complementary', { name: 'Scope' })).toBeNull()
  expect(screen.queryByText('Kubernetes 1.35.0 · 3 nodes · 4 namespaces')).toBeNull()
  const search = screen.getByRole('button', { name: 'Search' })
  expect(search).not.toHaveTextContent('Ctrl K')
  expect(search).not.toHaveTextContent('⌘K')
})

test('the drawer opens with the rail, closes on Escape and gives focus back to the menu button', async () => {
  media.wide = false
  mockApi().on('/scope', card)
  const { user } = renderApp('/')
  const menu = await screen.findByRole('button', { name: 'Open navigation' })
  await user.click(menu)
  const drawer = await screen.findByRole('dialog', { name: 'Navigation' })
  expect(within(drawer).getByText('Kubernetes 1.35.0 · 3 nodes · 4 namespaces')).toBeInTheDocument()
  expect(drawer).toContainElement(document.activeElement as HTMLElement)
  await user.keyboard('{Escape}')
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  expect(menu).toHaveFocus()
})

test('the drawer closes when one of its links navigates', async () => {
  media.wide = false
  mockApi().on('/scope', card).on('/findings', findingsPage())
  const { router, user } = renderApp('/')
  await user.click(await screen.findByRole('button', { name: 'Open navigation' }))
  const drawer = await screen.findByRole('dialog', { name: 'Navigation' })
  await user.click(within(drawer).getByRole('link', { name: /Vulnerabilities/ }))
  expect(router.state.location.pathname).toBe('/vulnerabilities')
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
})

test('the drawer closes on any route change, not only its own links', async () => {
  media.wide = false
  mockApi().on('/scope', card).on('/findings', findingsPage())
  const { router, user } = renderApp('/')
  await user.click(await screen.findByRole('button', { name: 'Open navigation' }))
  expect(await screen.findByRole('dialog', { name: 'Navigation' })).toBeInTheDocument()
  await act(() => router.navigate({ href: '/vulnerabilities?priority=urgent' }))
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  // Back to the page it was opened on, it stays closed.
  await act(() => router.navigate({ href: '/' }))
  expect(await screen.findByRole('button', { name: 'Open navigation' })).toBeInTheDocument()
  expect(screen.queryByRole('dialog')).toBeNull()
})

test('the selected view keeps its gap mark legible: the mark brings its own ground and text', async () => {
  media.wide = true
  mockApi().on('/scope', card).on('/findings', findingsPage())
  renderApp('/vulnerabilities')
  const rail = await screen.findByRole('complementary', { name: 'Scope' })
  const current = await within(rail).findByRole('link', { name: /Vulnerabilities/ })
  expect(current).toHaveAttribute('aria-current', 'page')
  const mark = current.querySelector('.hatched')
  expect(mark).toHaveClass('bg-background', 'text-foreground')
  expect(within(rail).getByRole('link', { name: /Exposure/ }).querySelector('.hatched')).toBeNull()
})

const page = findingsPage({
  total: 120,
  findings: 120,
  rows: [findingRow({ id: 'f1', advisory: { id: 'CVE-2026-0001', title: 'Example', kev: false, epss: 0.004 } })],
  facets: {
    priority: facet([
      ['urgent', 401, true],
      ['high', 1356],
    ]),
    namespace: facet([['shop', 90, true]]),
  },
})

test('below 1024 px the explorer puts results first and its facets in a Filters (n) sheet', async () => {
  media.wide = false
  mockApi().on('/findings', page)
  const { router, user } = renderApp('/vulnerabilities?priority=urgent&namespace=shop')
  const main = await screen.findByRole('main')
  const filters = await within(main).findByRole('button', { name: 'Filters (2)' })
  // No facet column on the page; the results and the chips are.
  expect(within(main).queryByRole('checkbox')).toBeNull()
  expect(await within(main).findByText('CVE-2026-0001', { exact: true })).toBeInTheDocument()
  expect(within(main).getByRole('button', { name: 'Remove Priority: urgent' })).toBeInTheDocument()
  expect(within(main).getByRole('button', { name: 'Remove Namespace: shop' })).toBeInTheDocument()
  // The filters button comes before the results table.
  const table = main.querySelector('[data-slot="table"]')!
  expect(filters.compareDocumentPosition(table) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()

  await user.click(filters)
  const sheet = await screen.findByRole('dialog', { name: 'Filters' })
  expect(within(sheet).getByRole('checkbox', { name: /^urgent\s*401$/ })).toBeChecked()
  expect(within(sheet).getByRole('checkbox', { name: /^shop\b/ })).toBeChecked()
  await user.click(within(sheet).getByRole('checkbox', { name: /^high\b/ }))
  expect(router.state.location.search).toEqual({ priority: ['urgent', 'high'], namespace: ['shop'] })
  // Setting a filter keeps the sheet open; closing it shows the new count.
  expect(screen.getByRole('dialog', { name: 'Filters' })).toBeInTheDocument()
  await user.keyboard('{Escape}')
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  expect(await screen.findByRole('button', { name: 'Filters (3)' })).toBeInTheDocument()
})

test('from 1024 px the explorer keeps its facet column and has no filters button', async () => {
  media.wide = true
  mockApi().on('/findings', page)
  renderApp('/vulnerabilities?priority=urgent&namespace=shop')
  expect(await screen.findByRole('checkbox', { name: /^urgent\s*401$/ })).toBeChecked()
  expect(screen.queryByRole('button', { name: /^Filters/ })).toBeNull()
})
