import { act, screen, waitFor, within } from '@testing-library/react'
import { expect, test } from 'vitest'
import { imagePath } from '@/lib/links'
import { mockApi } from '@/test/api'
import { coverageFigure, feedFreshness, scopeCard, workloadsPage } from '@/test/fixtures'
import { renderApp } from '@/test/render'

const shop = scopeCard({
  scope: { scope: 'namespace:shop', kind: 'namespace', label: 'shop' },
  title: 'shop',
  summary: '2 workloads · 1 urgent · 1 exposed',
  breadcrumbs: [{ scope: 'cluster', kind: 'cluster', label: 'test' }],
  views: [
    { id: 'exposure', count: 1, gap: false },
    { id: 'vulnerabilities', count: 1240, gap: false },
    { id: 'images', count: null, gap: true },
  ],
  related: [
    {
      id: 'workloads',
      more: 3,
      items: [
        { scope: 'workload:Deployment/shop/web', kind: 'Deployment', label: 'web', worst: 'urgent', count: 12, gap: false },
        { scope: 'workload:Deployment/shop/worker', kind: 'Deployment', label: 'worker', worst: 'none', count: null, gap: true },
      ],
    },
  ],
})

test('builds the card, scoped views and related items for a namespace', async () => {
  const api = mockApi().on('/scope', shop)
  renderApp('/namespaces/shop')
  const rail = await screen.findByRole('complementary', { name: 'Scope' })
  expect(await within(rail).findByText('2 workloads · 1 urgent · 1 exposed')).toBeInTheDocument()
  expect(within(rail).getByRole('link', { name: /test/ })).toHaveAttribute('href', '/')
  expect(within(rail).getByRole('link', { name: /Vulnerabilities\s*1\.2k/ })).toHaveAttribute('href', '/vulnerabilities?scope=namespace:shop')
  expect(within(rail).getByRole('link', { name: /Exposure/ })).toHaveAttribute('aria-current', 'page')
  expect(within(rail).getByRole('link', { name: /Images/ }).querySelector('.hatched')).not.toBeNull()
  expect(within(rail).getByRole('link', { name: /web/ })).toHaveAttribute('href', '/workloads/Deployment/shop/web')
  expect(within(rail).getByRole('img', { name: 'coverage gap' })).toHaveClass('hatched')
  expect(within(rail).getByRole('link', { name: '+ 3 more' })).toHaveAttribute('href', '/workloads?scope=namespace:shop')
  expect(api.calls('/scope')[0].searchParams.get('scope')).toBe('namespace:shop')
  expect(rail.querySelector('[data-slot="table"]')).toBeNull()
})

test('rebuilds around the destination after navigation', async () => {
  mockApi().on('/scope', (u) =>
    u.searchParams.get('scope') === 'workload:Deployment/shop/web'
      ? scopeCard({ title: 'web', scope: { scope: 'workload:Deployment/shop/web', kind: 'workload', label: 'web' } })
      : scopeCard(),
  )
  const { router } = renderApp('/')
  const rail = await screen.findByRole('complementary', { name: 'Scope' })
  await within(rail).findByText('test')
  await act(() => router.navigate({ href: '/workloads/Deployment/shop/web' }))
  expect(await within(rail).findByText('web')).toBeInTheDocument()
  expect(within(rail).getByText('Deployment')).toBeInTheDocument() // kind label
})

test('filters a related section through its explorer, server-side', async () => {
  mockApi().on('/scope', shop).on('/workloads', workloadsPage())
  const { router, user } = renderApp('/namespaces/shop')
  await user.type(await screen.findByRole('searchbox', { name: 'Filter Workloads' }), 'wor{Enter}')
  expect(router.state.location.href).toBe('/workloads?scope=namespace:shop&q=wor')
})

test('a node scope lists its group members without a filter or a more link', async () => {
  mockApi().on(
    '/scope',
    scopeCard({
      scope: { scope: 'node:worker-1', kind: 'node', label: 'worker-1' },
      related: [{ id: 'members', items: [{ scope: 'node:worker-2', kind: 'node', label: 'worker-2', worst: 'none', count: null, gap: false }], more: 2 }],
    }),
  )
  renderApp('/nodes/worker-1')
  const rail = await screen.findByRole('complementary', { name: 'Scope' })
  expect(await within(rail).findByText('Nodes')).toBeInTheDocument()
  expect(within(rail).queryByRole('searchbox')).toBeNull()
  expect(within(rail).queryByRole('link', { name: '+ 2 more' })).toBeNull()
})

test('passes the breadcrumb parent of an image scope', async () => {
  const api = mockApi()
  renderApp(imagePath('sha256:' + 'a'.repeat(64), 'workload:Deployment/shop/web'))
  await waitFor(() => expect(api.calls('/scope')[0]?.searchParams.get('from')).toBe('workload:Deployment/shop/web'))
})

test('trust footer hatches stale feeds and links exceptions and settings at cluster level', async () => {
  mockApi().on(
    '/scope',
    scopeCard({ trust: { feeds: feedFreshness({ fresh: false, stale: ['kev'] }), coverage: coverageFigure({ inUse: 6, seenInto: 5, full: 4 }), settings: true } }),
  )
  renderApp('/')
  const rail = await screen.findByRole('complementary', { name: 'Scope' })
  expect((await within(rail).findByText('Feeds stale: kev')).closest('.hatched')).not.toBeNull()
  expect(within(rail).getByText('4/6')).toBeInTheDocument()
  expect(within(rail).getByRole('link', { name: 'Exceptions' })).toHaveAttribute('href', '/exceptions')
  expect(within(rail).getByRole('link', { name: 'Settings' })).toHaveAttribute('href', '/settings')
})

test('a long parent trail ends in an ellipsis with the whole trail as its title', async () => {
  mockApi().on(
    '/scope',
    scopeCard({
      scope: { scope: 'workload:Deployment/shop/web', kind: 'workload', label: 'web' },
      title: 'web',
      breadcrumbs: [
        { scope: 'cluster', kind: 'cluster', label: 'test' },
        { scope: 'namespace:shop', kind: 'namespace', label: 'shop' },
      ],
    }),
  )
  renderApp('/vulnerabilities?scope=workload:Deployment/shop/web')
  const rail = await screen.findByRole('complementary', { name: 'Scope' })
  const trail = await within(rail).findByRole('navigation', { name: 'Parent scopes' })
  expect(trail).toHaveAttribute('title', 'test › shop')
  expect(trail).toHaveClass('truncate')
  // Inline links, so the ellipsis applies; atomic inline-flex boxes would clip without one.
  for (const a of within(trail).getAllByRole('link')) expect(a.className).not.toMatch(/inline-flex/)
})
