import { screen, waitFor, within } from '@testing-library/react'
import { afterEach, expect, test, vi } from 'vitest'
import { copy } from '@/lib/copy'
import { mockApi } from '@/test/api'
import { searchResult } from '@/test/fixtures'
import { renderApp } from '@/test/render'

// The platform spy is restored even when a test fails, so later tests see jsdom's own platform.
afterEach(() => {
  vi.restoreAllMocks()
})

test('opens with Ctrl-K, searches once after typing and jumps to the hit', async () => {
  const api = mockApi().on('/search', (u) =>
    searchResult({
      query: u.searchParams.get('q')!,
      hits: [{ kind: 'workload', id: 'Deployment/shop/web', label: 'web', detail: 'shop · Deployment', worst: 'urgent', scope: 'workload:Deployment/shop/web' }],
    }),
  )
  const { router, user } = renderApp('/')
  await user.keyboard('{Control>}k{/Control}')
  await user.type(within(await screen.findByRole('dialog')).getByRole('combobox'), 'web')
  const option = await screen.findByRole('option', { name: /web/ })
  expect(option).toHaveAttribute('data-value', 'workload:Deployment/shop/web')
  await user.click(option)
  expect(router.state.location.pathname).toBe('/workloads/Deployment/shop/web')
  expect(api.calls('/search').map((u) => u.searchParams.get('q'))).toEqual(['web'])
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
})

test('jumps to a placeholder image in one path segment', async () => {
  mockApi().on('/search', searchResult({ hits: [{ kind: 'image', id: 'unknown:ghcr.io/example/private:1.0', label: 'ghcr.io/example/private:1.0' }] }))
  const { router, user } = renderApp('/')
  await user.keyboard('{Meta>}k{/Meta}')
  await user.type(await screen.findByRole('combobox'), 'private')
  await user.click(await screen.findByRole('option', { name: /private/ }))
  expect(router.state.location.pathname).toBe('/images/unknown%3Aghcr.io%2Fexample%2Fprivate%3A1.0')
})

test('the Nodes and control plane hits open their pages and read by what they hold', async () => {
  mockApi().on(
    '/search',
    searchResult({
      hits: [
        { kind: 'nodes', id: 'test', label: 'Nodes', detail: '3 nodes', worst: 'high' },
        { kind: 'controlplane', id: 'test', label: 'Control plane', detail: 'Kubernetes 1.35.1', scope: 'controlplane' },
      ],
    }),
  )
  const { router, user } = renderApp('/')
  await user.keyboard('{Control>}k{/Control}')
  await user.type(within(await screen.findByRole('dialog')).getByRole('combobox'), 'no')
  const nodes = await screen.findByRole('option', { name: /3 nodes/ })
  expect(nodes).toHaveAttribute('data-value', 'nodes:test')
  expect(nodes).toHaveTextContent(/^Nodes \(host packages\)Nodes/)
  const cp = screen.getByRole('option', { name: /Kubernetes 1\.35\.1/ })
  expect(cp).toHaveAttribute('data-value', 'controlplane:test')
  expect(cp).toHaveTextContent(/^Control planeControl plane/)
  expect(screen.queryByText(copy.command.kind.workload)).toBeNull()
  await user.click(nodes)
  expect(router.state.location.pathname).toBe('/nodes')
})

test('the control plane hit opens the Control plane page', async () => {
  mockApi().on('/search', searchResult({ hits: [{ kind: 'controlplane', id: 'test', label: 'Control plane', scope: 'controlplane' }] }))
  const { router, user } = renderApp('/')
  await user.keyboard('{Control>}k{/Control}')
  await user.type(within(await screen.findByRole('dialog')).getByRole('combobox'), 'control')
  await user.click(await screen.findByRole('option', { name: /Control plane/ }))
  expect(router.state.location.pathname).toBe('/controlplane')
})

test('says to refine the search when more objects matched than are listed', async () => {
  mockApi().on('/search', searchResult({ hits: [{ kind: 'namespace', id: 'kube-system', label: 'kube-system' }], truncated: true }))
  const { user } = renderApp('/')
  await user.keyboard('{Control>}k{/Control}')
  await user.type(within(await screen.findByRole('dialog')).getByRole('combobox'), 'kube')
  expect(await screen.findByText(copy.command.truncated)).toBeInTheDocument()
})

test('does not ask to refine a search that listed everything', async () => {
  mockApi().on('/search', searchResult({ hits: [{ kind: 'namespace', id: 'kube-system', label: 'kube-system' }], truncated: false }))
  const { user } = renderApp('/')
  await user.keyboard('{Control>}k{/Control}')
  await user.type(within(await screen.findByRole('dialog')).getByRole('combobox'), 'kube')
  expect(await screen.findByRole('option', { name: /kube-system/ })).toBeInTheDocument()
  expect(screen.queryByText(copy.command.truncated)).toBeNull()
})

test('the search hint is ⌘K on Apple platforms', async () => {
  mockApi()
  vi.spyOn(navigator, 'platform', 'get').mockReturnValue('MacIntel')
  renderApp('/')
  expect(await screen.findByRole('button', { name: /^Search/ })).toHaveTextContent('⌘K')
})

test('the search hint is Ctrl K off Apple platforms', async () => {
  mockApi()
  vi.spyOn(navigator, 'platform', 'get').mockReturnValue('Linux x86_64')
  renderApp('/')
  expect(await screen.findByRole('button', { name: /^Search/ })).toHaveTextContent('Ctrl K')
})
