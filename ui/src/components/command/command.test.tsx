import { screen, waitFor, within } from '@testing-library/react'
import { expect, test, vi } from 'vitest'
import { copy } from '@/lib/copy'
import { mockApi } from '@/test/api'
import { searchResult } from '@/test/fixtures'
import { renderApp } from '@/test/render'

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

test('the search hint is ⌘K on Apple platforms and Ctrl K elsewhere', async () => {
  mockApi()
  vi.spyOn(navigator, 'platform', 'get').mockReturnValue('MacIntel')
  renderApp('/')
  expect(await screen.findByRole('button', { name: /^Search/ })).toHaveTextContent('⌘K')
  vi.restoreAllMocks()
})
