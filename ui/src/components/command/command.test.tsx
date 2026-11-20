import { screen, waitFor, within } from '@testing-library/react'
import { expect, test } from 'vitest'
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
