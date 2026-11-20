import { screen, waitFor, within } from '@testing-library/react'
import { expect, test } from 'vitest'
import { mockApi } from '@/test/api'
import { counts, fixAction, imagesPage, packagesPage, workloadRow, workloadsPage } from '@/test/fixtures'
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

test('the packages explorer links a package to its findings', async () => {
  mockApi().on(
    '/packages',
    packagesPage({ total: 1, rows: [{ ecosystem: 'deb', name: 'openssl', version: '3.5.1-1', images: 2, workloads: 3, counts: counts({ high: 2 }), worst: 'high' }] }),
  )
  renderApp('/packages')
  expect(await screen.findByRole('link', { name: /openssl/ })).toHaveAttribute('href', '/vulnerabilities?package=openssl')
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
