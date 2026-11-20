import { screen, waitFor, within } from '@testing-library/react'
import { expect, test } from 'vitest'
import { copy } from '@/lib/copy'
import { mockApi } from '@/test/api'
import { coverageFigure, exposureRow, exposureTable, imagesPage, rowSignals, summary, workloadRef } from '@/test/fixtures'
import { renderApp } from '@/test/render'

const gw = exposureRow({
  id: 'gw:gateway/public',
  depth: 0,
  kind: 'entry',
  label: 'Internet → Gateway gateway/public',
  detail: '3 hostnames · public',
  expandable: true,
  signals: rowSignals({ urgent: 5, high: 2 }),
})
const host = exposureRow({
  id: 'h:shop.example.com',
  parent: gw.id,
  depth: 1,
  kind: 'hostname',
  label: 'shop.example.com',
  workloads: [workloadRef('Deployment', 'shop', 'web'), workloadRef('Deployment', 'shop', 'api')],
  moreWorkloads: 2,
})
const tail = exposureRow({ id: 'tail:gw:gateway/public', parent: gw.id, depth: 1, kind: 'tail', label: '2 more hostnames', detail: 'nothing above medium', expandable: true })
const nodeRow = exposureRow({ id: 'node:worker-1', depth: 1, kind: 'node', label: 'worker-1', signals: rowSignals({ privileged: null, saPower: null }) })
const notExposed = exposureRow({ id: 'not-exposed', depth: 0, kind: 'notexposed', label: 'Not exposed', collapsed: true, expandable: true })

test('the headline shows the summary figures with the contract copy, coverage first', async () => {
  mockApi()
    .on('/summary', summary({ reachable: 3, reachableUrgent: 1, fixable: 12, coverage: coverageFigure({ inUse: 7, seenInto: 5, full: 4 }) }))
    .on('/exposure', exposureTable({ rows: [gw, host, tail, notExposed], maxUrgent: 5 }))
  renderApp('/')
  const main = await screen.findByRole('main')
  for (const t of ['workloads reachable from outside', 'of them carry urgent findings', 'findings where a fixed version exists', 'images in full detail', '5 seen into', '4/7'])
    expect(await within(main).findByText(t)).toBeInTheDocument()
  expect(within(main).getByText('ffs cannot see into 2 of 7 images yet, so this may not be everything.')).toBeInTheDocument()
  expect(within(main).getByText(copy.footnote)).toBeInTheDocument()
})

test('hostname rows link their workloads and fold the rest', async () => {
  mockApi()
    .on('/summary', summary())
    .on('/exposure', exposureTable({ rows: [gw, host], maxUrgent: 5 }))
  renderApp('/')
  expect(await screen.findByRole('link', { name: 'web' })).toHaveAttribute('href', '/workloads/Deployment/shop/web')
  expect(screen.getByText('+2')).toBeInTheDocument()
  // The workloads behind a hostname can sit in several namespaces, so the row names none.
  expect(within(screen.getByRole('row', { name: /shop\.example\.com/ })).queryByText(/shop$/)).toBeNull()
  expect(screen.getAllByRole('columnheader').map((h) => h.textContent)).toEqual(['Path', 'Urgent', 'High', 'Fixable', 'Privileged', 'SA power', 'Exploited', 'Coverage', 'Best fix'])
})

test('regroup writes group to the URL, drops expand and refetches', async () => {
  const api = mockApi()
    .on('/summary', summary())
    .on('/exposure', exposureTable({ rows: [gw] }))
  const { router, user } = renderApp('/?expand=gw:gateway/public')
  await user.click(await screen.findByRole('radio', { name: 'Namespaces' }))
  expect(router.state.location.search).toEqual({ group: 'namespace' })
  await waitFor(() => expect(api.calls('/exposure').at(-1)!.searchParams.get('group')).toBe('namespace'))
  expect(api.calls('/exposure').at(-1)!.searchParams.has('expand')).toBe(false)
})

test('a tail row expands its group through the URL', async () => {
  const api = mockApi()
    .on('/summary', summary())
    .on('/exposure', exposureTable({ rows: [gw, host, tail] }))
  const { router, user } = renderApp('/')
  await user.click(await screen.findByRole('button', { name: /2 more hostnames/ }))
  expect(router.state.location.search).toEqual({ expand: 'gw:gateway/public' })
  await waitFor(() => expect(api.calls('/exposure').at(-1)!.searchParams.get('expand')).toBe('gw:gateway/public'))
})

test('Not exposed stays collapsed until opened', async () => {
  mockApi()
    .on('/summary', summary())
    .on('/exposure', exposureTable({ rows: [notExposed] }))
  const { router, user } = renderApp('/')
  const btn = await screen.findByRole('button', { name: /Not exposed/ })
  expect(btn).toHaveAttribute('aria-expanded', 'false')
  await user.click(btn)
  expect(router.state.location.search).toEqual({ expand: 'not-exposed' })
})

test('node rows show — for privileged and SA power', async () => {
  mockApi()
    .on('/summary', summary())
    .on('/exposure', exposureTable({ group: 'node', rows: [nodeRow] }))
  renderApp('/?group=node')
  expect(within(await screen.findByRole('row', { name: /worker-1/ })).getAllByText('—')).toHaveLength(2)
})

test('the namespace page asks for the namespace scope', async () => {
  const api = mockApi()
    .on('/summary', summary())
    .on('/exposure', exposureTable({ rows: [gw] }))
  renderApp('/namespaces/shop')
  expect(await screen.findByRole('heading', { level: 1, name: 'shop' })).toBeInTheDocument()
  await waitFor(() => expect(api.calls('/exposure')[0].searchParams.get('scope')).toBe('namespace:shop'))
})

test('a namespace explorer view redirects to the scoped explorer', async () => {
  mockApi().on('/images', imagesPage())
  const { router } = renderApp('/namespaces/shop?view=images')
  await waitFor(() => expect(router.state.location.pathname).toBe('/images'))
  expect(router.state.location.search).toEqual({ scope: 'namespace:shop' })
})

test('an empty home view says what ffs cannot see once', async () => {
  mockApi()
    .on('/summary', summary({ coverage: coverageFigure({ inUse: 7, seenInto: 5, full: 4 }) }))
    .on('/exposure', exposureTable({ rows: [] }))
  renderApp('/')
  const main = await screen.findByRole('main')
  expect(await within(main).findByText(copy.coverageFirst(2, 7))).toBeInTheDocument()
  await waitFor(() => expect(within(main).getAllByText(copy.coverageFirst(2, 7))).toHaveLength(1))
  expect(within(main).queryByText(copy.empty)).toBeNull()
})
