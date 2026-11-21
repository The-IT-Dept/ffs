import { screen, waitFor, within } from '@testing-library/react'
import { expect, test } from 'vitest'
import { copy } from '@/lib/copy'
import { workloadPath } from '@/lib/links'
import { mockApi } from '@/test/api'
import { counts, exposureEdge, findingRow, findingsPage, fixAction, groupRow, transitionsPage, workloadDetail, workloadRef } from '@/test/fixtures'
import { renderApp } from '@/test/render'

const scope = 'workload:Deployment/shop/web'
const groups = findingsPage({
  total: 3,
  groups: 3,
  findings: 13,
  groupRows: [
    groupRow({
      key: 'upgrade:ghcr.io/example/web:1.4.3',
      findings: 3,
      distinct: 3,
      counts: counts({ urgent: 2, high: 1 }),
      fix: fixAction({ kind: 'upgrade', key: 'upgrade:ghcr.io/example/web:1.4.3', label: 'ghcr.io/example/web:1.4.3', introduces: counts() }),
    }),
    groupRow({
      key: 'package:deb:openssl:3.5.1-1:3.5.2-1',
      findings: 6,
      distinct: 2,
      counts: counts({ urgent: 1 }),
      fix: fixAction({ kind: 'package', key: 'package:deb:openssl:3.5.1-1:3.5.2-1', label: 'openssl 3.5.1-1 → 3.5.2-1' }),
    }),
    groupRow({ key: 'none', findings: 4, distinct: 2, counts: counts({ high: 4 }), fix: fixAction() }),
  ],
})
const detail = workloadDetail({
  workload: workloadRef('Deployment', 'shop', 'web'),
  pods: 2,
  exposed: true,
  managedBy: { tool: 'flux-helmrelease', name: 'web' },
  exposure: [exposureEdge({ entry: 'gateway', entryName: 'gateway/public', listener: 'https', hostname: 'shop.example.com', route: 'HTTPRoute shop/web', service: 'shop/web:8080' })],
  containers: [
    { name: 'web', kind: 'container', image: 'ghcr.io/example/web:1.4.2', repo: 'ghcr.io/example/web', digest: 'sha256:' + 'a'.repeat(64), status: 'catalogued', coverage: 'full' },
  ],
  counts: counts({ urgent: 3, high: 5 }),
  fixable: 9,
})
const mocks = () =>
  mockApi()
    .on('/workloads/{kind}/{namespace}/{name}', detail)
    .on('/findings', (u) => (u.searchParams.has('group') ? groups : findingsPage({ total: 6, findings: 6, rows: [findingRow({ id: 'f9', signals: ['provisional'] })] })))

test('groups findings by the fix that clears them', async () => {
  mocks()
  renderApp(workloadPath('Deployment', 'shop', 'web'))
  expect(await screen.findByText('ghcr.io/example/web:1.4.3 · clears 2 urgent, 1 high · introduces none')).toBeInTheDocument()
  expect(screen.getByText('openssl 3.5.1-1 → 3.5.2-1 · clears 1 urgent, 0 high')).toBeInTheDocument()
  expect(screen.getByText('No fix yet · 4 findings · 2 advisories')).toBeInTheDocument()
  expect(screen.getByRole('heading', { level: 1, name: 'web' })).toBeInTheDocument()
  expect(screen.getByText('Managed by Flux web')).toBeInTheDocument()
})

test('opening a fix group lists its findings by fix key and links the rest', async () => {
  const api = mocks()
  const { user } = renderApp(workloadPath('Deployment', 'shop', 'web'))
  await user.click(await screen.findByRole('button', { name: /openssl 3\.5\.1-1 → 3\.5\.2-1/ }))
  await waitFor(() =>
    expect(
      api
        .calls('/findings')
        .some((u) => u.searchParams.get('fixKey') === 'package:deb:openssl:3.5.1-1:3.5.2-1' && u.searchParams.get('scope') === scope && u.searchParams.get('limit') === '10'),
    ).toBe(true),
  )
  expect(screen.queryByRole('link', { name: /^\+ \d+ more$/ })).toBeNull() // 6 and 3 findings ≤ GROUP_PREVIEW: no link
  expect((await within(screen.getByRole('main')).findAllByText('provisional')).length).toBeGreaterThan(0) // marked, as in the explorer
})

test('draws the exposure path once, with pods', async () => {
  mocks()
  renderApp(workloadPath('Deployment', 'shop', 'web'))
  const path = await screen.findByRole('list', { name: 'Exposure path' })
  expect([...path.querySelectorAll('li')].map((li) => li.textContent)).toEqual([
    'Internet',
    'Gateway gateway/public · https',
    'HTTPRoute shop/web · shop.example.com',
    'shop/web:8080',
    '2 pods',
  ])
})

test('container images link with the workload as their breadcrumb parent', async () => {
  mocks()
  renderApp(workloadPath('Deployment', 'shop', 'web'))
  expect(await screen.findByRole('link', { name: /ghcr\.io\/example\/web/ })).toHaveAttribute('href', `/images/sha256%3A${'a'.repeat(64)}?from=workload:Deployment/shop/web`)
})

test('view tabs and the group switch write the URL', async () => {
  const api = mocks().on('/transitions', transitionsPage())
  const { router, user } = renderApp(workloadPath('Deployment', 'shop', 'web'))
  await user.click(await screen.findByRole('radio', { name: 'Advisory' }))
  expect(router.state.location.search).toEqual({ group: 'advisory' })
  await user.click(screen.getByRole('tab', { name: 'History' }))
  expect(router.state.location.search).toEqual({ group: 'advisory', view: 'history' })
  await waitFor(() => expect(api.calls('/transitions')[0].searchParams.get('scope')).toBe(scope))
})

test('an empty history says no changes are recorded, not that nothing needs attention', async () => {
  mocks().on('/transitions', transitionsPage())
  renderApp(`${workloadPath('Deployment', 'shop', 'web')}?view=history`)
  expect(await screen.findByText(copy.emptyList.history)).toBeInTheDocument()
  expect(screen.queryByText(copy.empty)).toBeNull()
})
