import { screen, waitFor, within } from '@testing-library/react'
import { expect, test } from 'vitest'
import { advisoryPath } from '@/lib/links'
import { copy } from '@/lib/copy'
import { mockApi } from '@/test/api'
import { advisoryDetail, counts, coverageFigure, feedFreshness, findingRow, findingsPage, fixAction, groupRow, summary } from '@/test/fixtures'
import { renderApp } from '@/test/render'

const adv = advisoryDetail({
  id: 'CVE-2026-0001',
  aliases: ['GHSA-xxxx-yyyy-zzzz'],
  title: 'Example advisory',
  severities: [
    { source: 'nvd', severity: 'critical', used: false },
    { source: 'debian', severity: 'high', used: true },
  ],
  kev: { added: '2026-11-01' },
  epss: { score: 0.012, percentile: 0.93 },
  timeline: { published: '2026-10-30T00:00:00Z', observed: '2026-10-31T00:00:00Z', firstMatched: '2026-11-01T00:00:00Z' },
  byFix: [
    groupRow({
      key: 'rebuild:debian:13',
      findings: 3,
      distinct: 3,
      counts: counts({ urgent: 3 }),
      fix: fixAction({ kind: 'rebuild', key: 'rebuild:debian:13', label: 'debian 13 rebuild', title: 'Rebuild to pick up distro fixes' }),
    }),
  ],
  packages: [{ name: 'openssl', ecosystem: 'deb', installed: '3.5.1-1', fixed: ['3.5.2-1'], findings: 3 }],
  uncatalogued: 2,
})

test('shows severity by source and the one used, KEV, EPSS and the timeline', async () => {
  mockApi().on('/advisories/{id}', adv).on('/findings', findingsPage())
  renderApp(advisoryPath('CVE-2026-0001'))
  expect(await screen.findByRole('heading', { level: 1, name: 'CVE-2026-0001' })).toBeInTheDocument()
  expect(within(screen.getByRole('row', { name: /debian/ })).getByText('used')).toBeInTheDocument()
  expect(within(screen.getByRole('row', { name: /nvd/ })).queryByText('used')).toBeNull()
  expect(screen.getByText('KEV · added 2026-11-01')).toBeInTheDocument()
  expect(screen.getByText('EPSS 1.2% · percentile 93%')).toBeInTheDocument()
  for (const t of ['Published', 'Observed by ffs', 'First matched', '2026-10-30', '2026-10-31', '2026-11-01']) expect(screen.getAllByText(t).length).toBeGreaterThan(0)
  expect(screen.getByText('2 images not seen into').closest('.hatched')).not.toBeNull()
})

test('affected workloads are grouped by fix and open by fix key', async () => {
  const api = mockApi()
    .on('/advisories/{id}', adv)
    .on('/findings', findingsPage({ total: 3, findings: 3, rows: [findingRow({ id: 'f1' })] }))
  renderApp(advisoryPath('CVE-2026-0001'))
  expect(await screen.findByText('debian 13 rebuild · clears 3 urgent, 0 high')).toBeInTheDocument()
  await waitFor(() =>
    expect(api.calls('/findings').some((u) => u.searchParams.get('advisory') === 'CVE-2026-0001' && u.searchParams.get('fixKey') === 'rebuild:debian:13')).toBe(true),
  )
  expect(await screen.findByRole('columnheader', { name: 'Workload' })).toBeInTheDocument()
  expect(screen.queryByRole('columnheader', { name: 'Advisory' })).toBeNull()
})

test('an advisory with no affected workloads leads with the images ffs has not seen into', async () => {
  mockApi()
    .on('/advisories/{id}', advisoryDetail({ uncatalogued: 2 }))
    .on('/summary', summary({ coverage: coverageFigure({ inUse: 10, seenInto: 8, full: 7 }) }))
  renderApp(advisoryPath('CVE-2026-0001'))
  expect(await screen.findByText(copy.coverageFirst(2, 10))).toBeInTheDocument()
  expect(screen.queryByText(copy.empty)).toBeNull()
})

test('before the summary is in, an empty affected list still leads with the uncatalogued count', async () => {
  mockApi().on('/advisories/{id}', advisoryDetail({ uncatalogued: 2 }))
  renderApp(advisoryPath('CVE-2026-0001'))
  expect((await screen.findByText('2 images not seen into')).closest('.hatched')).not.toBeNull()
  expect(screen.queryByText(copy.empty)).toBeNull()
})

test('an advisory with no affected workloads and a stale matching feed does not read clean', async () => {
  mockApi()
    .on('/advisories/{id}', advisoryDetail({ uncatalogued: 0 }))
    .on('/summary', summary({ feeds: feedFreshness({ fresh: false, stale: ['osv'] }) }))
  renderApp(advisoryPath('CVE-2026-0001'))
  expect(await screen.findByText('feed out of date: osv')).toBeInTheDocument()
  expect(screen.queryByText(copy.empty)).toBeNull()
})

test('an advisory that affects host packages lists its node groups with members and installed versions', async () => {
  mockApi()
    .on(
      '/advisories/{id}',
      advisoryDetail({
        nodeGroups: [{ id: 'ubuntu-24.04-k6.8', label: 'ubuntu-24.04-k6.8-3f9c1a', nodes: 3, versions: [{ package: 'openssl', version: '3.0.13-0ubuntu3' }] }],
      }),
    )
    .on('/summary', summary())
  renderApp(advisoryPath('CVE-2026-0001'))
  expect(await screen.findByText(copy.advisory.nodeGroups)).toBeInTheDocument()
  const row = screen.getByRole('row', { name: /ubuntu-24\.04/ })
  expect(within(row).getByRole('link', { name: 'ubuntu-24.04-k6.8-3f9c1a' })).toHaveAttribute('href', '/nodegroups/ubuntu-24.04-k6.8')
  expect(within(row).getByText('3')).toBeInTheDocument()
  expect(within(row).getByText('3.0.13-0ubuntu3')).toBeInTheDocument()
})
