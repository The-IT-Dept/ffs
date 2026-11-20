import { screen, waitFor, within } from '@testing-library/react'
import { expect, test } from 'vitest'
import { advisoryPath } from '@/lib/links'
import { mockApi } from '@/test/api'
import { advisoryDetail, counts, findingRow, findingsPage, fixAction, groupRow } from '@/test/fixtures'
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
