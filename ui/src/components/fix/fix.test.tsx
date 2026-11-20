import { render, screen, waitFor, within } from '@testing-library/react'
import { expect, test } from 'vitest'
import { copy } from '@/lib/copy'
import { mockApi } from '@/test/api'
import { counts, findingsPage, groupRow, suggestion } from '@/test/fixtures'
import { renderWithRouter } from '@/test/render'
import { FixGroupFindings } from './FixGroupFindings'
import { UpgradeTable } from './UpgradeTable'

test('net change is per priority and never sums across priorities', () => {
  render(
    <UpgradeTable
      suggestions={[
        suggestion({ toTag: '1.5.0', fixes: counts({ low: 3 }), introduces: counts({ urgent: 1 }), netChange: 'fixes 3 low; introduces 1 urgent' }),
        suggestion({ toTag: '1.4.3', fixes: counts({ high: 2 }), introduces: counts({ high: 2 }), netChange: 'fixes 2 high; introduces 2 high' }),
      ]}
    />,
  )
  const traded = screen.getByRole('row', { name: /1\.5\.0/ })
  const net = within(traded).getAllByRole('cell')[6]
  expect(net).toHaveTextContent('+1 urgent · −3 low')
  expect(net).toHaveAttribute('title', 'fixes 3 low; introduces 1 urgent')
  expect(within(net).getByText('+1 urgent')).toHaveClass('text-(--urgent)')
  expect(net).not.toHaveTextContent('−2')
  const even = within(screen.getByRole('row', { name: /1\.4\.3/ })).getAllByRole('cell')[6]
  expect(even).toHaveTextContent(copy.upgrades.noChange)
})

test('grouped findings ask for a page of groups and link the rest in the explorer', async () => {
  const api = mockApi().on(
    '/findings',
    findingsPage({
      total: 120,
      groups: 120,
      findings: 300,
      groupRows: [groupRow({ key: 'CVE-2026-0001', findings: 2, distinct: 1 }), groupRow({ key: 'CVE-2026-0002', findings: 1, distinct: 1 })],
    }),
  )
  renderWithRouter(<FixGroupFindings scope="nodegroup:g1" group="advisory" />)
  expect(await screen.findByText(/Showing 2 of 120/)).toBeInTheDocument()
  expect(screen.getByRole('link', { name: copy.fixList.openExplorer })).toHaveAttribute('href', '/vulnerabilities?scope=nodegroup:g1&group=advisory')
  const grouped = api.calls('/findings').find((u) => u.searchParams.get('group') === 'advisory')!
  expect(grouped.searchParams.get('limit')).toBe('50')
})

test('grouped findings that fit on the page have no link to the rest', async () => {
  mockApi().on('/findings', findingsPage({ total: 1, groups: 1, findings: 2, groupRows: [groupRow({ findings: 2 })] }))
  renderWithRouter(<FixGroupFindings scope="nodegroup:g1" group="advisory" />)
  await waitFor(() => expect(screen.getAllByRole('button').length).toBeGreaterThan(0))
  expect(screen.queryByRole('link', { name: copy.fixList.openExplorer })).toBeNull()
})
