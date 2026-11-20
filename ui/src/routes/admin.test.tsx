import { screen, within } from '@testing-library/react'
import { expect, test } from 'vitest'
import { mockApi } from '@/test/api'
import { exceptionsList, feedsList, NOW, settings } from '@/test/fixtures'
import { renderApp } from '@/test/render'

test('the feeds page hatches a stale feed and shows its last error', async () => {
  mockApi().on(
    '/feeds',
    feedsList({
      feeds: [
        { name: 'osv', lastSuccess: NOW, lastAttempt: NOW, lastError: '', staleAfter: '6h0m0s', stale: false },
        { name: 'kev', lastSuccess: '2026-11-10T00:00:00Z', lastAttempt: NOW, lastError: 'dial tcp: timeout', staleAfter: '72h0m0s', stale: true },
      ],
    }),
  )
  renderApp('/feeds')
  expect(within(await screen.findByRole('row', { name: /kev/ })).getByText('stale').closest('.hatched')).not.toBeNull()
  expect(screen.getByText('dial tcp: timeout')).toBeInTheDocument()
})

test('the exceptions page shows expiry, matches and urgent findings not excepted', async () => {
  mockApi().on(
    '/exceptions',
    exceptionsList({
      exceptions: [
        {
          id: 'ops/accept-openssl',
          namespace: 'ops',
          name: 'accept-openssl',
          reason: 'Vendor patch pending',
          expires: '2026-11-01T00:00:00Z',
          advisories: ['CVE-2026-0001'],
          packages: [],
          imageRepositories: [],
          owners: [],
          matchedFindings: 4,
          urgentNotExcepted: 1,
          expired: true,
        },
      ],
    }),
  )
  renderApp('/exceptions')
  const row = await screen.findByRole('row', { name: /accept-openssl/ })
  for (const t of ['expired', 'CVE-2026-0001', '4', '1']) expect(within(row).getByText(t)).toBeInTheDocument()
})

test('the settings page lists configuration keys and values read-only', async () => {
  mockApi().on('/settings', settings({ priority: { epssHigh: 0.5, epssBump: 0.1 } }))
  renderApp('/settings')
  expect(within(await screen.findByRole('row', { name: /priority\.epssBump/ })).getByText('0.1')).toBeInTheDocument()
  expect(screen.queryByRole('textbox')).toBeNull()
})
