import { expect, test } from '@playwright/test'
import { api, CONTROL_URL, settled, WEB_SCOPE, type S } from './support'

// This spec adds a finding (CVE-2099-*) to the shared server's store, so its file name sorts last:
// the specs run in file order on one worker, and the others, the screenshots above all, see the
// fixture as seeded.

test('a new urgent finding appears without a reload', async ({ page, request }) => {
  const q = { scope: WEB_SCOPE, priority: 'urgent' }
  const before = await api<S['FindingsPage']>(request, '/findings', q)

  // The totals of every urgent findings page of the web workload the browser fetches.
  const totals: number[] = []
  page.on('response', async (r) => {
    const u = new URL(r.url())
    if (u.pathname !== '/api/v1/findings' || u.searchParams.get('scope') !== WEB_SCOPE || u.searchParams.get('priority') !== 'urgent' || !r.ok()) {
      return
    }
    try {
      totals.push(((await r.json()) as S['FindingsPage']).total)
    } catch {
      // the body is gone when the page navigated away
    }
  })
  await page.goto(`/vulnerabilities?${new URLSearchParams(q)}`)
  await settled(page)
  await page.evaluate(() => {
    ;(window as unknown as { __ffsNoReload: boolean }).__ffsNoReload = true
  })

  const res = await request.post(`${CONTROL_URL}/transition`)
  expect(res.status()).toBe(201)
  const { advisory } = (await res.json()) as { advisory: string }

  await expect.poll(() => totals.includes(before.total + 1), { timeout: 15_000 }).toBe(true) // refetched by the stream event
  await expect(page.getByText(advisory, { exact: true }).first()).toBeVisible({ timeout: 15_000 })
  expect(await page.evaluate(() => (window as unknown as { __ffsNoReload?: boolean }).__ffsNoReload)).toBe(true)
})
