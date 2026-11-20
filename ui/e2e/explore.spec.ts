import { expect, test, type Response } from '@playwright/test'
import { imageIdOf, PLACEHOLDER_IMAGE, settled, type S } from './support'

const isFindings = (r: Response) => new URL(r.url()).pathname === '/api/v1/findings' && r.ok()

test('facet selection round-trips through the URL with back and forward', async ({ page }) => {
  const first = page.waitForResponse(isFindings)
  await page.goto('/vulnerabilities')
  const initial = (await (await first).json()) as S['FindingsPage']
  await settled(page)

  const box = page.getByRole('checkbox', { name: /^urgent\b/ })
  const [resp] = await Promise.all([page.waitForResponse(isFindings), box.click()])
  const body = (await resp.json()) as S['FindingsPage']
  expect(new URL(resp.url()).searchParams.get('priority')).toBe('urgent')
  await expect(page).toHaveURL((u) => u.searchParams.get('priority') === 'urgent')
  await expect(box).toBeChecked()
  const rows = page.locator('[data-slot="table-body"] > [data-slot="table-row"]')
  await expect(rows).toHaveCount(body.rows.length + body.groupRows.length)
  expect(body.total).toBeLessThan(initial.total)

  await page.goBack()
  await expect(page).toHaveURL((u) => !u.searchParams.has('priority'))
  await expect(box).not.toBeChecked()
  await expect(rows).toHaveCount(initial.rows.length + initial.groupRows.length)

  await page.goForward()
  await expect(page).toHaveURL((u) => u.searchParams.get('priority') === 'urgent')
  await expect(box).toBeChecked()
  await expect(rows).toHaveCount(body.rows.length + body.groupRows.length)
})

test('opens an unresolvable placeholder image from the images explorer', async ({ page }) => {
  // The image API is asked for the placeholder ID as one percent-encoded segment.
  const isPlaceholderAPI = (r: Response) => {
    const { pathname } = new URL(r.url())
    const prefix = '/api/v1/images/'
    if (!pathname.startsWith(prefix)) return false
    const rest = pathname.slice(prefix.length)
    return !rest.includes('/') && decodeURIComponent(rest) === PLACEHOLDER_IMAGE
  }
  await page.goto('/images')
  await settled(page)

  const link = page.locator('a[href^="/images/"]', { hasText: 'ghcr.io/example/private' }).first()
  const [resp] = await Promise.all([page.waitForResponse(isPlaceholderAPI), link.click()])
  expect(resp.status()).toBe(200)
  await expect.poll(() => imageIdOf(page.url())).toBe(PLACEHOLDER_IMAGE)
  await settled(page)

  const [again] = await Promise.all([page.waitForResponse(isPlaceholderAPI), page.reload()])
  expect(again.status()).toBe(200)
  await settled(page)
  await expect(page.getByText('That page does not exist.')).toHaveCount(0)
})
