import { expect, test } from '@playwright/test'
import { api, settled, type S } from './support'

test('shows a coverage gap hatched with its remedy', async ({ page, request }) => {
  const cov = await api<S['Coverage']>(request, '/coverage')
  expect(cov.gaps.some((g) => g.code === 'unresolvable_auth')).toBe(true)

  await page.goto('/coverage')
  await settled(page)
  await expect(page.getByText('registry refused access').first()).toBeVisible()
  await expect(page.getByText('Give ffs a pull secret that can read this repository.').first()).toBeVisible()

  const mark = page.locator('.hatched').first()
  await expect(mark).toBeVisible()
  const s = await mark.evaluate((el) => {
    const c = getComputedStyle(el)
    return { bg: c.backgroundImage, border: c.borderTopStyle }
  })
  expect(s.bg).toContain('repeating-linear-gradient')
  expect(s.border).toBe('dashed')
})
