import { expect, test } from '@playwright/test'
import { api } from './support'

// Spec G8: the first view renders within 1.5 s from cold.
test('first view renders within 1.5 s from cold', async ({ browser, request }) => {
  await api(request, '/exposure') // the server is warm, as a running pod is; the browser stays cold
  const context = await browser.newContext() // empty HTTP cache
  await context.addInitScript(() => {
    const w = window as unknown as { __ffsFirstView?: number }
    const seen = () => [...document.querySelectorAll('[data-slot="table"]')].some((t) => t.textContent?.includes('Not exposed'))
    new MutationObserver((_, obs) => {
      if (seen()) {
        w.__ffsFirstView ??= performance.now()
        obs.disconnect()
      }
    }).observe(document, { childList: true, subtree: true, characterData: true })
  })
  const page = await context.newPage()
  await page.goto('/')
  await page.locator('[data-slot="table"]', { hasText: 'Not exposed' }).waitFor()
  const ms = await page.evaluate(() => (window as unknown as { __ffsFirstView?: number }).__ffsFirstView)
  expect(ms).toBeDefined()
  test.info().annotations.push({ type: 'first-view-ms', description: ms!.toFixed(0) })
  expect(ms!).toBeLessThan(1500) // performance.now() counts from navigation start
  await context.close()
})
