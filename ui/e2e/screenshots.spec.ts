import fs from 'node:fs'
import path from 'node:path'
import { expect, test } from '@playwright/test'
import { mainPages, settled, themedContext } from './support'

// Artefacts for review, never compared.
test('captures the six main pages in light and dark', async ({ browser, request }) => {
  const pages = await mainPages(request)
  const dir = path.join(test.info().project.testDir, 'screenshots')
  fs.rmSync(dir, { recursive: true, force: true })
  for (const theme of ['light', 'dark'] as const) {
    const context = await themedContext(browser, theme)
    const page = await context.newPage()
    for (const p of pages) {
      await page.goto(p.path)
      await settled(page)
      await page.screenshot({ path: path.join(dir, `${p.name}-${theme}.png`), fullPage: true })
    }
    await context.close()
  }
  expect(fs.readdirSync(dir).filter((f) => f.endsWith('.png'))).toHaveLength(12)
})

// Spec §3: the layout holds down to 1024 px; wide tables scroll inside shadcn's table container.
test('main pages do not overflow horizontally at 1024 px', async ({ browser, request }) => {
  for (const p of await mainPages(request)) {
    const context = await browser.newContext({ viewport: { width: 1024, height: 768 } })
    const page = await context.newPage()
    await page.goto(p.path)
    await settled(page)
    expect(await page.evaluate(() => document.documentElement.scrollWidth), p.name).toBeLessThanOrEqual(1024)
    await context.close()
  }
})
