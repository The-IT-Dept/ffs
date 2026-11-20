import { expect, test } from '@playwright/test'
import { cspViolations, mainPages, settled, themedContext, type Theme } from './support'

// Review Focus 3: the strict CSP blocks nothing the UI needs, in either theme.
test('no CSP violation on any main page in either theme', async ({ browser, request }) => {
  const pages = await mainPages(request)
  const backgrounds: Record<Theme, string[]> = { light: [], dark: [] }
  for (const theme of ['light', 'dark'] as const) {
    const context = await themedContext(browser, theme)
    const page = await context.newPage()
    const errors: string[] = []
    page.on('console', (m) => {
      if (m.type() === 'error') errors.push(`${theme} ${page.url()}: ${m.text()}`)
    })
    page.on('pageerror', (e) => errors.push(`${theme} ${page.url()}: ${e.message}`))

    for (const p of pages) {
      await page.goto(p.path)
      await settled(page)
      expect(await cspViolations(page), `${p.name} in ${theme}`).toEqual([])
      expect(await page.evaluate(() => document.documentElement.classList.contains('dark')), `${p.name} in ${theme}`).toBe(theme === 'dark')
      backgrounds[theme].push(await page.evaluate(() => getComputedStyle(document.body).backgroundColor))
      if (p.name === 'home') {
        // The dialog's scroll lock injects a <style> element.
        await page.keyboard.press('ControlOrMeta+k')
        await expect(page.getByRole('dialog')).toBeVisible()
        await page.keyboard.press('Escape')
        await expect(page.getByRole('dialog')).toBeHidden()
        expect(await cspViolations(page), `command menu in ${theme}`).toEqual([])
      }
    }
    expect(errors).toEqual([])
    await context.close()
  }
  pages.forEach((p, i) => {
    expect(backgrounds.light[i], `${p.name} is styled`).not.toBe('rgba(0, 0, 0, 0)')
    expect(backgrounds.light[i], `${p.name} differs between themes`).not.toBe(backgrounds.dark[i])
  })
})
