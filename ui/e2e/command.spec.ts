import { expect, test } from '@playwright/test'
import { settled } from './support'

test('⌘K jumps to a workload and the rail rebuilds around it', async ({ page }) => {
  await page.goto('/')
  await settled(page)
  await page.keyboard.press('ControlOrMeta+k')
  const dialog = page.getByRole('dialog')
  await expect(dialog).toBeVisible()
  await dialog.locator('[cmdk-input]').fill('worker')

  const rail = page.waitForResponse((r) => {
    const u = new URL(r.url())
    return u.pathname === '/api/v1/scope' && u.searchParams.get('scope') === 'workload:Deployment/shop/worker' && r.ok()
  })
  await dialog.locator('[cmdk-item][data-value="workload:Deployment/shop/worker"]').click()
  await rail
  await expect(page).toHaveURL((u) => u.pathname === '/workloads/Deployment/shop/worker')
  await expect(dialog).toBeHidden()
  await settled(page)
  await expect(page.locator('h1').first()).toContainText('worker')
})
