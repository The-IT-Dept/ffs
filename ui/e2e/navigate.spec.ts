import { expect, test } from '@playwright/test'
import { api, imageIdOf, imageLinkTo, settled, WEB_PATH, type S } from './support'

test('home → workload → image and back', async ({ page, request }) => {
  const detail = await api<S['WorkloadDetail']>(request, '/workloads/Deployment/shop/web')
  const digest = detail.containers.find((c) => c.digest)?.digest
  expect(digest).toBeTruthy()

  await page.goto('/')
  await settled(page)
  await page.locator(`a[href="${WEB_PATH}"]`).first().click()
  await expect(page).toHaveURL((u) => u.pathname === WEB_PATH)
  await settled(page)

  await page.locator(`a[href="${await imageLinkTo(page, digest!)}"]`).first().click()
  await expect.poll(() => imageIdOf(page.url())).toBe(digest)
  await settled(page)

  await page.goBack()
  await expect(page).toHaveURL((u) => u.pathname === WEB_PATH)
})
