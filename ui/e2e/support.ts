import { expect, type APIRequestContext, type Browser, type BrowserContext, type Page } from '@playwright/test'
import type { components } from '../src/api/schema'

// Shared helpers of the end-to-end specs, which run against hack/uiserve over the Small fixture.

export type S = components['schemas']

export const WEB_PATH = '/workloads/Deployment/shop/web'
export const WEB_SCOPE = 'workload:Deployment/shop/web'
export const PLACEHOLDER_IMAGE = 'unknown:ghcr.io/example/private:1.0'
export const CONTROL_URL = 'http://127.0.0.1:8098'

export type Theme = 'light' | 'dark'
export type MainPageName = 'home' | 'vulnerabilities' | 'workload' | 'image' | 'advisory' | 'coverage'
export interface MainPage {
  name: MainPageName
  path: string
}

// api GETs /api/v1<path> and returns its JSON body, which must come with a 200.
export async function api<T>(request: APIRequestContext, path: string, params?: Record<string, string>): Promise<T> {
  const res = await request.get(`/api/v1${path}`, { params })
  expect(res.status(), `GET /api/v1${path}`).toBe(200)
  return (await res.json()) as T
}

// LIVE_ADVISORY matches the advisories the live spec adds through the control listener. A reused
// dev server keeps them between runs.
export const LIVE_ADVISORY = /^CVE-2099-/

// mainPages are the six pages the screenshots and the CSP check cover. The image and advisory
// paths are built as lib/links.ts builds them: one percent-encoded segment. The advisory is the
// fixture's first, never one the live spec added.
export async function mainPages(request: APIRequestContext): Promise<MainPage[]> {
  const web = await api<S['WorkloadDetail']>(request, '/workloads/Deployment/shop/web')
  const digest = web.containers.find((c) => c.digest)?.digest
  if (!digest) throw new Error('Deployment/shop/web runs no image with a digest')
  const groups = await api<S['FindingsPage']>(request, '/findings', { group: 'advisory', limit: '200' })
  const advisory = groups.groupRows.map((g) => g.key).find((key) => !LIVE_ADVISORY.test(key))
  if (!advisory) throw new Error('the fixture has no open findings')
  return [
    { name: 'home', path: '/' },
    { name: 'vulnerabilities', path: '/vulnerabilities' },
    { name: 'workload', path: WEB_PATH },
    { name: 'image', path: '/images/' + encodeURIComponent(digest) },
    { name: 'advisory', path: '/vulnerabilities/' + encodeURIComponent(advisory) },
    { name: 'coverage', path: '/coverage' },
  ]
}

// settled waits until the page shows its title and no loading placeholder. It never waits for the
// network to go idle: the open event stream keeps it busy.
export async function settled(page: Page): Promise<void> {
  await expect(page.locator('h1').first()).toBeVisible()
  await expect(page.locator('[data-slot="skeleton"]')).toHaveCount(0)
}

// themedContext is a browser context in the given theme, both as the stored choice and as the
// system preference, that records every Content-Security-Policy violation of each document.
export async function themedContext(browser: Browser, theme: Theme): Promise<BrowserContext> {
  const context = await browser.newContext({ colorScheme: theme })
  await context.addInitScript((t) => {
    try {
      localStorage.setItem('ffs-theme', t)
    } catch {
      // about:blank has no storage
    }
    const w = window as unknown as { __ffsCSP: string[] }
    w.__ffsCSP = []
    document.addEventListener('securitypolicyviolation', (e) => w.__ffsCSP.push(`${e.violatedDirective} ${e.blockedURI}`))
  }, theme)
  return context
}

// cspViolations returns the violations the current document reported, as "directive blocked-URI".
export async function cspViolations(page: Page): Promise<string[]> {
  return page.evaluate(() => (window as unknown as { __ffsCSP?: string[] }).__ffsCSP ?? [])
}

// imageIdOf returns the image ID of an image page's href or URL: its path must be exactly
// /images/<one segment>, and the segment is decoded. Anything else is null.
export function imageIdOf(href: string): string | null {
  const { pathname } = new URL(href, 'http://127.0.0.1')
  const m = /^\/images\/([^/]+)$/.exec(pathname)
  return m ? decodeURIComponent(m[1]) : null
}

// imageLinkTo returns the href of the first link on the page to the image with ID id.
export async function imageLinkTo(page: Page, id: string): Promise<string> {
  const hrefs = await page.locator('a[href^="/images/"]').evaluateAll((els) => els.map((e) => e.getAttribute('href') ?? ''))
  const href = hrefs.find((h) => imageIdOf(h) === id)
  if (!href) throw new Error(`no link to image ${id} among ${hrefs.join(', ')}`)
  return href
}
