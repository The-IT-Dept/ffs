import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import src from '../../public/theme.js?raw'

function run() {
  new Function(src)()
}

describe('theme.js', () => {
  beforeEach(() => {
    document.documentElement.classList.remove('dark')
    localStorage.clear()
  })
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it.each([
    ['dark', false, true],
    ['light', true, false],
    [null, true, true],
    ['system', false, false],
    ['bogus', true, true],
  ])('stored %s with system dark=%s → dark class %s', (stored, systemDark, want) => {
    if (stored !== null) localStorage.setItem('ffs-theme', stored)
    const matchMedia = vi.fn((query: string) => ({ matches: query === '(prefers-color-scheme: dark)' && systemDark }))
    vi.stubGlobal('matchMedia', matchMedia)
    run()
    expect(document.documentElement.classList.contains('dark')).toBe(want)
  })

  it('removes a dark class left by an earlier choice', () => {
    document.documentElement.classList.add('dark')
    localStorage.setItem('ffs-theme', 'light')
    vi.stubGlobal('matchMedia', () => ({ matches: true }))
    run()
    expect(document.documentElement.classList.contains('dark')).toBe(false)
  })

  it('treats system as light when matchMedia is missing', () => {
    vi.stubGlobal('matchMedia', undefined)
    run()
    expect(document.documentElement.classList.contains('dark')).toBe(false)
  })
})
