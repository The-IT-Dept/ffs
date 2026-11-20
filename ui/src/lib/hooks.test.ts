import { act, renderHook } from '@testing-library/react'
import { afterEach, expect, test, vi } from 'vitest'
import { useMediaQuery, WIDE } from './hooks'

afterEach(() => {
  vi.unstubAllGlobals()
})

test('useMediaQuery reports the query and follows its changes', () => {
  const listeners = new Set<() => void>()
  let matches = false
  const matchMedia = vi.fn((query: string) => ({
    media: query,
    get matches() {
      return matches
    },
    addEventListener: (_: string, l: () => void) => listeners.add(l),
    removeEventListener: (_: string, l: () => void) => listeners.delete(l),
  }))
  vi.stubGlobal('matchMedia', matchMedia)

  const { result, unmount } = renderHook(() => useMediaQuery(WIDE))
  expect(result.current).toBe(false)
  expect(matchMedia).toHaveBeenCalledWith('(min-width: 64rem)')
  expect(listeners.size).toBe(1)

  act(() => {
    matches = true
    listeners.forEach((l) => l())
  })
  expect(result.current).toBe(true)

  unmount()
  expect(listeners.size).toBe(0)
})

test('WIDE is Tailwind lg in rem, and the test stub answers rem widths at 16 px each', () => {
  expect(WIDE).toBe('(min-width: 64rem)')
  // jsdom's window is 1024 px wide: exactly lg.
  expect(window.innerWidth).toBe(1024)
  expect(window.matchMedia('(min-width: 64rem)').matches).toBe(true)
  expect(window.matchMedia('(min-width: 64.0625rem)').matches).toBe(false)
  expect(window.matchMedia('(max-width: 40rem)').matches).toBe(false)
  expect(window.matchMedia('(min-width: 1024px)').matches).toBe(true)
  const { result } = renderHook(() => useMediaQuery(WIDE))
  expect(result.current).toBe(true)
})
