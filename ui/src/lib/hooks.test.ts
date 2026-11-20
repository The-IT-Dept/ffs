import { act, renderHook } from '@testing-library/react'
import { expect, test, vi } from 'vitest'
import { useMediaQuery, WIDE } from './hooks'

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
  expect(matchMedia).toHaveBeenCalledWith('(min-width: 1024px)')
  expect(listeners.size).toBe(1)

  act(() => {
    matches = true
    listeners.forEach((l) => l())
  })
  expect(result.current).toBe(true)

  unmount()
  expect(listeners.size).toBe(0)
})
