import { useCallback, useEffect, useState, useSyncExternalStore } from 'react'

// useDebounced returns value once it has held still for ms.
export function useDebounced<T>(value: T, ms: number): T {
  const [settled, setSettled] = useState(value)
  useEffect(() => {
    const t = setTimeout(() => setSettled(value), ms)
    return () => clearTimeout(t)
  }, [value, ms])
  return settled
}

// WIDE is Tailwind's lg breakpoint (64rem, as lg: and max-lg: are, so the JS layout and the CSS
// agree whatever the browser's font size): from here up the rail and the explorer facets sit
// inline; below it they open as sheets.
export const WIDE = '(min-width: 64rem)'

function matchesNow(query: string): boolean {
  return typeof window.matchMedia === 'function' && window.matchMedia(query).matches
}

// useMediaQuery reports whether query matches, and follows it as the window changes.
export function useMediaQuery(query: string): boolean {
  const subscribe = useCallback(
    (onChange: () => void) => {
      if (typeof window.matchMedia !== 'function') return () => {}
      const mq = window.matchMedia(query)
      mq.addEventListener('change', onChange)
      return () => mq.removeEventListener('change', onChange)
    },
    [query],
  )
  return useSyncExternalStore(
    subscribe,
    () => matchesNow(query),
    () => false,
  )
}
