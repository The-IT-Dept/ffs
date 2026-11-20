import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach, vi } from 'vitest'

// jsdom lacks the layout APIs Radix and cmdk call; they only need the calls to exist.
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
if (!('ResizeObserver' in globalThis)) {
  Object.defineProperty(globalThis, 'ResizeObserver', { configurable: true, writable: true, value: ResizeObserverStub })
}
Element.prototype.scrollIntoView ??= function scrollIntoView() {}
Element.prototype.hasPointerCapture ??= function hasPointerCapture() {
  return false
}
Element.prototype.releasePointerCapture ??= function releasePointerCapture() {}
// The router restores scroll positions, and scrolls #main to the top of a new page; jsdom reports
// window.scrollTo as not implemented and has no Element.scrollTo.
window.scrollTo = function scrollTo() {} as typeof window.scrollTo
Element.prototype.scrollTo ??= function scrollTo() {} as typeof Element.prototype.scrollTo

// Width queries are answered against window.innerWidth, which jsdom sets to 1024, so pages render
// their wide layout unless a test says otherwise; every other query (the colour scheme) is false.
// Widths in rem count 16 px each, the browser default.
function widthMatches(query: string): boolean {
  const px = (m: RegExpExecArray | null) => (m ? Number(m[1]) * (m[2] === 'rem' ? 16 : 1) : undefined)
  const min = px(/\(min-width:\s*(\d+(?:\.\d+)?)(px|rem)\)/.exec(query))
  const max = px(/\(max-width:\s*(\d+(?:\.\d+)?)(px|rem)\)/.exec(query))
  if (min === undefined && max === undefined) return false
  return (min === undefined || window.innerWidth >= min) && (max === undefined || window.innerWidth <= max)
}

if (typeof window.matchMedia !== 'function') {
  Object.defineProperty(window, 'matchMedia', {
    configurable: true,
    writable: true,
    value: (query: string): MediaQueryList => ({
      matches: widthMatches(query),
      media: query,
      onchange: null,
      addEventListener() {},
      removeEventListener() {},
      addListener() {},
      removeListener() {},
      dispatchEvent() {
        return false
      },
    }),
  })
}

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  vi.useRealTimers()
  localStorage.clear()
  document.documentElement.className = ''
})
