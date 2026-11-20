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
// The router restores scroll positions; jsdom reports window.scrollTo as not implemented.
window.scrollTo = function scrollTo() {} as typeof window.scrollTo

// Width queries are answered against window.innerWidth, which jsdom sets to 1024, so pages render
// their wide layout unless a test says otherwise; every other query (the colour scheme) is false.
function widthMatches(query: string): boolean {
  const min = /\(min-width:\s*(\d+)px\)/.exec(query)
  const max = /\(max-width:\s*(\d+(?:\.\d+)?)px\)/.exec(query)
  if (!min && !max) return false
  return (!min || window.innerWidth >= Number(min[1])) && (!max || window.innerWidth <= Number(max[1]))
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
