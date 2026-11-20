import { afterEach, expect, test, vi } from 'vitest'
import { apiKey, createQueryClient } from './client'
import { shouldInvalidate } from './keys'
import { RECREATE_AFTER_MS, startLive } from './live'
import type { ChangeKind, S } from './types'

type Listener = (e: MessageEvent) => void

class FakeSource {
  readyState = 0
  onopen: (() => void) | null = null
  onerror: (() => void) | null = null
  close = vi.fn()
  private listeners: Listener[] = []

  addEventListener(type: string, fn: Listener) {
    if (type === 'changed') this.listeners.push(fn)
  }

  open() {
    this.readyState = 1
    this.onopen?.()
  }

  fail(closed = false) {
    this.readyState = closed ? 2 : 0
    this.onerror?.()
  }

  emit(ev: S<'ChangeEvent'>) {
    const e = new MessageEvent('changed', { data: JSON.stringify(ev) })
    for (const fn of this.listeners) fn(e)
  }
}

const keys = [apiKey('/findings', { query: { scope: 'namespace:ops' } }), apiKey('/settings', {}), apiKey('/nodegroups', {})]

afterEach(() => {
  vi.useRealTimers()
})

test('an all event or a reconnect invalidates every active query', () => {
  const qc = createQueryClient({ retry: false })
  keys.forEach((k) => qc.setQueryData(k, {}))
  const src = new FakeSource()
  const stop = startLive(qc, () => src as unknown as EventSource)
  src.open()
  expect(keys.map((k) => qc.getQueryState(k)!.isInvalidated)).toEqual([false, false, false]) // first open: no refresh
  src.emit({ seq: 'a-1', kinds: ['all'], scopes: ['*'] })
  expect(keys.every((k) => qc.getQueryState(k)!.isInvalidated)).toBe(true)
  keys.forEach((k) => qc.setQueryData(k, {})) // success resets isInvalidated
  expect(keys.some((k) => qc.getQueryState(k)!.isInvalidated)).toBe(false)
  src.fail()
  src.open()
  expect(keys.every((k) => qc.getQueryState(k)!.isInvalidated)).toBe(true)
  stop()
  expect(src.close).toHaveBeenCalled()
})

test('a changed event invalidates by endpoint kinds and scope', () => {
  const ev = (kinds: ChangeKind[], scopes: string[]) => ({ seq: 'a-2', kinds, scopes })
  const f = (scope?: string) => apiKey('/findings', scope ? { query: { scope } } : {})
  expect(shouldInvalidate(f('namespace:shop'), ev(['findings'], ['cluster', 'namespace:shop']))).toBe(true)
  expect(shouldInvalidate(f('namespace:ops'), ev(['findings'], ['cluster', 'namespace:shop']))).toBe(false)
  expect(shouldInvalidate(f(), ev(['findings'], ['workload:Deployment/shop/web']))).toBe(true)
  expect(shouldInvalidate(f('cluster'), ev(['findings'], ['image:sha256:aa']))).toBe(true)
  expect(shouldInvalidate(f(), ev(['feeds'], ['*']))).toBe(false)
  expect(shouldInvalidate(apiKey('/summary', {}), ev(['feeds'], ['*']))).toBe(true)
  expect(shouldInvalidate(apiKey('/summary', { query: { scope: 'nodegroup:g1' } }), ev(['nodes'], ['nodegroup:*']))).toBe(true)
  expect(shouldInvalidate(apiKey('/summary', { query: { scope: 'nodegroup:g1' } }), ev(['nodes'], ['node:*']))).toBe(false)
  expect(shouldInvalidate(apiKey('/nodegroups/{id}', { path: { id: 'g1' } }), ev(['nodes'], ['nodegroup:*']))).toBe(true)
  expect(shouldInvalidate(apiKey('/search', { query: { q: 'web' } }), ev(['findings', 'inventory', 'images', 'feeds', 'nodes', 'exceptions'], ['*']))).toBe(false)
  expect(shouldInvalidate(apiKey('/search', { query: { q: 'web' } }), ev(['all'], ['*']))).toBe(true)
  expect(shouldInvalidate(['other'], ev(['all'], ['*']))).toBe(false)
})

test('a closed stream is recreated after 5 s and refreshes everything when it opens', () => {
  vi.useFakeTimers()
  const qc = createQueryClient({ retry: false })
  const made: FakeSource[] = []
  const stop = startLive(qc, () => {
    const s = new FakeSource()
    made.push(s)
    return s as unknown as EventSource
  })
  const k = keys[0]
  made[0].open()
  made[0].fail(true)
  vi.advanceTimersByTime(RECREATE_AFTER_MS - 1)
  expect(made).toHaveLength(1)
  vi.advanceTimersByTime(1)
  expect(made).toHaveLength(2)
  qc.setQueryData(k, {})
  expect(qc.getQueryState(k)!.isInvalidated).toBe(false)
  made[1].open()
  expect(qc.getQueryState(k)!.isInvalidated).toBe(true)
  stop()
  expect(made[1].close).toHaveBeenCalled()
})
