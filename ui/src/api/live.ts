import type { QueryClient } from '@tanstack/react-query'
import { shouldInvalidate } from './keys'
import type { S } from './types'

export const STREAM_URL = '/api/v1/stream'
// A CLOSED EventSource never reconnects by itself; it is recreated after this delay.
export const RECREATE_AFTER_MS = 5000

const CLOSED = 2

// startLive subscribes to the change stream and invalidates the cached queries each event can
// alter. An "all" event, an unreadable event, or the stream opening again after an error refreshes
// every query, so the page never keeps data the store has moved past. It returns a stop function.
export function startLive(qc: QueryClient, source: () => EventSource = () => new EventSource(STREAM_URL)): () => void {
  let current: EventSource | undefined
  let timer: ReturnType<typeof setTimeout> | undefined
  let errored = false
  let stopped = false

  const refreshAll = () => {
    void qc.invalidateQueries({ queryKey: ['api'] })
  }

  const onChanged = (e: Event) => {
    let ev: S<'ChangeEvent'>
    try {
      ev = JSON.parse(String((e as MessageEvent).data)) as S<'ChangeEvent'>
    } catch {
      refreshAll()
      return
    }
    if (!ev || !Array.isArray(ev.kinds) || !Array.isArray(ev.scopes) || ev.kinds.includes('all')) {
      refreshAll()
      return
    }
    void qc.invalidateQueries({ predicate: (q) => shouldInvalidate(q.queryKey, ev) })
  }

  const open = () => {
    const es = source()
    current = es
    es.addEventListener('changed', onChanged)
    es.onopen = () => {
      if (!errored) return
      errored = false
      refreshAll()
    }
    es.onerror = () => {
      errored = true
      if (es.readyState !== CLOSED || stopped || timer !== undefined) return
      timer = setTimeout(() => {
        timer = undefined
        es.close()
        if (!stopped) open()
      }, RECREATE_AFTER_MS)
    }
  }

  open()
  return () => {
    stopped = true
    if (timer !== undefined) clearTimeout(timer)
    timer = undefined
    current?.close()
  }
}
