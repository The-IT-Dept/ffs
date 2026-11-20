import { useRef } from 'react'
import { Button } from '@/components/ui/button'
import { copy } from '@/lib/copy'

// PageInfo places the current cursor: its page number, and the cursor of the page before it.
// page is null when the page was reached by a shared cursor, so its position is unknown.
export interface PageInfo {
  page: number | null
  prev: { cursor?: string } | null
}

interface Entry {
  page: number
  prev?: string // '' is the first page
}

// useCursorPages remembers which page each cursor opened, for one query (baseKey), so Previous,
// browser back and forward all land on known pages. A new query starts over at page one.
export function useCursorPages(baseKey: string, cursor: string | undefined): PageInfo & { recordNext(next: string): void } {
  const state = useRef<{ key: string; pages: Map<string, Entry> }>({ key: baseKey, pages: new Map([['', { page: 1 }]]) })
  if (state.current.key !== baseKey) state.current = { key: baseKey, pages: new Map([['', { page: 1 }]]) }
  const pages = state.current.pages
  const here = cursor ?? ''
  const entry = pages.get(here)
  const info: PageInfo = entry
    ? { page: entry.page, prev: entry.prev === undefined ? null : entry.prev === '' ? {} : { cursor: entry.prev } }
    : { page: null, prev: null }
  return {
    ...info,
    recordNext(next: string) {
      if (entry && !pages.has(next)) pages.set(next, { page: entry.page + 1, prev: here })
    },
  }
}

export function Pager({
  info,
  total,
  limit,
  hasNext,
  onNext,
  onPrev,
  onFirst,
}: {
  info: PageInfo
  total: number | undefined // undefined for a list whose size the server does not report
  limit: number
  hasNext: boolean
  onNext: () => void
  onPrev: () => void
  onFirst: () => void
}) {
  let label: string | null
  if (total === undefined) label = info.page === null ? null : copy.explorer.pageAlone(info.page)
  else {
    const pages = Math.max(1, Math.ceil(total / limit))
    label = info.page === null ? copy.explorer.pages(pages) : copy.explorer.page(info.page, pages)
  }
  return (
    <nav aria-label="Pages" className="mt-3 flex items-center gap-2 text-[12px] text-muted-foreground">
      {label ? <span className="tabular-nums">{label}</span> : null}
      <span className="ml-auto flex items-center gap-1.5">
        {info.page === null ? (
          <Button variant="outline" size="xs" onClick={onFirst}>
            {copy.explorer.first}
          </Button>
        ) : null}
        {info.prev ? (
          <Button variant="outline" size="xs" onClick={onPrev}>
            {copy.explorer.previous}
          </Button>
        ) : null}
        <Button variant="outline" size="xs" disabled={!hasNext} onClick={onNext}>
          {copy.explorer.next}
        </Button>
      </span>
    </nav>
  )
}
