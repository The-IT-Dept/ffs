import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { useEffect, useRef, useState } from 'react'
import { apiQuery } from '@/api/client'
import type { S } from '@/api/types'
import { type Column, ExplorerTable } from '@/components/explorer/ExplorerTable'
import { PAGE_LIMIT } from '@/components/explorer/params'
import { Pager, useCursorPages } from '@/components/explorer/Pager'
import { EmptyState } from '@/components/layout/EmptyState'
import { ProblemNotice } from '@/components/layout/ProblemNotice'
import { Mono } from '@/components/signals/Mono'
import { PriorityDot } from '@/components/signals/PriorityDot'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { copy } from '@/lib/copy'
import { formatCount } from '@/lib/format'
import { useDebounced } from '@/lib/hooks'

const SEARCH_DEBOUNCE_MS = 250

type Row = S<'ImagePackageRow'>

const c = copy.image.packageCols
const columns: Column<Row>[] = [
  { id: 'package', header: c.package, cell: (r) => r.name },
  { id: 'version', header: c.version, cell: (r) => <Mono>{r.version}</Mono> },
  { id: 'ecosystem', header: c.ecosystem, cell: (r) => r.ecosystem },
  { id: 'foundBy', header: c.foundBy, cell: (r) => <span className="text-muted-foreground">{r.classifier ?? ''}</span> },
  { id: 'path', header: c.path, cell: (r) => (r.path ? <Mono title={r.path} className="inline-block max-w-[16rem] align-bottom">{r.path}</Mono> : null) },
  { id: 'findings', header: c.findings, align: 'right', cell: (r) => <span className={r.findings === 0 ? 'text-muted-foreground' : undefined}>{formatCount(r.findings)}</span> },
  { id: 'worst', header: c.worst, cell: (r) => <PriorityDot priority={r.worst} /> },
]

// PackageTable is an image's (or a node group's) package list, searched and paged on the server.
// The search box writes q through onQ, debounced, so the query lives in the page's URL.
export function PackageTable({ digest, q, onQ }: { digest: string; q?: string; onQ: (q: string | undefined) => void }) {
  const [input, setInput] = useState(q ?? '')
  const typed = useDebounced(input.trim(), SEARCH_DEBOUNCE_MS)
  const latest = useRef({ q, onQ })
  latest.current = { q, onQ }
  useEffect(() => {
    if (typed !== (latest.current.q ?? '')) latest.current.onQ(typed || undefined)
  }, [typed])

  const baseKey = `${digest}|${q ?? ''}`
  const [paging, setPaging] = useState<{ key: string; cursor?: string }>({ key: baseKey })
  const cursor = paging.key === baseKey ? paging.cursor : undefined
  const pages = useCursorPages(baseKey, cursor)
  const list = useQuery({
    ...apiQuery('/images/{digest}/packages', { path: { digest }, query: { ...(q ? { q } : {}), ...(cursor ? { cursor } : {}) } }),
    placeholderData: keepPreviousData,
  })

  return (
    <div>
      <Input
        type="search"
        aria-label={copy.image.searchPackages}
        placeholder={copy.image.searchPackages}
        value={input}
        onChange={(e) => setInput(e.target.value)}
        className="mb-2 h-8 max-w-xs text-[12px] md:text-[12px]"
      />
      {list.data ? (
        list.data.total === 0 ? (
          <EmptyState filtered={Boolean(q)} />
        ) : (
          <>
            <ExplorerTable columns={columns} rows={list.data.rows} rowKey={(r) => `${r.ecosystem}/${r.name}@${r.version}:${r.path ?? ''}`} busy={list.isPlaceholderData} />
            <Pager
              info={pages}
              total={list.data.total}
              limit={PAGE_LIMIT}
              hasNext={list.data.next !== null}
              onNext={() => {
                const next = list.data?.next
                if (!next) return
                pages.recordNext(next)
                setPaging({ key: baseKey, cursor: next })
              }}
              onPrev={() => setPaging({ key: baseKey, cursor: pages.prev?.cursor })}
              onFirst={() => setPaging({ key: baseKey })}
            />
          </>
        )
      ) : list.error ? (
        <ProblemNotice error={list.error} />
      ) : (
        <Skeleton className="h-24" />
      )}
    </div>
  )
}
