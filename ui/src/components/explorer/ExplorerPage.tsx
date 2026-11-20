import { useQuery } from '@tanstack/react-query'
import { useNavigate } from '@tanstack/react-router'
import { SlidersHorizontal } from 'lucide-react'
import { type ReactNode, useEffect, useMemo, useRef } from 'react'
import { ApiProblem, apiQuery } from '@/api/client'
import type { S } from '@/api/types'
import { EmptyState } from '@/components/layout/EmptyState'
import { goneState } from '@/components/layout/GoneNotice'
import { PageHeader } from '@/components/layout/PageHeader'
import { ProblemNotice } from '@/components/layout/ProblemNotice'
import { CoverageFigureText } from '@/components/signals/CoverageFigureText'
import { Button } from '@/components/ui/button'
import { Sheet, SheetContent, SheetTitle, SheetTrigger } from '@/components/ui/sheet'
import { Skeleton } from '@/components/ui/skeleton'
import { type CountNoun, copy, countsLine } from '@/lib/copy'
import { plural } from '@/lib/format'
import { useMediaQuery, WIDE } from '@/lib/hooks'
import {
  chipsOf,
  EXPLORERS,
  type ExplorerKind,
  type ExplorerSearch,
  explorerSearchFor,
  removeChip,
  revalidate,
  toApiQuery,
  withFacet,
} from '@/lib/query'
import { CLUSTER, parseScope, type Scope, scopeParam } from '@/lib/scope'
import { type Column, ExplorerTable } from './ExplorerTable'
import { FacetColumn } from './FacetColumn'
import { FilterChips } from './FilterChips'
import { GroupSwitch } from './GroupSwitch'
import { GroupTable } from './GroupTable'
import { Pager, useCursorPages } from './Pager'
import { type ExplorerRow, explorerQuery, keepWhileGroup, PAGE_LIMIT } from './params'

const groupNoun: Record<string, CountNoun> = {
  advisory: 'advisories',
  workload: 'workloads',
  image: 'images',
  package: 'packages',
  namespace: 'namespaces',
  fix: 'fixes',
}

function scopeOf(search: ExplorerSearch): Scope {
  try {
    return parseScope(search.scope)
  } catch {
    return CLUSTER
  }
}

function withoutCursor(s: ExplorerSearch): ExplorerSearch {
  const next = { ...s }
  delete next.cursor
  return next
}

function TableSkeleton() {
  return (
    <div className="flex flex-col gap-2 py-2">
      {Array.from({ length: 6 }, (_, i) => (
        <Skeleton key={i} className="h-5" />
      ))}
    </div>
  )
}

// FilterSheet holds the facets below the lg breakpoint, behind a "Filters (n)" button counting the
// active filters (the chips). Toggling a facet keeps the sheet open, so several can be set at once.
function FilterSheet({ count, children }: { count: number; children: ReactNode }) {
  return (
    <Sheet>
      <SheetTrigger asChild>
        <Button variant="outline" className="h-10 shrink-0 px-3 text-[12px] font-normal">
          <SlidersHorizontal aria-hidden="true" />
          {copy.explorer.filters(count)}
        </Button>
      </SheetTrigger>
      <SheetContent side="right" aria-describedby={undefined} closeLabel={copy.shell.close} className="w-[300px] max-w-[85vw] gap-0 overflow-y-auto sm:max-w-[85vw]">
        <SheetTitle className="flex h-12 shrink-0 items-center px-4 text-[13px]">{copy.explorer.filtersTitle}</SheetTitle>
        <div className="px-4 pb-6">{children}</div>
      </SheetContent>
    </Sheet>
  )
}

// ExplorerPage is one explorer: facets, chips, a group switch (findings only), a server-sorted
// table and a cursor pager. The URL is the state: every change goes through onSearch, and every
// filter change drops the cursor. A cursor the server rejects is dropped, and page one loads.
// Below the lg breakpoint the results come first: the facets move into a filters sheet, and the
// chips stay above the table.
export function ExplorerPage<K extends ExplorerKind>({
  kind,
  title,
  search: routeSearch,
  onSearch,
  columns,
  rowKey,
}: {
  kind: K
  title: string
  search: ExplorerSearch
  onSearch: (next: ExplorerSearch, o?: { replace?: boolean }) => void
  columns: Column<ExplorerRow<K>>[]
  rowKey: (r: ExplorerRow<K>) => string
}) {
  const spec = EXPLORERS[kind]
  const wide = useMediaQuery(WIDE)
  // Only what this explorer's endpoint takes; every update below is built from it, so a stray key
  // in a shared URL never reaches the server and is dropped from the URL on the next change.
  const search = useMemo(() => revalidate(explorerSearchFor(kind), routeSearch), [kind, routeSearch])
  const q = useQuery({ ...explorerQuery(kind, search), placeholderData: keepWhileGroup(search.group) })
  const settings = useQuery(apiQuery('/settings', {}))
  const epssBump = settings.data?.priority.epssBump ?? 0.1
  const scope = scopeOf(search)
  // The same key the rail asks, so the coverage beside the count costs no request.
  const card = useQuery(apiQuery('/scope', { query: scopeParam(scope) }))
  const pages = useCursorPages(JSON.stringify(toApiQuery(withoutCursor(search), [])), search.cursor)

  const rejected = q.error instanceof ApiProblem && q.error.code === 'invalid_cursor' && search.cursor !== undefined
  const latest = useRef({ search, onSearch })
  latest.current = { search, onSearch }
  useEffect(() => {
    if (rejected) latest.current.onSearch(withoutCursor(latest.current.search), { replace: true })
  }, [rejected])

  // A scope that no longer exists (a node group re-keyed by a package update, a deleted workload)
  // answers 404 not_found; its list takes over, with the notice the node group page gives.
  const navigate = useNavigate()
  const gone = q.error instanceof ApiProblem && q.error.code === 'not_found' && scope.kind !== 'cluster' ? scope.kind : undefined
  useEffect(() => {
    if (gone) void navigate({ to: gone === 'nodegroup' || gone === 'node' ? '/nodes' : '/workloads', replace: true, state: goneState(gone) })
  }, [gone, navigate])

  const chips = chipsOf(search, epssBump, q.data?.facets)
  const data = q.data
  const grouped = kind === 'findings' && search.group !== undefined
  const findingsData = kind === 'findings' ? (data as S<'FindingsPage'> | undefined) : undefined
  const coverage = card.data?.trust.coverage
  const feeds = card.data?.trust.feeds

  let countLine: string | undefined
  if (data) {
    countLine =
      grouped && findingsData && search.group
        ? countsLine(findingsData.findings, findingsData.groups, groupNoun[search.group] ?? 'advisories')
        : plural(data.total, ...spec.noun)
  }

  const sub = countLine ? (
    <>
      <span>{countLine}</span>
      {coverage ? (
        <>
          {' · '}
          <CoverageFigureText figure={coverage} /> <span>{copy.headline.coverage}</span>
          {coverage.inUse > 0 ? <span> · {copy.headline.seenInto(coverage.seenInto)}</span> : null}
        </>
      ) : null}
    </>
  ) : undefined

  let body
  if (rejected || gone || (!data && !q.error)) body = <TableSkeleton />
  else if (q.error && !data) body = <ProblemNotice error={q.error} />
  else if (data && data.total === 0) body = <EmptyState coverage={coverage} feeds={feeds} scope={scope} filtered={chips.length > 0} />
  else if (data && grouped && findingsData && search.group)
    body = <GroupTable group={search.group} rows={findingsData.groupRows} search={search} />
  else if (data)
    body = (
      <ExplorerTable
        columns={columns}
        rows={data.rows as ExplorerRow<K>[]}
        rowKey={rowKey}
        sort={search.sort ?? spec.sorts[0]}
        busy={q.isPlaceholderData}
        onSort={(v) => onSearch({ ...search, sort: v === spec.sorts[0] ? undefined : v, cursor: undefined })}
      />
    )

  const facetColumn = (className?: string) => (
    <FacetColumn
      kind={kind}
      facets={data?.facets ?? {}}
      search={search}
      epssBump={epssBump}
      onToggle={(key, value, on) => onSearch(withFacet(search, key, value, on))}
      className={className}
    />
  )
  const filterChips = (
    <FilterChips
      chips={chips}
      onRemove={(c) => onSearch(removeChip(search, c))}
      onClear={() => onSearch({ scope: search.scope, group: search.group, sort: search.sort })}
    />
  )
  const groupSwitch =
    kind === 'findings' ? (
      <GroupSwitch
        label={copy.explorer.groupBy}
        value={search.group ?? ''}
        options={['', ...spec.groups].map((g) => ({ value: g, label: copy.explorer.group[g] ?? g }))}
        onChange={(v) => onSearch({ ...search, group: v || undefined, cursor: undefined })}
      />
    ) : null

  return (
    <div className="flex gap-5">
      {wide ? facetColumn() : null}
      <div className="min-w-0 flex-1">
        <PageHeader title={title} sub={sub} />
        {wide ? (
          <div className="mb-2 flex flex-wrap items-center gap-3">
            <div className="min-w-0 flex-1">{filterChips}</div>
            {groupSwitch}
          </div>
        ) : (
          <div className="mb-2 flex flex-col gap-2">
            <div className="flex min-w-0 items-center gap-3">
              <FilterSheet count={chips.length}>{facetColumn('w-full border-r-0 pr-0')}</FilterSheet>
              {groupSwitch}
            </div>
            {filterChips}
          </div>
        )}
        {body}
        {data && data.total > 0 && !rejected ? (
          <Pager
            info={pages}
            total={data.total}
            limit={PAGE_LIMIT}
            hasNext={data.next !== null}
            onNext={() => {
              if (!data.next) return
              pages.recordNext(data.next)
              onSearch({ ...search, cursor: data.next })
            }}
            onPrev={() => onSearch({ ...search, cursor: pages.prev?.cursor })}
            onFirst={() => onSearch(withoutCursor(search))}
          />
        ) : null}
      </div>
    </div>
  )
}
