import { useQuery } from '@tanstack/react-query'
import { createRoute } from '@tanstack/react-router'
import type { ReactNode } from 'react'
import { apiQuery } from '@/api/client'
import type { S } from '@/api/types'
import { keepWhileGroup } from '@/components/explorer/params'
import { ExposureTable } from '@/components/exposure/ExposureTable'
import { Footnote } from '@/components/exposure/Footnote'
import { RegroupSwitch } from '@/components/exposure/RegroupSwitch'
import { CoverageFirstLine, EmptyState } from '@/components/layout/EmptyState'
import { PageHeader } from '@/components/layout/PageHeader'
import { ProblemNotice } from '@/components/layout/ProblemNotice'
import { CoverageMark } from '@/components/signals/CoverageMark'
import { Skeleton } from '@/components/ui/skeleton'
import { copy } from '@/lib/copy'
import { formatCount } from '@/lib/format'
import { parseHomeSearch, revalidate, toggleExpand } from '@/lib/query'
import { cn } from '@/lib/utils'
import { rootRoute } from './root'

function Stat({ value, label, secondary, className }: { value: ReactNode; label: string; secondary?: string; className?: string }) {
  return (
    <div className="min-w-0">
      <div className={cn('text-[22px] leading-tight font-semibold whitespace-nowrap tabular-nums', className)}>{value}</div>
      <div className="text-[11px] text-muted-foreground">{label}</div>
      {secondary ? <div className="text-[11px] text-muted-foreground">{secondary}</div> : null}
    </div>
  )
}

// Headline is the four home figures: reachable workloads, how many of them carry urgent findings,
// fixable findings, and how many images ffs sees in full detail. Below sm they sit two by two.
function Headline({ s }: { s: S<'Summary'> }) {
  const c = s.coverage
  const figure = `${formatCount(c.full)}/${formatCount(c.inUse)}`
  return (
    <div className="mb-3 grid max-w-4xl grid-cols-2 gap-x-6 gap-y-4 sm:grid-cols-4 sm:gap-6">
      <Stat value={formatCount(s.reachable)} label={copy.headline.reachable} />
      <Stat value={formatCount(s.reachableUrgent)} label={copy.headline.reachableUrgent} className={s.reachableUrgent > 0 ? 'text-(--urgent)' : undefined} />
      <Stat value={formatCount(s.fixable)} label={copy.headline.fixable} />
      <Stat value={c.full < c.inUse ? <CoverageMark>{figure}</CoverageMark> : figure} label={copy.headline.coverage} secondary={copy.headline.seenInto(c.seenInto)} />
    </div>
  )
}

function HomePage() {
  const search = revalidate(parseHomeSearch, homeRoute.useSearch())
  const navigate = homeRoute.useNavigate()
  const group = search.group ?? 'entry'
  const summary = useQuery(apiQuery('/summary', { query: {} }))
  const exposure = useQuery({
    ...apiQuery('/exposure', {
      query: { ...(group !== 'entry' ? { group } : {}), ...(search.expand ? { expand: search.expand.split(',') } : {}) },
    }),
    // Folding keeps the table on screen; a regroup does not.
    placeholderData: keepWhileGroup(group !== 'entry' ? group : undefined),
  })

  let table
  if (exposure.data) {
    table =
      exposure.data.rows.length === 0 ? (
        <EmptyState coverage={summary.data?.coverage} feeds={summary.data?.feeds} />
      ) : (
        <ExposureTable
          table={exposure.data}
          expand={search.expand}
          onToggle={(id) => void navigate({ to: '.', search: { ...search, expand: toggleExpand(search.expand, id) } })}
        />
      )
  } else if (exposure.error) {
    table = <ProblemNotice error={exposure.error} />
  } else {
    table = <Skeleton className="h-40" />
  }

  return (
    <div>
      {summary.data ? <Headline s={summary.data} /> : summary.error ? null : <Skeleton className="mb-3 h-12 max-w-4xl" />}
      {/* An empty table leads with the coverage line itself, so it is said once. */}
      {exposure.data?.rows.length === 0 ? null : <CoverageFirstLine coverage={summary.data?.coverage} className="mb-3 text-[12px] text-muted-foreground" />}
      <PageHeader
        title={copy.page.home}
        actions={<RegroupSwitch value={group} onChange={(g) => void navigate({ to: '.', search: { group: g === 'entry' ? undefined : g } })} />}
      />
      {table}
      <Footnote />
    </div>
  )
}

export const homeRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  validateSearch: parseHomeSearch,
  component: HomePage,
})
