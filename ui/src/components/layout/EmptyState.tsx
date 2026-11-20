import type { S } from '@/api/types'
import { copy } from '@/lib/copy'
import { cn } from '@/lib/utils'
import { AppLink } from './AppLink'

// CoverageFirstLine is the coverage-first message, shown wherever ffs cannot see into every image
// in use; it renders nothing when it can.
export function CoverageFirstLine({ coverage, className }: { coverage?: S<'CoverageFigure'>; className?: string }) {
  if (!coverage || coverage.inUse <= coverage.seenInto) return null
  return (
    <p className={className}>
      <span>{copy.coverageFirst(coverage.inUse - coverage.seenInto, coverage.inUse)}</span>{' '}
      <AppLink href="/coverage" className="underline underline-offset-2 hover:text-foreground">
        {copy.coverageLink}
      </AppLink>
    </p>
  )
}

// EmptyState says why a view is empty. When ffs cannot see into every image in use, it leads with
// that instead of "Nothing needs attention", because an empty list is then not proof of nothing.
export function EmptyState({ coverage, filtered, message }: { coverage?: S<'CoverageFigure'>; filtered?: boolean; message?: string }) {
  const box = 'rounded-md border border-dashed px-4 py-6 text-[13px] text-muted-foreground'
  if (message) {
    return (
      <div className={box}>
        <p>{message}</p>
      </div>
    )
  }
  const gap = coverage !== undefined && coverage.inUse > coverage.seenInto
  return (
    <div className={cn(box, 'flex flex-col gap-1')}>
      {filtered ? <p>{copy.emptyFiltered}</p> : gap ? null : <p>{copy.empty}</p>}
      <CoverageFirstLine coverage={coverage} />
    </div>
  )
}
