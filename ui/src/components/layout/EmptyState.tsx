import type { S } from '@/api/types'
import { copy } from '@/lib/copy'
import { AppLink } from './AppLink'

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
  const coverageLine = gap ? (
    <p>
      <span>{copy.coverageFirst(coverage.inUse - coverage.seenInto, coverage.inUse)}</span>{' '}
      <AppLink href="/coverage" className="underline underline-offset-2 hover:text-foreground">
        {copy.coverageLink}
      </AppLink>
    </p>
  ) : null
  return (
    <div className={box}>
      {filtered ? <p>{copy.emptyFiltered}</p> : gap ? null : <p>{copy.empty}</p>}
      {coverageLine}
    </div>
  )
}
