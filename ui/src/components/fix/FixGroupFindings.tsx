import { useQuery } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { findingsQuery, PAGE_LIMIT } from '@/components/explorer/params'
import { AppLink } from '@/components/layout/AppLink'
import { EmptyState } from '@/components/layout/EmptyState'
import { ProblemNotice } from '@/components/layout/ProblemNotice'
import { Skeleton } from '@/components/ui/skeleton'
import { copy } from '@/lib/copy'
import { explorerHref } from '@/lib/links'
import { cn, touchLink } from '@/lib/utils'
import { type FixGroupKind, FixGroupList } from './FixGroupList'

// FixGroupFindings is a scope's findings view: its findings grouped by the fix that clears them
// (or by advisory or package), or `empty` when there are none. Each page passes the empty state
// that is true for its scope, so a scope ffs cannot fully see never reads as clean, and may pass a
// notice that leads the groups. It lists the first PAGE_LIMIT groups; past that it says how many
// there are and links the whole list in the explorer.
export function FixGroupFindings({ scope, group = 'fix', empty, notice }: { scope: string; group?: FixGroupKind; empty?: ReactNode; notice?: ReactNode }) {
  // No placeholder data: rows of another scope or grouping would open groups with the wrong filter.
  const q = useQuery(findingsQuery({ scope, group }, { limit: PAGE_LIMIT }))
  if (q.data) {
    const rows = q.data.groupRows
    if (rows.length === 0) return empty ?? <EmptyState />
    return (
      <>
        {notice}
        <FixGroupList key={`${scope}:${group}`} rows={rows} group={group} base={{ scope }} />
        {q.data.total > rows.length ? (
          <p className="mt-2 text-[11px] text-muted-foreground">
            {copy.fixList.showing(rows.length, q.data.total)} ·{' '}
            <AppLink href={explorerHref('findings', { scope, group })} className={cn('hover:text-foreground hover:underline', touchLink)}>
              {copy.fixList.openExplorer}
            </AppLink>
          </p>
        ) : null}
      </>
    )
  }
  if (q.error) return <ProblemNotice error={q.error} />
  return <Skeleton className="h-24" />
}
