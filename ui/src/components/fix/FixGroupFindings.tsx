import { useQuery } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { findingsQuery } from '@/components/explorer/params'
import { EmptyState } from '@/components/layout/EmptyState'
import { ProblemNotice } from '@/components/layout/ProblemNotice'
import { Skeleton } from '@/components/ui/skeleton'
import { type FixGroupKind, FixGroupList } from './FixGroupList'

// FixGroupFindings is a scope's findings view: its findings grouped by the fix that clears them
// (or by advisory or package), or `empty` when there are none. Each page passes the empty state
// that is true for its scope, so a scope ffs cannot fully see never reads as clean.
export function FixGroupFindings({ scope, group = 'fix', empty }: { scope: string; group?: FixGroupKind; empty?: ReactNode }) {
  // No placeholder data: rows of another scope or grouping would open groups with the wrong filter.
  const q = useQuery(findingsQuery({ scope, group }))
  if (q.data) {
    if (q.data.groupRows.length === 0) return empty ?? <EmptyState />
    return <FixGroupList key={`${scope}:${group}`} rows={q.data.groupRows} group={group} base={{ scope }} />
  }
  if (q.error) return <ProblemNotice error={q.error} />
  return <Skeleton className="h-24" />
}
