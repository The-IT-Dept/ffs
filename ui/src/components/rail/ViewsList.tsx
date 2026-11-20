import type { S, ViewId } from '@/api/types'
import { AppLink } from '@/components/layout/AppLink'
import { CoverageMark } from '@/components/signals/CoverageMark'
import { copy } from '@/lib/copy'
import { formatCompact } from '@/lib/format'
import { viewHref } from '@/lib/links'
import type { Scope } from '@/lib/scope'
import { cn } from '@/lib/utils'

// ViewsList is the ways to look at a scope, each with its count for the scope; a view ffs cannot
// fully see is marked as a gap instead of a number.
export function ViewsList({ scope, views, active, from }: { scope: Scope; views: S<'ViewCount'>[]; active?: ViewId; from?: string }) {
  return (
    <ul className="flex flex-col gap-px">
      {views.map((v) => {
        const current = v.id === active
        return (
          <li key={v.id}>
            <AppLink
              href={viewHref(scope, v.id, from)}
              aria-current={current ? 'page' : undefined}
              className={cn(
                'flex items-center justify-between gap-2 rounded-md px-2 py-1 text-[12px] max-lg:min-h-10',
                current ? 'bg-foreground font-medium text-background' : 'text-foreground hover:bg-muted',
              )}
            >
              <span className="truncate">{copy.view(v.id, scope.kind)}</span>
              {v.gap ? (
                // On the selected row the mark keeps its own ground and text, so it reads in both themes.
                <CoverageMark className={current ? 'bg-background text-foreground' : undefined}>{copy.rail.gap}</CoverageMark>
              ) : v.count !== null ? (
                <span className={cn('tabular-nums', current ? 'text-background/70' : 'text-muted-foreground')}>{formatCompact(v.count)}</span>
              ) : null}
            </AppLink>
          </li>
        )
      })}
    </ul>
  )
}
