import { Fragment } from 'react'
import type { S } from '@/api/types'
import { copy } from '@/lib/copy'
import { formatCount } from '@/lib/format'
import { priorityTone } from './tone'

const order = ['urgent', 'high', 'medium', 'low'] as const

// PriorityCountsText reads counts as "2 urgent · 1 high · 3 medium", leaving zeros out; urgent and
// high take their colour. All zero reads "none".
export function PriorityCountsText({ counts }: { counts: S<'PriorityCounts'> }) {
  const parts = order.filter((p) => counts[p] > 0)
  if (parts.length === 0) return <span className="text-muted-foreground">{copy.upgrades.nothing}</span>
  return (
    <span className="tabular-nums">
      {parts.map((p, i) => (
        <Fragment key={p}>
          {i > 0 ? <span className="text-muted-foreground"> · </span> : null}
          <span className={p === 'urgent' || p === 'high' ? priorityTone[p].text : undefined}>
            {formatCount(counts[p])} {p}
          </span>
        </Fragment>
      ))}
    </span>
  )
}
