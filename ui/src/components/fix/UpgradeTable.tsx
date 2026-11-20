import { Fragment } from 'react'
import type { S } from '@/api/types'
import { EmptyState } from '@/components/layout/EmptyState'
import { Mono } from '@/components/signals/Mono'
import { PriorityCountsText } from '@/components/signals/PriorityCountsText'
import { RelativeTime } from '@/components/signals/RelativeTime'
import { priorityTone } from '@/components/signals/tone'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { copy } from '@/lib/copy'
import { formatCount } from '@/lib/format'
import { cn } from '@/lib/utils'

type Suggestion = S<'Suggestion'>

const order = ['urgent', 'high', 'medium', 'low'] as const

// NetChange is the change in open findings the upgrade makes, per priority: what it introduces less
// what it fixes, e.g. "+1 urgent · −3 low". Priorities are never summed into one figure, so an
// upgrade that trades low findings for an urgent one never reads as a gain. An introduced urgent or
// high finding takes its colour. The server's own wording is the cell's title.
function NetChange({ s }: { s: Suggestion }) {
  const parts = order.map((p) => ({ p, n: s.introduces[p] - s.fixes[p] })).filter((x) => x.n !== 0)
  if (parts.length === 0) return <span className="text-muted-foreground">{copy.upgrades.noChange}</span>
  return (
    <span className="tabular-nums">
      {parts.map(({ p, n }, i) => (
        <Fragment key={p}>
          {i > 0 ? <span className="text-muted-foreground"> · </span> : null}
          <span className={n > 0 && (p === 'urgent' || p === 'high') ? priorityTone[p].text : undefined}>
            {n > 0 ? `+${formatCount(n)}` : `−${formatCount(-n)}`} {p}
          </span>
        </Fragment>
      ))}
    </span>
  )
}

function UpgradeRow({ s, alternative }: { s: Suggestion; alternative?: boolean }) {
  return (
    <TableRow className={cn('h-[30px]', alternative && 'text-muted-foreground')} title={s.notes.length ? s.notes.join('; ') : undefined}>
      <TableCell className={cn('py-0', alternative && 'pl-6')}>
        <Mono>{s.repo}</Mono>
      </TableCell>
      <TableCell className="py-0">
        <Mono>{`${s.fromTag} → ${s.toTag}`}</Mono>
      </TableCell>
      <TableCell className="py-0">{s.tier}</TableCell>
      <TableCell className="py-0">
        <PriorityCountsText counts={s.fixes} />
      </TableCell>
      <TableCell className="py-0">
        <PriorityCountsText counts={s.remaining} />
      </TableCell>
      <TableCell className="py-0">
        <PriorityCountsText counts={s.introduces} />
      </TableCell>
      <TableCell className="py-0" title={s.netChange}>
        <NetChange s={s} />
      </TableCell>
      <TableCell className="py-0">{s.eol || <span className="text-muted-foreground">{copy.noValue}</span>}</TableCell>
      <TableCell className="py-0">
        <RelativeTime iso={s.computedAt} />
      </TableCell>
    </TableRow>
  )
}

// UpgradeTable lists upgrade candidates with what each fixes, leaves and introduces; each
// candidate's alternatives follow it, indented and muted.
export function UpgradeTable({ suggestions }: { suggestions: Suggestion[] }) {
  if (suggestions.length === 0) return <EmptyState message={copy.upgrades.none} />
  const c = copy.upgrades.cols
  const headers = [c.image, c.change, c.tier, c.fixes, c.remaining, c.introduces, c.net, c.eol, c.checked]
  return (
    <Table className="text-[12px]">
      <TableHeader>
        <TableRow className="h-[30px] hover:bg-transparent">
          {headers.map((h) => (
            <TableHead key={h} className="h-[30px] py-0 text-[11px] font-medium text-muted-foreground">
              {h}
            </TableHead>
          ))}
        </TableRow>
      </TableHeader>
      <TableBody>
        {suggestions.map((s, i) => (
          <Fragment key={`${s.repo}:${s.toTag}:${i}`}>
            <UpgradeRow s={s} />
            {s.alternatives.map((a, j) => (
              <UpgradeRow key={`${a.repo}:${a.toTag}:${j}`} s={a} alternative />
            ))}
          </Fragment>
        ))}
      </TableBody>
    </Table>
  )
}
