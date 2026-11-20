import { Fragment } from 'react'
import type { S } from '@/api/types'
import { EmptyState } from '@/components/layout/EmptyState'
import { Mono } from '@/components/signals/Mono'
import { PriorityCountsText } from '@/components/signals/PriorityCountsText'
import { RelativeTime } from '@/components/signals/RelativeTime'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { copy } from '@/lib/copy'
import { formatCount } from '@/lib/format'
import { cn } from '@/lib/utils'

type Suggestion = S<'Suggestion'>

const total = (c: S<'PriorityCounts'>) => c.urgent + c.high + c.medium + c.low

// netOf is the signed change in open findings the upgrade makes: what it introduces less what it
// fixes. The server's own wording is the cell's title.
function netOf(s: Suggestion): string {
  const n = total(s.introduces) - total(s.fixes)
  if (n > 0) return `+${formatCount(n)}`
  if (n < 0) return `−${formatCount(-n)}`
  return '0'
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
      <TableCell className="py-0 text-right tabular-nums" title={s.netChange}>
        {netOf(s)}
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
            <TableHead key={h} className={cn('h-[30px] py-0 text-[11px] font-medium text-muted-foreground', h === c.net && 'text-right')}>
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
