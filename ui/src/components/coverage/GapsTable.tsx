import type { S } from '@/api/types'
import { AppLink } from '@/components/layout/AppLink'
import { EmptyState } from '@/components/layout/EmptyState'
import { CoverageMark } from '@/components/signals/CoverageMark'
import { Mono } from '@/components/signals/Mono'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { copy, gapTodo } from '@/lib/copy'
import { scopePath } from '@/lib/links'
import { parseScope } from '@/lib/scope'

function What({ gap }: { gap: S<'Gap'> }) {
  const text = /[/:]/.test(gap.what) ? <Mono>{gap.what}</Mono> : <span>{gap.what}</span>
  if (!gap.target) return text
  try {
    return (
      <AppLink href={scopePath(parseScope(gap.target.scope))} className="hover:underline">
        {text}
      </AppLink>
    )
  } catch {
    return text
  }
}

// GapsTable lists what ffs cannot see and what to do about it. The API sends codes; the copy
// lives in lib/copy.ts.
export function GapsTable({ gaps, totalGaps }: { gaps: S<'Gap'>[]; totalGaps: number }) {
  if (gaps.length === 0) return <EmptyState message={copy.emptyList.gaps} />
  return (
    <>
      <Table className="text-[12px]">
        <TableHeader>
          <TableRow className="h-[30px] hover:bg-transparent">
            {[copy.gapsTable.what, copy.gapsTable.gap, copy.gapsTable.affects, copy.gapsTable.todo].map((h) => (
              <TableHead key={h} className="h-[30px] py-0 text-[11px] font-medium text-muted-foreground">
                {h}
              </TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {gaps.map((g, i) => (
            <TableRow key={`${g.code}:${g.what}:${i}`}>
              <TableCell className="max-w-[18rem] truncate py-1.5">
                <What gap={g} />
              </TableCell>
              <TableCell className="py-1.5">
                <CoverageMark>{copy.gaps[g.code].gap}</CoverageMark>
              </TableCell>
              <TableCell className="py-1.5 tabular-nums">{copy.affects(g.affects)}</TableCell>
              <TableCell className="py-1.5 whitespace-normal max-lg:min-w-[16rem]">
                <div>{gapTodo(g)}</div>
                {g.detail && g.code !== 'cpe_only_classifier' ? <div className="text-muted-foreground">{g.detail}</div> : null}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {totalGaps > gaps.length ? <p className="mt-2 text-[11px] text-muted-foreground">{copy.moreGaps(gaps.length, totalGaps)}</p> : null}
    </>
  )
}
