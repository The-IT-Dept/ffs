import type { S } from '@/api/types'
import { TableCell } from '@/components/ui/table'
import { copy } from '@/lib/copy'
import { formatCount } from '@/lib/format'
import { CoverageFigureText } from './CoverageFigureText'
import { FixLabel } from './FixLabel'
import { MagnitudeBar } from './MagnitudeBar'
import { PriorityCount } from './PriorityCount'

const num = 'text-right tabular-nums'

function Count({ n }: { n: number | null }) {
  if (n === null) return <span className="text-muted-foreground">{copy.noValue}</span>
  return <span className={n === 0 ? 'text-muted-foreground' : undefined}>{formatCount(n)}</span>
}

// SignalCells are the eight signal columns after Path, in the Contract's order: Urgent, High,
// Fixable, Privileged, SA power, Exploited, Coverage, Best fix. Unknown node signals read "—".
export function SignalCells({ signals, max }: { signals: S<'RowSignals'>; max: number }) {
  return (
    <>
      <TableCell className={num}>
        <span className="inline-flex items-center justify-end gap-2">
          <PriorityCount priority="urgent" n={signals.urgent} />
          <MagnitudeBar value={signals.urgent} max={max} tone="urgent" />
        </span>
      </TableCell>
      <TableCell className={num}>
        <PriorityCount priority="high" n={signals.high} />
      </TableCell>
      <TableCell className={num}>
        <Count n={signals.fixable} />
      </TableCell>
      <TableCell className={num}>
        <Count n={signals.privileged} />
      </TableCell>
      <TableCell className={num}>
        <Count n={signals.saPower} />
      </TableCell>
      <TableCell className={num}>
        <Count n={signals.exploited} />
      </TableCell>
      <TableCell className={num}>
        <CoverageFigureText figure={signals.coverage} />
      </TableCell>
      <TableCell>
        <FixLabel fix={signals.bestFix} />
      </TableCell>
    </>
  )
}
