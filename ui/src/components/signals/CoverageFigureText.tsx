import type { S } from '@/api/types'
import { copy } from '@/lib/copy'
import { CoverageMark } from './CoverageMark'

// CoverageFigureText is "full/in use", hatched when ffs sees less than everything in full detail.
export function CoverageFigureText({ figure, secondary }: { figure: S<'CoverageFigure'>; secondary?: boolean }) {
  if (figure.inUse === 0) return <span className="text-muted-foreground">{copy.noValue}</span>
  const main = `${figure.full}/${figure.inUse}`
  return (
    <span className="tabular-nums">
      {figure.full < figure.inUse ? <CoverageMark>{main}</CoverageMark> : main}
      {secondary ? <span className="text-muted-foreground"> · {copy.headline.seenInto(figure.seenInto)}</span> : null}
    </span>
  )
}
