import type { S } from '@/api/types'
import { copy } from '@/lib/copy'
import { cn } from '@/lib/utils'

export function FixLabel({ fix }: { fix?: S<'FixAction'> | null }) {
  if (!fix) return <span className="text-muted-foreground">{copy.noValue}</span>
  return (
    <span title={fix.title ?? fix.label} className={cn((fix.kind === 'none' || fix.kind === 'wontfix') && 'text-muted-foreground')}>
      {fix.label}
    </span>
  )
}
