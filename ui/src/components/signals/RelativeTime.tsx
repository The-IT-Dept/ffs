import { copy } from '@/lib/copy'
import { formatAge } from '@/lib/format'

export function RelativeTime({ iso }: { iso?: string | null }) {
  if (!iso) return <span className="text-muted-foreground">{copy.noValue}</span>
  return (
    <time dateTime={iso} title={iso}>
      {formatAge(iso)}
    </time>
  )
}
