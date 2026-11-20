import { cn } from '@/lib/utils'

// MagnitudeBar is a thin bar for a value against the largest in view; it decorates a number that
// is always shown beside it.
export function MagnitudeBar({ value, max, tone = 'muted' }: { value: number; max: number; tone?: 'urgent' | 'muted' }) {
  const pct = max > 0 ? Math.min(100, Math.max(0, (value / max) * 100)) : 0
  return (
    <span aria-hidden="true" className="inline-block h-[2px] w-12 shrink-0 overflow-hidden rounded-full bg-muted align-middle">
      <span className={cn('block h-full', tone === 'urgent' ? 'bg-(--urgent)' : 'bg-zinc-400')} style={{ width: `${pct}%` }} />
    </span>
  )
}
