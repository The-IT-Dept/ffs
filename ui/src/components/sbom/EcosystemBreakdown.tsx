import type { S } from '@/api/types'
import { MagnitudeBar } from '@/components/signals/MagnitudeBar'
import { formatCount } from '@/lib/format'

// EcosystemBreakdown is the image's package count per ecosystem, in the server's order. The bars
// scale to the largest row for display only.
export function EcosystemBreakdown({ ecosystems }: { ecosystems: S<'ImageDetail'>['ecosystems'] }) {
  const max = Math.max(0, ...ecosystems.map((e) => e.packages))
  return (
    <ul className="flex flex-col gap-1 text-[12px]">
      {ecosystems.map((e) => (
        <li key={e.ecosystem} className="grid grid-cols-[8rem_4rem_auto] items-center gap-3">
          <span className="truncate">{e.ecosystem}</span>
          <span className="text-right tabular-nums">{formatCount(e.packages)}</span>
          <MagnitudeBar value={e.packages} max={max} />
        </li>
      ))}
    </ul>
  )
}
