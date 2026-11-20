import type { S } from '@/api/types'
import { copy } from '@/lib/copy'
import { formatCount } from '@/lib/format'

interface Step {
  label: string
  value: string
  filled: number | null // the share of the track that is filled; null draws no bar
  hatchRest: boolean // the missing remainder is what ffs cannot see
}

function share(n: number, of: number): number {
  return of > 0 ? Math.min(1, Math.max(0, n / of)) : 1
}

// Funnel is pods → distinct images → catalogued → full detail → feeds fresh. Each step's missing
// part is hatched: that is what ffs cannot see. Plain elements, no chart library.
export function Funnel({ funnel }: { funnel: S<'Coverage'>['funnel'] }) {
  const steps: Step[] = [
    { label: copy.funnel.pods, value: funnel.pods === null ? copy.noValue : formatCount(funnel.pods), filled: funnel.pods === null ? null : 1, hatchRest: false },
    { label: copy.funnel.images, value: formatCount(funnel.images), filled: 1, hatchRest: false },
    {
      label: copy.funnel.catalogued,
      value: `${formatCount(funnel.catalogued)}/${formatCount(funnel.images)}`,
      filled: share(funnel.catalogued, funnel.images),
      hatchRest: true,
    },
    {
      label: copy.funnel.full,
      value: `${formatCount(funnel.fullDetail)}/${formatCount(funnel.images)}`,
      filled: share(funnel.fullDetail, funnel.images),
      hatchRest: true,
    },
    {
      label: copy.funnel.feeds,
      value: `${formatCount(funnel.feedsFresh)}/${formatCount(funnel.feedsTotal)}`,
      filled: share(funnel.feedsFresh, funnel.feedsTotal),
      hatchRest: true,
    },
  ]
  return (
    <ol className="mb-6 flex max-w-3xl flex-col gap-2 text-[12px]">
      {steps.map((s) => (
        <li key={s.label} className="grid grid-cols-[9rem_5rem_1fr] items-center gap-3">
          <span>{s.label}</span>
          <span className="text-right tabular-nums">{s.value}</span>
          {s.filled === null ? (
            <span />
          ) : (
            <span aria-hidden="true" className="flex h-2 w-full overflow-hidden rounded-sm bg-muted">
              <span className="block h-full bg-zinc-300 dark:bg-zinc-600" style={{ width: `${s.filled * 100}%` }} />
              {s.hatchRest && s.filled < 1 ? <span className="hatched block h-full" style={{ width: `${(1 - s.filled) * 100}%` }} /> : null}
            </span>
          )}
        </li>
      ))}
    </ol>
  )
}
