import { useState } from 'react'
import type { S } from '@/api/types'
import { Checkbox } from '@/components/ui/checkbox'
import { copy, facetValueLabel } from '@/lib/copy'
import { formatCount } from '@/lib/format'
import { EXPLORERS, type ExplorerKind, type ExplorerSearch } from '@/lib/query'

const FOLD_AFTER = 8

function selected(search: ExplorerSearch, name: string): readonly string[] {
  if (name === 'state') return search.state ?? ['open']
  const v = (search as Record<string, unknown>)[name]
  return Array.isArray(v) ? (v as string[]) : []
}

function FacetSection({
  name,
  values,
  search,
  epssBump,
  onToggle,
}: {
  name: string
  values: S<'FacetValue'>[]
  search: ExplorerSearch
  epssBump: number
  onToggle: (key: keyof ExplorerSearch, value: string, on: boolean) => void
}) {
  const [all, setAll] = useState(false)
  const on = selected(search, name)
  const shown = all ? values : values.slice(0, FOLD_AFTER)
  return (
    <section className="flex flex-col gap-1">
      <h2 className="text-[10px] font-medium tracking-wider text-muted-foreground uppercase">{copy.facetTitle[name] ?? name}</h2>
      <ul className="flex flex-col gap-0.5">
        {shown.map((v) => (
          <li key={v.value}>
            <label className="flex cursor-pointer items-center gap-2 py-0.5 text-[12px]">
              <Checkbox
                className="size-3.5"
                checked={on.includes(v.value)}
                onCheckedChange={(c) => onToggle(name as keyof ExplorerSearch, v.value, c === true)}
              />
              <span className="min-w-0 flex-1 truncate">{facetValueLabel(name, v.value, epssBump)}</span>{' '}
              <span className="text-muted-foreground tabular-nums">{formatCount(v.count)}</span>
            </label>
          </li>
        ))}
      </ul>
      {values.length > FOLD_AFTER ? (
        <button type="button" className="self-start text-[11px] text-muted-foreground hover:text-foreground hover:underline" onClick={() => setAll(!all)}>
          {all ? copy.explorer.showFewer : copy.explorer.showAll}
        </button>
      ) : null}
    </section>
  )
}

// FacetColumn lists each facet's values with the server's counts. A box is checked when the URL
// selects its value (the state facet defaults to open). Folding long lists only hides rows.
export function FacetColumn({
  kind,
  facets,
  search,
  epssBump,
  onToggle,
}: {
  kind: ExplorerKind
  facets: S<'Facets'>
  search: ExplorerSearch
  epssBump: number
  onToggle: (key: keyof ExplorerSearch, value: string, on: boolean) => void
}) {
  return (
    <div className="flex w-[175px] shrink-0 flex-col gap-4 border-r pr-4">
      {EXPLORERS[kind].facets
        .filter((name) => facets[name] !== undefined)
        .map((name) => (
          <FacetSection key={name} name={name} values={facets[name]} search={search} epssBump={epssBump} onToggle={onToggle} />
        ))}
    </div>
  )
}
