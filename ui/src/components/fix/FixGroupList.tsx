import { useQuery } from '@tanstack/react-query'
import { ChevronDown, ChevronRight } from 'lucide-react'
import { useState } from 'react'
import type { S } from '@/api/types'
import type { Column } from '@/components/explorer/ExplorerTable'
import { ExplorerTable } from '@/components/explorer/ExplorerTable'
import { OwnerCell } from '@/components/explorer/OwnerCell'
import { findingsQuery } from '@/components/explorer/params'
import { PriorityCell } from '@/components/explorer/PriorityCell'
import { AppLink } from '@/components/layout/AppLink'
import { ProblemNotice } from '@/components/layout/ProblemNotice'
import { Mono } from '@/components/signals/Mono'
import { RelativeTime } from '@/components/signals/RelativeTime'
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import { Skeleton } from '@/components/ui/skeleton'
import { copy, countsLine, fixGroupHeader } from '@/lib/copy'
import { advisoryPath, explorerHref } from '@/lib/links'
import { type ExplorerSearch, parsePackageKey } from '@/lib/query'

export type FixGroupKind = 'fix' | 'advisory' | 'package'

// GROUP_PREVIEW findings are listed under an open group; the rest are a link to the explorer.
export const GROUP_PREVIEW = 10

type Row = S<'FindingGroupRow'>

// groupFilter is the explorer filter that selects one group's findings.
export function groupFilter(group: FixGroupKind, row: Row): ExplorerSearch {
  if (group === 'fix') return { fixKey: row.key }
  if (group === 'advisory') return { advisory: row.key }
  return { package: parsePackageKey(row.key).name }
}

function header(group: FixGroupKind, row: Row): string {
  if (group === 'fix') return fixGroupHeader(row)
  if (group === 'advisory') return `${row.key} · ${countsLine(row.findings, row.distinct, 'workloads')}`
  return `${row.label} · ${countsLine(row.findings, row.distinct, 'advisories')}`
}

function GroupFindings({ row, group, base }: { row: Row; group: FixGroupKind; base: ExplorerSearch }) {
  const filter = { ...base, ...groupFilter(group, row) }
  const q = useQuery(findingsQuery(filter, { limit: GROUP_PREVIEW }))
  const inWorkload = base.scope?.startsWith('workload:') ?? false
  const columns: Column<S<'FindingRow'>>[] = [
    ...(base.advisory
      ? []
      : [
          {
            id: 'advisory',
            header: copy.fixList.cols.advisory,
            cell: (r: S<'FindingRow'>) => (
              <AppLink href={advisoryPath(r.advisory.id)} className="hover:underline">
                <Mono>{r.advisory.id}</Mono>
              </AppLink>
            ),
          },
        ]),
    ...(inWorkload
      ? []
      : [
          {
            id: 'workload',
            header: copy.fixList.cols.workload,
            cell: (r: S<'FindingRow'>) => <OwnerCell owner={r.workload} nodeGroups={r.nodeGroups} namespace={false} />,
          },
        ]),
    { id: 'priority', header: copy.fixList.cols.priority, cell: (r) => <PriorityCell finding={r} /> },
    { id: 'package', header: copy.fixList.cols.package, cell: (r) => r.packages[0]?.name ?? copy.noValue },
    { id: 'installed', header: copy.fixList.cols.installed, cell: (r) => <Mono>{r.packages[0]?.installed ?? ''}</Mono> },
    {
      id: 'why',
      header: copy.fixList.cols.why,
      cell: (r) => (
        <span className="text-muted-foreground" title={r.reasons.join(' · ')}>
          {r.reasons.join(' · ')}
        </span>
      ),
    },
    { id: 'seen', header: copy.fixList.cols.seen, cell: (r) => <RelativeTime iso={r.observed} /> },
  ]
  return (
    <div className="pt-1 pb-2">
      {q.data ? (
        <ExplorerTable columns={columns} rows={q.data.rows} rowKey={(r) => r.id} />
      ) : q.error ? (
        <ProblemNotice error={q.error} />
      ) : (
        <Skeleton className="h-16" />
      )}
      {row.findings > GROUP_PREVIEW ? (
        <AppLink
          href={explorerHref('findings', filter)}
          className="mt-1 inline-block text-[11px] text-muted-foreground hover:text-foreground hover:underline max-lg:inline-flex max-lg:min-h-10 max-lg:items-center"
        >
          {copy.fixList.more(row.findings - GROUP_PREVIEW)}
        </AppLink>
      ) : null}
    </div>
  )
}

function FixGroup({ row, group, base, initiallyOpen }: { row: Row; group: FixGroupKind; base: ExplorerSearch; initiallyOpen: boolean }) {
  const [open, setOpen] = useState(initiallyOpen)
  const Chevron = open ? ChevronDown : ChevronRight
  return (
    <Collapsible open={open} onOpenChange={setOpen}>
      <CollapsibleTrigger asChild>
        <button
          type="button"
          className="flex w-full items-center gap-2 rounded-md bg-muted/50 px-2 py-1.5 text-left text-[12px] font-semibold hover:bg-muted max-lg:min-h-10"
        >
          <Chevron aria-hidden="true" className="size-3.5 shrink-0 text-muted-foreground" />
          <span className="min-w-0 truncate">{header(group, row)}</span>
        </button>
      </CollapsibleTrigger>
      <CollapsibleContent>{open ? <GroupFindings row={row} group={group} base={base} /> : null}</CollapsibleContent>
    </Collapsible>
  )
}

// FixGroupList lists findings grouped by what clears them (or by advisory or package), worst
// first as the server sends them. An open group lists its first findings, marked as the explorer
// marks them.
export function FixGroupList({ rows, group, base, open = 1 }: { rows: Row[]; group: FixGroupKind; base: ExplorerSearch; open?: number }) {
  return (
    <div className="flex flex-col gap-1.5">
      {rows.map((row, i) => (
        <FixGroup key={`${group}:${row.key}`} row={row} group={group} base={base} initiallyOpen={i < open} />
      ))}
    </div>
  )
}
