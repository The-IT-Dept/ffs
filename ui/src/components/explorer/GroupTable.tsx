import type { S } from '@/api/types'
import { AppLink } from '@/components/layout/AppLink'
import { FixLabel } from '@/components/signals/FixLabel'
import { Mono } from '@/components/signals/Mono'
import { PriorityCount } from '@/components/signals/PriorityCount'
import { PriorityDot } from '@/components/signals/PriorityDot'
import { copy, countsLine } from '@/lib/copy'
import { formatCount } from '@/lib/format'
import { advisoryPath, explorerHref, isClusterLevel, namespacePath, ownerHref, ownerLabel, ownerOfKey } from '@/lib/links'
import { type ExplorerSearch, parsePackageKey } from '@/lib/query'
import { type Column, ExplorerTable } from './ExplorerTable'

type Row = S<'FindingGroupRow'>

function narrowed(search: ExplorerSearch, extra: ExplorerSearch): string {
  return explorerHref('findings', { ...search, ...extra, group: undefined, cursor: undefined })
}

function groupCell(group: string, row: Row, search: ExplorerSearch) {
  switch (group) {
    case 'advisory':
      return (
        <span className="inline-flex min-w-0 items-center gap-2">
          <AppLink href={advisoryPath(row.key)} className="hover:underline">
            <Mono>{row.key}</Mono>
          </AppLink>
          {row.label && row.label !== row.key ? <span className="truncate text-muted-foreground">{row.label}</span> : null}
        </span>
      )
    case 'workload': {
      // The key is the owner key, "Kind/Namespace/Name"; cluster-level owners open their own pages.
      const owner = ownerOfKey(row.key)
      if (!owner.kind || !owner.name) return <span>{row.label}</span>
      return (
        <AppLink href={ownerHref(owner)} className="hover:underline">
          {isClusterLevel(owner) ? ownerLabel(owner) : row.label}
        </AppLink>
      )
    }
    case 'image':
      return (
        <AppLink href={narrowed(search, { repo: row.key })} className="hover:underline">
          <Mono>{row.label}</Mono>
        </AppLink>
      )
    case 'package': {
      const p = parsePackageKey(row.key)
      return (
        <AppLink href={narrowed(search, { package: p.name, ...(p.ecosystem ? { ecosystem: [p.ecosystem] } : {}) })} className="hover:underline">
          <Mono>{row.label}</Mono>
        </AppLink>
      )
    }
    case 'namespace':
      return row.key === '' ? (
        <span className="text-muted-foreground">{copy.clusterLevel}</span>
      ) : (
        <AppLink href={namespacePath(row.key)} className="hover:underline">
          {row.label}
        </AppLink>
      )
    case 'fix':
      return (
        <AppLink href={narrowed(search, { fixKey: row.key })} className="hover:underline">
          <FixLabel fix={row.fix} />
        </AppLink>
      )
  }
  return <span>{row.label}</span>
}

function Muted({ n }: { n: number }) {
  return <span className={n === 0 ? 'text-muted-foreground' : undefined}>{formatCount(n)}</span>
}

// GroupTable lists the groups of a grouped findings query, each with its findings and distinct
// counts. Its links narrow the explorer to the group, or open the group's own page.
export function GroupTable({ group, rows, search }: { group: string; rows: Row[]; search: ExplorerSearch }) {
  const columns: Column<Row>[] = [
    { id: 'group', header: copy.explorer.group[group] ?? group, cell: (r) => groupCell(group, r, search) },
    { id: 'findings', header: copy.col.findings, cell: (r) => countsLine(r.findings, r.distinct, group === 'advisory' ? 'workloads' : 'advisories') },
    { id: 'urgent', header: copy.col.urgent, align: 'right', cell: (r) => <PriorityCount priority="urgent" n={r.counts.urgent} /> },
    { id: 'high', header: copy.col.high, align: 'right', cell: (r) => <PriorityCount priority="high" n={r.counts.high} /> },
    { id: 'fixable', header: copy.col.fixable, align: 'right', cell: (r) => <Muted n={r.fixable} /> },
    { id: 'exploited', header: copy.col.exploited, align: 'right', cell: (r) => <Muted n={r.exploited} /> },
    { id: 'worst', header: copy.col.worst, cell: (r) => <PriorityDot priority={r.worst} /> },
  ]
  return <ExplorerTable columns={columns} rows={rows} rowKey={(r) => r.key} />
}
