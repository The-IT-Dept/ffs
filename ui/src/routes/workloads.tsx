import { createRoute } from '@tanstack/react-router'
import type { S } from '@/api/types'
import { ExplorerPage } from '@/components/explorer/ExplorerPage'
import type { Column } from '@/components/explorer/ExplorerTable'
import { AppLink } from '@/components/layout/AppLink'
import { CoverageFigureText } from '@/components/signals/CoverageFigureText'
import { FixLabel } from '@/components/signals/FixLabel'
import { PriorityCount } from '@/components/signals/PriorityCount'
import { copy } from '@/lib/copy'
import { formatCount } from '@/lib/format'
import { ownerHref, ownerLabel } from '@/lib/links'
import { explorerSearchFor } from '@/lib/query'
import { rootRoute } from './root'

type Row = S<'WorkloadRow'>

function Count({ n }: { n: number | null }) {
  if (n === null) return <span className="text-muted-foreground">{copy.noValue}</span>
  return <span className={n === 0 ? 'text-muted-foreground' : undefined}>{formatCount(n)}</span>
}

function Tags({ r }: { r: Row }) {
  const tags = [
    r.exposed && copy.explorer.tag.exposed,
    r.privileged && copy.explorer.tag.privileged,
    r.saPower && copy.explorer.tag.saPower,
    r.notRunning && copy.explorer.tag.notRunning,
  ].filter((t): t is string => typeof t === 'string')
  return (
    <span className="inline-flex gap-1">
      {tags.map((t) => (
        <span key={t} className="rounded border px-1 text-[10px] leading-4 text-muted-foreground">
          {t}
        </span>
      ))}
    </span>
  )
}

const columns: Column<Row>[] = [
  {
    id: 'workload',
    header: copy.col.workload,
    sort: 'name',
    cell: (r) => (
      <span className="inline-flex items-center gap-1.5">
        <AppLink href={ownerHref(r.workload)} className="hover:underline">
          {ownerLabel(r.workload)}
        </AppLink>
        <span className="text-muted-foreground">{r.workload.kind}</span>
      </span>
    ),
  },
  { id: 'namespace', header: copy.col.namespace, sort: 'namespace', cell: (r) => r.workload.namespace },
  { id: 'urgent', header: copy.col.urgent, sort: '-risk', align: 'right', cell: (r) => <PriorityCount priority="urgent" n={r.counts.urgent} /> },
  { id: 'high', header: copy.col.high, align: 'right', cell: (r) => <PriorityCount priority="high" n={r.counts.high} /> },
  { id: 'findings', header: copy.col.findings, sort: '-findings', align: 'right', cell: (r) => <Count n={r.open} /> },
  { id: 'fixable', header: copy.col.fixable, align: 'right', cell: (r) => <Count n={r.fixable} /> },
  { id: 'exploited', header: copy.col.exploited, align: 'right', cell: (r) => <Count n={r.exploited} /> },
  { id: 'signals', header: copy.col.signals, cell: (r) => <Tags r={r} /> },
  { id: 'coverage', header: copy.col.coverage, align: 'right', cell: (r) => <CoverageFigureText figure={r.coverage} /> },
  { id: 'bestFix', header: copy.col.bestFix, cell: (r) => <FixLabel fix={r.bestFix} /> },
  { id: 'pods', header: copy.col.pods, align: 'right', cell: (r) => <Count n={r.pods} /> },
]

function WorkloadsPage() {
  const search = workloadsRoute.useSearch()
  const navigate = workloadsRoute.useNavigate()
  return (
    <ExplorerPage
      kind="workloads"
      title={copy.page.workloads}
      search={search}
      onSearch={(next, o) => void navigate({ to: '.', search: next, replace: o?.replace })}
      columns={columns}
      rowKey={(r) => r.workload.scope}
    />
  )
}

export const workloadsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/workloads',
  validateSearch: explorerSearchFor('workloads'),
  component: WorkloadsPage,
})
