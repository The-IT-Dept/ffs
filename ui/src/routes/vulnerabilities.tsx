import { createRoute } from '@tanstack/react-router'
import type { S } from '@/api/types'
import { ExplorerPage } from '@/components/explorer/ExplorerPage'
import type { Column } from '@/components/explorer/ExplorerTable'
import { OwnerCell } from '@/components/explorer/OwnerCell'
import { PriorityCell } from '@/components/explorer/PriorityCell'
import { AppLink } from '@/components/layout/AppLink'
import { FixLabel } from '@/components/signals/FixLabel'
import { Mono } from '@/components/signals/Mono'
import { RelativeTime } from '@/components/signals/RelativeTime'
import { copy } from '@/lib/copy'
import { formatPercent } from '@/lib/format'
import { advisoryPath } from '@/lib/links'
import { explorerSearchFor } from '@/lib/query'
import { rootRoute } from './root'

type Row = S<'FindingRow'>

const columns: Column<Row>[] = [
  {
    id: 'advisory',
    header: copy.col.advisory,
    sort: 'advisory',
    cell: (r) => (
      // Held to its cell as well as to 22rem, so on a phone the title ends in an ellipsis.
      <span className="inline-flex max-w-[min(22rem,var(--pin-cap,100%))] min-w-0 items-center gap-2">
        <AppLink href={advisoryPath(r.advisory.id)} className="shrink-0 hover:underline">
          <Mono>{r.advisory.id}</Mono>
        </AppLink>
        {r.advisory.title ? (
          <span className="truncate text-muted-foreground" title={r.advisory.title}>
            {r.advisory.title}
          </span>
        ) : null}
        {r.advisory.kev ? <span className="rounded border px-1 text-[10px] leading-4 text-muted-foreground">{copy.explorer.tag.kev}</span> : null}
      </span>
    ),
  },
  { id: 'priority', header: copy.col.priority, sort: '-priority', cell: (r) => <PriorityCell finding={r} /> },
  { id: 'severity', header: copy.col.severity, sort: '-severity', cell: (r) => <span className="text-muted-foreground">{r.severity}</span> },
  {
    id: 'workload',
    header: copy.col.workload,
    sort: 'workload',
    cell: (r) => <OwnerCell owner={r.workload} nodeGroups={r.nodeGroups} />,
  },
  {
    id: 'package',
    header: copy.col.package,
    cell: (r) => {
      const p = r.packages[0]
      if (!p) return <span className="text-muted-foreground">{copy.noValue}</span>
      return (
        <span className="inline-flex items-center gap-1.5">
          <span>{p.name}</span>
          <Mono>{p.installed}</Mono>
          {r.packages.length > 1 ? <span className="text-muted-foreground">+{r.packages.length - 1}</span> : null}
        </span>
      )
    },
  },
  { id: 'fix', header: copy.col.fix, cell: (r) => <FixLabel fix={r.fix} /> },
  {
    id: 'epss',
    header: copy.col.epss,
    sort: '-epss',
    align: 'right',
    cell: (r) => (r.advisory.epss === null ? <span className="text-muted-foreground">{copy.noValue}</span> : formatPercent(r.advisory.epss)),
  },
  { id: 'published', header: copy.col.published, sort: '-published', cell: (r) => <RelativeTime iso={r.published} /> },
]

function VulnerabilitiesPage() {
  const search = vulnerabilitiesRoute.useSearch()
  const navigate = vulnerabilitiesRoute.useNavigate()
  return (
    <ExplorerPage
      kind="findings"
      title={copy.page.vulnerabilities}
      search={search}
      onSearch={(next, o) => void navigate({ to: '.', search: next, replace: o?.replace })}
      columns={columns}
      rowKey={(r) => r.id}
    />
  )
}

export const vulnerabilitiesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/vulnerabilities',
  validateSearch: explorerSearchFor('findings'),
  component: VulnerabilitiesPage,
})
