import { createRoute } from '@tanstack/react-router'
import type { S } from '@/api/types'
import { ExplorerPage } from '@/components/explorer/ExplorerPage'
import type { Column } from '@/components/explorer/ExplorerTable'
import { AppLink } from '@/components/layout/AppLink'
import { Mono } from '@/components/signals/Mono'
import { PriorityCount } from '@/components/signals/PriorityCount'
import { PriorityDot } from '@/components/signals/PriorityDot'
import { copy } from '@/lib/copy'
import { formatCount } from '@/lib/format'
import { explorerHref } from '@/lib/links'
import { explorerSearchFor } from '@/lib/query'
import { rootRoute } from './root'

type Row = S<'PackageRow'>

function Count({ n }: { n: number }) {
  return <span className={n === 0 ? 'text-muted-foreground' : undefined}>{formatCount(n)}</span>
}

const columns: Column<Row>[] = [
  {
    id: 'package',
    header: copy.col.package,
    sort: 'name',
    cell: (r) => (
      <span className="inline-flex items-center gap-1.5">
        <AppLink href={explorerHref('findings', { package: r.name })} className="hover:underline">
          {r.name}
        </AppLink>
        {r.classifier ? <span className="rounded border px-1 text-[10px] leading-4 text-muted-foreground">{r.classifier}</span> : null}
      </span>
    ),
  },
  { id: 'ecosystem', header: copy.col.ecosystem, cell: (r) => r.ecosystem },
  { id: 'version', header: copy.col.version, cell: (r) => <Mono>{r.version}</Mono> },
  { id: 'images', header: copy.col.images, sort: '-images', align: 'right', cell: (r) => <Count n={r.images} /> },
  { id: 'workloads', header: copy.col.workloads, align: 'right', cell: (r) => <Count n={r.workloads} /> },
  { id: 'urgent', header: copy.col.urgent, sort: '-risk', align: 'right', cell: (r) => <PriorityCount priority="urgent" n={r.counts.urgent} /> },
  { id: 'high', header: copy.col.high, align: 'right', cell: (r) => <PriorityCount priority="high" n={r.counts.high} /> },
  { id: 'worst', header: copy.col.worst, cell: (r) => <PriorityDot priority={r.worst} /> },
]

function PackagesPage() {
  const search = packagesRoute.useSearch()
  const navigate = packagesRoute.useNavigate()
  return (
    <ExplorerPage
      kind="packages"
      title={copy.page.packages}
      search={search}
      onSearch={(next, o) => void navigate({ to: '.', search: next, replace: o?.replace })}
      columns={columns}
      rowKey={(r) => `${r.ecosystem}/${r.name}@${r.version}`}
    />
  )
}

export const packagesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/packages',
  validateSearch: explorerSearchFor('packages'),
  component: PackagesPage,
})
