import { createRoute } from '@tanstack/react-router'
import type { S } from '@/api/types'
import { ExplorerPage } from '@/components/explorer/ExplorerPage'
import type { Column } from '@/components/explorer/ExplorerTable'
import { AppLink } from '@/components/layout/AppLink'
import { CoverageMark } from '@/components/signals/CoverageMark'
import { Mono } from '@/components/signals/Mono'
import { PriorityCount } from '@/components/signals/PriorityCount'
import { copy, facetValueLabel } from '@/lib/copy'
import { formatCount, shortDigest } from '@/lib/format'
import { imagePath } from '@/lib/links'
import { explorerSearchFor } from '@/lib/query'
import { rootRoute } from './root'

type Row = S<'ImageRow'>

function Count({ n }: { n: number }) {
  return <span className={n === 0 ? 'text-muted-foreground' : undefined}>{formatCount(n)}</span>
}

const columns: Column<Row>[] = [
  {
    id: 'image',
    header: copy.col.image,
    sort: 'repo',
    cell: (r) => (
      <AppLink href={imagePath(r.digest)} className="inline-flex max-w-[min(26rem,var(--pin-cap,100%))] min-w-0 items-center gap-2 hover:underline">
        <Mono>{r.repo || shortDigest(r.digest)}</Mono>
        {r.repo ? <Mono className="text-muted-foreground">{shortDigest(r.digest)}</Mono> : null}
      </AppLink>
    ),
  },
  { id: 'platform', header: copy.col.platform, cell: (r) => r.platform || <span className="text-muted-foreground">{copy.noValue}</span> },
  {
    id: 'status',
    header: copy.col.status,
    cell: (r) =>
      r.status === 'catalogued' ? (
        facetValueLabel('status', r.status, 0)
      ) : (
        <CoverageMark title={r.statusReason || undefined}>{facetValueLabel('status', r.status, 0)}</CoverageMark>
      ),
  },
  { id: 'source', header: copy.col.source, cell: (r) => r.source || <span className="text-muted-foreground">{copy.noValue}</span> },
  {
    id: 'coverage',
    header: copy.col.coverage,
    cell: (r) =>
      r.coverage === 'full' ? (
        facetValueLabel('coverage', r.coverage, 0)
      ) : (
        <CoverageMark title={r.gaps.map((g) => copy.gaps[g].gap).join(' · ') || undefined}>{facetValueLabel('coverage', r.coverage, 0)}</CoverageMark>
      ),
  },
  { id: 'workloads', header: copy.col.workloads, sort: '-workloads', align: 'right', cell: (r) => <Count n={r.workloads} /> },
  { id: 'urgent', header: copy.col.urgent, sort: '-risk', align: 'right', cell: (r) => <PriorityCount priority="urgent" n={r.counts.urgent} /> },
  { id: 'high', header: copy.col.high, align: 'right', cell: (r) => <PriorityCount priority="high" n={r.counts.high} /> },
  { id: 'fixable', header: copy.col.fixable, align: 'right', cell: (r) => <Count n={r.fixable} /> },
]

function ImagesPage() {
  const search = imagesRoute.useSearch()
  const navigate = imagesRoute.useNavigate()
  return (
    <ExplorerPage
      kind="images"
      title={copy.page.images}
      search={search}
      onSearch={(next, o) => void navigate({ to: '.', search: next, replace: o?.replace })}
      columns={columns}
      rowKey={(r) => r.digest}
    />
  )
}

export const imagesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/images',
  validateSearch: explorerSearchFor('images'),
  component: ImagesPage,
})
