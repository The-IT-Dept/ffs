import { useQuery } from '@tanstack/react-query'
import { createRoute } from '@tanstack/react-router'
import { Fragment } from 'react'
import { apiQuery } from '@/api/client'
import type { S } from '@/api/types'
import { FixGroupFindings } from '@/components/fix/FixGroupFindings'
import { UpgradeTable } from '@/components/fix/UpgradeTable'
import { EmptyState, useScopeTrust } from '@/components/layout/EmptyState'
import { PageHeader } from '@/components/layout/PageHeader'
import { ProblemNotice } from '@/components/layout/ProblemNotice'
import { PackageTable } from '@/components/sbom/PackageTable'
import { hasImageGaps, ImageGaps, SbomCard } from '@/components/sbom/SbomCard'
import { CoverageMark } from '@/components/signals/CoverageMark'
import { Mono } from '@/components/signals/Mono'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { copy, facetValueLabel } from '@/lib/copy'
import { shortDigest } from '@/lib/format'
import { type ImageSearch, parseImageSearch, revalidate } from '@/lib/query'
import { formatScope } from '@/lib/scope'
import { rootRoute } from './root'

type View = NonNullable<ImageSearch['view']>
const VIEWS: readonly View[] = ['findings', 'packages', 'upgrades', 'sbom']

// imageCoverage is the image's own coverage figure, by the store's rule for an image scope: one
// image in use, seen into when catalogued, in full detail when its coverage class is full.
function imageCoverage(d: S<'ImageDetail'>): S<'CoverageFigure'> {
  return { inUse: 1, seenInto: d.status === 'catalogued' ? 1 : 0, full: d.coverage.class === 'full' ? 1 : 0 }
}

// PackagesEmpty is an image's empty package list. An image ffs has not catalogued, or catalogued
// with gaps, leads with why it may list nothing; only a fully seen image says its SBOM is empty.
function PackagesEmpty({ d }: { d: S<'ImageDetail'> }) {
  const status = d.status !== 'catalogued' ? <StatusLine d={d} /> : null
  if (!status && !hasImageGaps(d)) return <EmptyState message={copy.emptyList.packages} />
  return (
    <EmptyState
      lead={
        <>
          {status}
          <ImageGaps image={d} />
        </>
      }
    />
  )
}

// StatusLine says why an image is not catalogued, hatched.
function StatusLine({ d }: { d: S<'ImageDetail'> }) {
  return (
    <p>
      <CoverageMark title={d.statusReason || undefined}>
        {facetValueLabel('status', d.status, 0)}
        {d.statusReason ? `: ${d.statusReason}` : ''}
      </CoverageMark>
    </p>
  )
}

function ImagePage() {
  const { digest } = imageRoute.useParams()
  const search = revalidate(parseImageSearch, imageRoute.useSearch())
  const navigate = imageRoute.useNavigate()
  const scopeObj = { kind: 'image' as const, value: digest }
  const scope = formatScope(scopeObj)
  const detail = useQuery(apiQuery('/images/{digest}', { path: { digest } }))
  const trust = useScopeTrust(scopeObj)
  const d = detail.data
  const view = search.view ?? 'findings'

  const subParts = d
    ? [
        <Mono key="digest" wrap>
          {d.digest}
        </Mono>,
        ...(d.platform ? [<span key="platform">{d.platform}</span>] : []),
        ...d.tags.map((t) => (
          <Mono key={`tag:${t}`} wrap>
            {t}
          </Mono>
        )),
        ...(d.versionAnnotation ? [<span key="version">{d.versionAnnotation}</span>] : []),
      ]
    : []

  return (
    <div>
      <PageHeader
        kind={copy.scopeKind(scopeObj)}
        title={d?.repo || shortDigest(digest)}
        sub={
          subParts.length ? (
            <span className="inline-flex flex-wrap items-center gap-x-1">
              {subParts.map((p, i) => (
                <Fragment key={i}>
                  {i > 0 ? <span aria-hidden="true">·</span> : null}
                  {p}
                </Fragment>
              ))}
            </span>
          ) : undefined
        }
      />
      {d ? (
        <>
          {d.status !== 'catalogued' ? (
            <div className="mb-2 text-[12px]">
              <StatusLine d={d} />
            </div>
          ) : null}
          <div className="mb-2 flex flex-wrap items-center gap-1.5">
            {d.counts.urgent > 0 ? (
              <Badge variant="outline" className="border-red-200 bg-red-50 text-(--urgent) dark:border-red-900 dark:bg-red-950">
                {copy.workload.urgent(d.counts.urgent)}
              </Badge>
            ) : null}
            {d.counts.high > 0 ? (
              <Badge variant="outline" className="text-(--high)">
                {copy.workload.high(d.counts.high)}
              </Badge>
            ) : null}
            <Badge variant="outline">{copy.workload.fixable(d.fixable)}</Badge>
          </div>
          <Tabs value={view} onValueChange={(v) => void navigate({ to: '.', search: { ...search, view: v === 'findings' ? undefined : (v as View) } })}>
            <TabsList variant="line">
              {VIEWS.map((v) => (
                <TabsTrigger key={v} value={v} className="text-[12px]">
                  {copy.view(v, 'image')}
                </TabsTrigger>
              ))}
            </TabsList>
            <TabsContent value="findings">
              <FixGroupFindings scope={scope} empty={<EmptyState coverage={imageCoverage(d)} feeds={trust?.feeds} scope={scopeObj} />} />
            </TabsContent>
            <TabsContent value="packages">
              <PackageTable
                key={digest}
                digest={digest}
                q={search.q}
                onQ={(q) => void navigate({ to: '.', search: { ...search, q }, replace: true })}
                empty={<PackagesEmpty d={d} />}
              />
            </TabsContent>
            <TabsContent value="upgrades">
              <UpgradeTable suggestions={d.upgrades} />
            </TabsContent>
            <TabsContent value="sbom">
              <SbomCard image={d} />
            </TabsContent>
          </Tabs>
        </>
      ) : detail.error ? (
        <ProblemNotice error={detail.error} />
      ) : (
        <Skeleton className="h-40" />
      )}
    </div>
  )
}

export const imageRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/images/$digest',
  validateSearch: parseImageSearch,
  component: ImagePage,
})
