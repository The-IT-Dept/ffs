import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { createRoute } from '@tanstack/react-router'
import { useState } from 'react'
import { apiQuery } from '@/api/client'
import type { S } from '@/api/types'
import { type Column, ExplorerTable } from '@/components/explorer/ExplorerTable'
import { GroupSwitch } from '@/components/explorer/GroupSwitch'
import { PAGE_LIMIT, findingsQuery } from '@/components/explorer/params'
import { Pager, useCursorPages } from '@/components/explorer/Pager'
import { ExposurePathLine } from '@/components/fix/ExposurePathLine'
import { type FixGroupKind, FixGroupList } from '@/components/fix/FixGroupList'
import { UpgradeTable } from '@/components/fix/UpgradeTable'
import { AppLink } from '@/components/layout/AppLink'
import { EmptyState } from '@/components/layout/EmptyState'
import { PageHeader } from '@/components/layout/PageHeader'
import { ProblemNotice } from '@/components/layout/ProblemNotice'
import { CoverageMark } from '@/components/signals/CoverageMark'
import { Mono } from '@/components/signals/Mono'
import { RelativeTime } from '@/components/signals/RelativeTime'
import { priorityTone } from '@/components/signals/tone'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { copy, facetValueLabel } from '@/lib/copy'
import { shortDigest } from '@/lib/format'
import { advisoryPath, imagePath, namespacePath, scopePath } from '@/lib/links'
import { parseWorkloadSearch, revalidate, type WorkloadSearch } from '@/lib/query'
import { formatScope, workloadScope } from '@/lib/scope'
import { cn } from '@/lib/utils'
import { rootRoute } from './root'

type Detail = S<'WorkloadDetail'>
type View = NonNullable<WorkloadSearch['view']>

const VIEWS: readonly View[] = ['findings', 'upgrades', 'exposure', 'rbac', 'history']
const GROUPS: readonly FixGroupKind[] = ['fix', 'advisory', 'package']

// coverageClassOf names a coverage figure's class as the explorers do: nothing seen into, all in
// full detail, or partial.
function coverageClassOf(c: S<'CoverageFigure'>): S<'CoverageClass'> {
  if (c.seenInto === 0) return 'none'
  return c.full === c.inUse ? 'full' : 'partial'
}

function head(label: string, right?: boolean) {
  return (
    <TableHead key={label} className={cn('h-[30px] py-0 text-[11px] font-medium text-muted-foreground', right && 'text-right')}>
      {label}
    </TableHead>
  )
}

function Chips({ d }: { d: Detail }) {
  const cls = coverageClassOf(d.coverage)
  const coverage = copy.workload.coverage(facetValueLabel('coverage', cls, 0))
  return (
    <div className="mb-1 flex flex-wrap items-center gap-1.5">
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
      <Badge variant="outline">{d.exposed ? copy.workload.exposed : copy.workload.notExposed}</Badge>
      <Badge variant="outline">{d.privileged ? copy.workload.privileged : copy.workload.notPrivileged}</Badge>
      {cls === 'full' ? (
        <Badge variant="outline">{coverage}</Badge>
      ) : (
        <CoverageMark>
          <span className="text-xs">{coverage}</span>
        </CoverageMark>
      )}
      {d.coverageNotes.length > 0 ? <span className="text-[11px] text-muted-foreground">{d.coverageNotes.join(' · ')}</span> : null}
    </div>
  )
}

function Containers({ d, scope }: { d: Detail; scope: string }) {
  if (d.containers.length === 0) return null
  const c = copy.workload.containers
  return (
    <Table className="mb-3 text-[12px]">
      <TableHeader>
        <TableRow className="h-[30px] hover:bg-transparent">{[head(c.container), head(c.image), head(c.status), head(c.coverage)]}</TableRow>
      </TableHeader>
      <TableBody>
        {d.containers.map((ct) => (
          <TableRow key={`${ct.kind}:${ct.name}`} className="h-[30px]">
            <TableCell className="py-0">
              {ct.name} <span className="text-muted-foreground">{ct.kind}</span>
            </TableCell>
            <TableCell className="max-w-[28rem] truncate py-0">
              {ct.digest ? (
                <AppLink href={imagePath(ct.digest, scope)} className="inline-flex items-center gap-2 hover:underline">
                  <Mono>{ct.repo || ct.image}</Mono>
                  <Mono className="text-muted-foreground">{shortDigest(ct.digest)}</Mono>
                </AppLink>
              ) : (
                <Mono>{ct.image}</Mono>
              )}
            </TableCell>
            <TableCell className="py-0">
              {ct.status === undefined ? (
                <span className="text-muted-foreground">{copy.noValue}</span>
              ) : ct.status === 'catalogued' ? (
                facetValueLabel('status', ct.status, 0)
              ) : (
                <CoverageMark>{facetValueLabel('status', ct.status, 0)}</CoverageMark>
              )}
            </TableCell>
            <TableCell className="py-0">
              {ct.coverage === undefined ? (
                <span className="text-muted-foreground">{copy.noValue}</span>
              ) : ct.coverage === 'full' ? (
                facetValueLabel('coverage', ct.coverage, 0)
              ) : (
                <CoverageMark>{facetValueLabel('coverage', ct.coverage, 0)}</CoverageMark>
              )}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}

function FindingsView({ scope, group, coverage, onGroup }: { scope: string; group: FixGroupKind; coverage?: S<'CoverageFigure'>; onGroup: (g: FixGroupKind) => void }) {
  // The request always groups (by fix unless the URL says otherwise); the URL leaves the default out.
  // No placeholder data: rows of another grouping would open groups with the wrong filter.
  const q = useQuery(findingsQuery({ scope, group }))
  return (
    <div className="flex flex-col gap-2">
      <GroupSwitch
        label={copy.explorer.groupBy}
        value={group}
        options={GROUPS.map((g) => ({ value: g, label: copy.explorer.group[g] ?? g }))}
        onChange={(v) => onGroup(v as FixGroupKind)}
      />
      {q.data ? (
        q.data.groupRows.length === 0 ? (
          <EmptyState coverage={coverage} />
        ) : (
          <FixGroupList key={`${scope}:${group}`} rows={q.data.groupRows} group={group} base={{ scope }} />
        )
      ) : q.error ? (
        <ProblemNotice error={q.error} />
      ) : (
        <Skeleton className="h-24" />
      )}
    </div>
  )
}

function ExposureView({ edges }: { edges: S<'ExposureEdge'>[] }) {
  if (edges.length === 0) return <EmptyState message={copy.path.notExposed} />
  const c = copy.workload.exposureCols
  return (
    <Table className="text-[12px]">
      <TableHeader>
        <TableRow className="h-[30px] hover:bg-transparent">
          {[head(c.entry), head(c.name), head(c.listener), head(c.hostname), head(c.route), head(c.service), head(c.internal)]}
        </TableRow>
      </TableHeader>
      <TableBody>
        {edges.map((e, i) => (
          <TableRow key={i} className="h-[30px]">
            <TableCell className="py-0">{e.entry}</TableCell>
            <TableCell className="py-0">{e.entryName}</TableCell>
            <TableCell className="py-0">{e.listener}</TableCell>
            <TableCell className="py-0">{e.hostname || '*'}</TableCell>
            <TableCell className="py-0">{e.route}</TableCell>
            <TableCell className="py-0">{e.service}</TableCell>
            <TableCell className="py-0 text-muted-foreground">{e.internal ? 'internal' : ''}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}

function RbacView({ d }: { d: Detail }) {
  const w = copy.workload
  const yesNo = (b: boolean) => (b ? w.yes : w.no)
  const reasons = (list: string[]) =>
    list.length ? (
      <ul className="list-disc pl-4 text-muted-foreground">
        {list.map((r) => (
          <li key={r}>{r}</li>
        ))}
      </ul>
    ) : null
  return (
    <dl className="grid max-w-2xl grid-cols-[10rem_1fr] gap-x-4 gap-y-2 text-[12px]">
      <dt className="text-muted-foreground">{w.serviceAccount}</dt>
      <dd>
        <Mono>{d.serviceAccount}</Mono>
      </dd>
      <dt className="text-muted-foreground">{w.saPower}</dt>
      <dd>
        {yesNo(d.saPower)}
        {reasons(d.saReasons)}
      </dd>
      <dt className="text-muted-foreground">{w.privilegedTitle}</dt>
      <dd>
        {yesNo(d.privileged)}
        {reasons(d.privilegeReasons)}
      </dd>
    </dl>
  )
}

const h = copy.workload.history
const historyColumns: Column<S<'TransitionRow'>>[] = [
  { id: 'when', header: h.when, cell: (r) => <RelativeTime iso={r.at} /> },
  {
    id: 'advisory',
    header: h.advisory,
    cell: (r) => (
      <AppLink href={advisoryPath(r.advisory)} className="hover:underline">
        <Mono>{r.advisory}</Mono>
      </AppLink>
    ),
  },
  { id: 'change', header: h.change, cell: (r) => `${r.fromState} → ${r.toState}` },
  {
    id: 'priority',
    header: h.priority,
    cell: (r) => (
      <span>
        <span className="text-muted-foreground">{r.fromPriority} → </span>
        <span className={priorityTone[r.toPriority].text}>{r.toPriority}</span>
      </span>
    ),
  },
  {
    id: 'trigger',
    header: h.trigger,
    cell: (r) => (
      <span className="inline-flex items-center gap-1.5">
        {r.trigger}
        {r.provisional ? <span className="rounded border px-1 text-[10px] leading-4 text-muted-foreground">{copy.explorer.tag.provisional}</span> : null}
      </span>
    ),
  },
]

function HistoryView({ scope }: { scope: string }) {
  const [cursor, setCursor] = useState<string | undefined>()
  const pages = useCursorPages(scope, cursor)
  const q = useQuery({ ...apiQuery('/transitions', { query: { scope, ...(cursor ? { cursor } : {}) } }), placeholderData: keepPreviousData })
  if (q.error && !q.data) return <ProblemNotice error={q.error} />
  if (!q.data) return <Skeleton className="h-24" />
  if (q.data.rows.length === 0) return <EmptyState />
  const next = q.data.next
  return (
    <>
      <ExplorerTable columns={historyColumns} rows={q.data.rows} rowKey={(r) => String(r.id)} busy={q.isPlaceholderData} />
      <Pager
        info={pages}
        total={undefined}
        limit={PAGE_LIMIT}
        hasNext={next !== null}
        onNext={() => {
          if (!next) return
          pages.recordNext(next)
          setCursor(next)
        }}
        onPrev={() => setCursor(pages.prev?.cursor)}
        onFirst={() => setCursor(undefined)}
      />
    </>
  )
}

function WorkloadPage() {
  const { kind, namespace, name } = workloadRoute.useParams()
  const search = revalidate(parseWorkloadSearch, workloadRoute.useSearch())
  const navigate = workloadRoute.useNavigate()
  const scopeObj = workloadScope(kind, namespace, name)
  const scope = formatScope(scopeObj)
  const detail = useQuery(apiQuery('/workloads/{kind}/{namespace}/{name}', { path: { kind, namespace, name } }))
  const d = detail.data
  const view = search.view ?? 'findings'
  const group = search.group ?? 'fix'
  const ns = namespace === '-' ? '' : namespace
  const first = d?.containers[0]

  const crumbs = [
    { label: d?.cluster ?? '', href: '/' },
    ...(ns ? [{ label: ns, href: namespacePath(ns) }] : []),
    { label: kind },
  ].filter((c) => c.label !== '')

  const sub =
    d && (d.managedBy || first) ? (
      <>
        {d.managedBy ? <span>{copy.workload.managedBy(copy.managedBy(d.managedBy))}</span> : null}
        {d.managedBy && first ? ' · ' : null}
        {first ? <Mono>{first.image}</Mono> : null}
      </>
    ) : undefined

  return (
    <div>
      <PageHeader crumbs={crumbs} kind={kind} title={name} sub={sub} />
      {d ? (
        <>
          <Chips d={d} />
          <ExposurePathLine edges={d.exposure} pods={d.pods} moreHref={scopePath(scopeObj) + '?view=exposure'} />
          <Containers d={d} scope={scope} />
          <Tabs value={view} onValueChange={(v) => void navigate({ to: '.', search: { ...search, view: v === 'findings' ? undefined : (v as View) } })}>
            <TabsList variant="line">
              {VIEWS.map((v) => (
                <TabsTrigger key={v} value={v} className="text-[12px]">
                  {copy.view(v, 'workload')}
                </TabsTrigger>
              ))}
            </TabsList>
            <TabsContent value="findings">
              <FindingsView
                scope={scope}
                group={group}
                coverage={d.coverage}
                onGroup={(g) => void navigate({ to: '.', search: { ...search, group: g === 'fix' ? undefined : g } })}
              />
            </TabsContent>
            <TabsContent value="upgrades">
              <UpgradeTable suggestions={d.upgrades} />
            </TabsContent>
            <TabsContent value="exposure">
              <ExposureView edges={d.exposure} />
            </TabsContent>
            <TabsContent value="rbac">
              <RbacView d={d} />
            </TabsContent>
            <TabsContent value="history">
              <HistoryView key={scope} scope={scope} />
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

export const workloadRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/workloads/$kind/$namespace/$name',
  validateSearch: parseWorkloadSearch,
  component: WorkloadPage,
})
