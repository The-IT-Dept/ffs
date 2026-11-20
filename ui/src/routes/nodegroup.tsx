import { useQuery } from '@tanstack/react-query'
import { createRoute } from '@tanstack/react-router'
import { type ReactNode, useEffect, useState } from 'react'
import { ApiProblem, apiQuery } from '@/api/client'
import type { S } from '@/api/types'
import { FixGroupFindings } from '@/components/fix/FixGroupFindings'
import { AppLink } from '@/components/layout/AppLink'
import { EmptyState } from '@/components/layout/EmptyState'
import { PageHeader } from '@/components/layout/PageHeader'
import { ProblemNotice } from '@/components/layout/ProblemNotice'
import { AgentGate } from '@/components/nodes/AgentGate'
import { NodeImagesTable } from '@/components/nodes/NodeImagesTable'
import { PackageTable } from '@/components/sbom/PackageTable'
import { Mono } from '@/components/signals/Mono'
import { RelativeTime } from '@/components/signals/RelativeTime'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { copy } from '@/lib/copy'
import { formatCount } from '@/lib/format'
import { nodeGroupPath, nodePath } from '@/lib/links'
import { type NodeGroupSearch, parseNodeGroupSearch, revalidate, stringifySearchParams } from '@/lib/query'
import { cn } from '@/lib/utils'
import { rootRoute } from './root'

type View = NonNullable<NodeGroupSearch['view']>
type Detail = S<'NodeGroupDetail'>

const VIEWS: readonly View[] = ['findings', 'hostPackages', 'kernel', 'cachedImages', 'members']

function Heads({ labels }: { labels: { label: string; right?: boolean }[] }) {
  return (
    <TableHeader>
      <TableRow className="h-[30px] hover:bg-transparent">
        {labels.map((h) => (
          <TableHead key={h.label} className={cn('h-[30px] py-0 text-[11px] font-medium text-muted-foreground', h.right && 'text-right')}>
            {h.label}
          </TableHead>
        ))}
      </TableRow>
    </TableHeader>
  )
}

function Subsection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="mt-4">
      <h2 className="mb-1.5 text-[10px] font-medium tracking-wider text-muted-foreground uppercase">{title}</h2>
      {children}
    </section>
  )
}

function HostPackagesView({ digest }: { digest: string }) {
  // The node group route keeps no q param, so the host package search is page state here.
  const [q, setQ] = useState<string | undefined>()
  return <PackageTable digest={digest} q={q} onQ={setQ} />
}

function KernelView({ d }: { d: Detail }) {
  const g = d.group
  const f = copy.nodes.groupCols
  const k = copy.nodes.kernelCols
  return (
    <div className="text-[12px]">
      <dl className="grid max-w-2xl grid-cols-[10rem_minmax(0,1fr)] wrap-anywhere max-sm:grid-cols-[7rem_minmax(0,1fr)] gap-x-4 gap-y-1.5">
        <dt className="text-muted-foreground">{f.kernel}</dt>
        <dd>
          <Mono wrap>{g.kernelRelease}</Mono>
        </dd>
        <dt className="text-muted-foreground">{f.runtime}</dt>
        <dd>
          <Mono wrap>{g.containerRuntimeVersion}</Mono>
        </dd>
        <dt className="text-muted-foreground">{f.kubelet}</dt>
        <dd>
          <Mono wrap>{g.kubeletVersion}</Mono>
        </dd>
        <dt className="text-muted-foreground">{f.osImage}</dt>
        <dd>{g.osImage}</dd>
        <dt className="text-muted-foreground">{copy.nodes.packageDb}</dt>
        <dd>{g.packageDb ? `${g.packageDb} · ${formatCount(g.packageCount)}` : <span className="text-muted-foreground">{copy.noValue}</span>}</dd>
      </dl>
      <div className="mt-4">
        <AgentGate agentData={d.agentData}>
          {g.kernel ? (
            <dl className="grid max-w-2xl grid-cols-[10rem_minmax(0,1fr)] wrap-anywhere max-sm:grid-cols-[7rem_minmax(0,1fr)] gap-x-4 gap-y-1.5">
              <dt className="text-muted-foreground">{copy.nodes.kernelFields.release}</dt>
              <dd>
                <Mono wrap>{g.kernel.release}</Mono>
              </dd>
              <dt className="text-muted-foreground">{copy.nodes.kernelFields.package}</dt>
              <dd>
                <Mono wrap>{g.kernel.package}</Mono>
              </dd>
              <dt className="text-muted-foreground">{copy.nodes.kernelFields.version}</dt>
              <dd>
                <Mono wrap>{g.kernel.version}</Mono>
              </dd>
              <dt className="text-muted-foreground">{copy.nodes.kernelFields.source}</dt>
              <dd>
                <Mono wrap>{g.kernel.sourceName}</Mono>
              </dd>
            </dl>
          ) : null}
          {g.binaries.length > 0 ? (
            <Table className="mt-3 text-[12px]">
              <Heads labels={[{ label: k.name }, { label: k.path }, { label: k.module }, { label: k.version }]} />
              <TableBody>
                {g.binaries.map((b) => (
                  <TableRow key={`${b.path}:${b.module}`} className="h-[30px]">
                    <TableCell className="py-0">{b.name}</TableCell>
                    <TableCell className="py-0">
                      <Mono>{b.path}</Mono>
                    </TableCell>
                    <TableCell className="py-0">
                      <Mono>{b.module}</Mono>
                    </TableCell>
                    <TableCell className="py-0">
                      <Mono>{b.version}</Mono>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : null}
        </AgentGate>
      </div>
    </div>
  )
}

function Count({ n }: { n: number }) {
  return <span className={n === 0 ? 'text-muted-foreground' : undefined}>{formatCount(n)}</span>
}

function PackageList({ title, packages }: { title: string; packages: S<'DriftPackage'>[] }) {
  if (packages.length === 0) return null
  return (
    <Subsection title={title}>
      <ul className="flex flex-col gap-0.5 text-[12px]">
        {packages.map((p) => (
          <li key={`${p.ecosystem}/${p.name}/${p.arch}`} className="flex gap-2">
            <span>{p.name}</span>
            <Mono>{p.version}</Mono>
            <span className="text-muted-foreground">{p.arch}</span>
          </li>
        ))}
      </ul>
    </Subsection>
  )
}

function CompareView({ compare }: { compare: S<'NodeDriftDetail'> }) {
  const fc = copy.nodes.fieldCols
  const cc = copy.nodes.changedCols
  return (
    <div>
      <Subsection title={copy.nodes.compareTitle}>
        <Table className="max-w-2xl text-[12px]">
          <Heads labels={[{ label: fc.field }, { label: fc.from }, { label: fc.to }]} />
          <TableBody>
            {compare.fields.map((f) => (
              <TableRow key={f.field} className="h-[30px]">
                <TableCell className="py-0">{f.field}</TableCell>
                <TableCell className="py-0">
                  <Mono>{f.from}</Mono>
                </TableCell>
                <TableCell className="py-0">
                  <Mono>{f.to}</Mono>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Subsection>
      {compare.packagesCompared ? (
        <>
          {compare.changed.length > 0 ? (
            <Subsection title={copy.nodes.changedTitle}>
              <Table className="text-[12px]">
                <Heads labels={[{ label: cc.package }, { label: cc.arch }, { label: cc.from }, { label: cc.to }, { label: cc.newer }]} />
                <TableBody>
                  {compare.changed.map((p) => (
                    <TableRow key={`${p.ecosystem}/${p.name}/${p.arch}`} className="h-[30px]">
                      <TableCell className="py-0">{p.name}</TableCell>
                      <TableCell className="py-0">{p.arch}</TableCell>
                      <TableCell className="py-0">
                        <Mono>{p.from}</Mono>
                      </TableCell>
                      <TableCell className="py-0">
                        <Mono>{p.to}</Mono>
                      </TableCell>
                      <TableCell className="py-0">{p.newer ? copy.nodes.newer[p.newer] : <span className="text-muted-foreground">{copy.noValue}</span>}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Subsection>
          ) : null}
          <PackageList title={copy.nodes.onlyThere} packages={compare.onlyFrom} />
          <PackageList title={copy.nodes.onlyHere} packages={compare.onlyTo} />
        </>
      ) : (
        <div className="mt-4">
          <EmptyState message={copy.agentMissing} />
        </div>
      )}
    </div>
  )
}

function MembersView({ d, id }: { d: Detail; id: string }) {
  const m = copy.nodes.memberCols
  const dc = copy.nodes.driftCols
  return (
    <div>
      <Table className="text-[12px]">
        <Heads labels={[{ label: m.node }, { label: m.ready }, { label: m.exposed }, ...(d.agentData ? [{ label: m.agent }] : [])]} />
        <TableBody>
          {d.members.map((n) => (
            <TableRow key={n.name} className="h-[30px]">
              <TableCell className="py-0">
                <AppLink href={nodePath(n.name)} className="hover:underline">
                  {n.name}
                </AppLink>
              </TableCell>
              <TableCell className="py-0">{n.ready ? copy.nodes.ready : copy.nodes.notReady}</TableCell>
              <TableCell className="py-0">{n.exposed ? copy.nodes.yes : copy.nodes.no}</TableCell>
              {d.agentData ? (
                <TableCell className="py-0">
                  {copy.agentState[n.agent.state]} <RelativeTime iso={n.agent.lastReport} />
                </TableCell>
              ) : null}
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {d.drift.length > 0 ? (
        <Subsection title={copy.nodes.driftTitle}>
          <Table className="text-[12px]">
            <Heads
              labels={[
                { label: dc.other },
                { label: dc.summary },
                { label: dc.newerHere, right: true },
                { label: dc.newerThere, right: true },
                { label: dc.onlyHere, right: true },
                { label: dc.onlyThere, right: true },
                { label: '' },
              ]}
            />
            <TableBody>
              {d.drift.map((r) => (
                <TableRow key={r.other.id} className="h-[30px]">
                  <TableCell className="py-0">
                    <AppLink href={nodeGroupPath(r.other.id)} className="hover:underline">
                      {r.other.label}
                    </AppLink>
                  </TableCell>
                  <TableCell className="py-0 text-muted-foreground">{r.summary}</TableCell>
                  <TableCell className="py-0 text-right tabular-nums">
                    <Count n={r.newerHere} />
                  </TableCell>
                  <TableCell className="py-0 text-right tabular-nums">
                    <Count n={r.newerThere} />
                  </TableCell>
                  <TableCell className="py-0 text-right tabular-nums">
                    <Count n={r.onlyHere} />
                  </TableCell>
                  <TableCell className="py-0 text-right tabular-nums">
                    <Count n={r.onlyThere} />
                  </TableCell>
                  <TableCell className="py-0">
                    <AppLink
                      href={nodeGroupPath(id) + stringifySearchParams({ view: 'members', compare: r.other.id })}
                      className="text-muted-foreground hover:text-foreground hover:underline"
                    >
                      {copy.nodes.compare(r.other.label)}
                    </AppLink>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Subsection>
      ) : null}
      {d.compare ? <CompareView compare={d.compare} /> : null}
    </div>
  )
}

function NodeGroupPage() {
  const { id } = nodeGroupRoute.useParams()
  const search = revalidate(parseNodeGroupSearch, nodeGroupRoute.useSearch())
  const navigate = nodeGroupRoute.useNavigate()
  const q = useQuery({
    ...apiQuery('/nodegroups/{id}', { path: { id }, query: search.compare ? { compare: search.compare } : {} }),
    // Keep the page while compare changes, but never show another group's data.
    placeholderData: (prev, prevQuery) => ((prevQuery?.queryKey[2] as { path?: { id?: string } } | undefined)?.path?.id === id ? prev : undefined),
  })
  const missing = q.error instanceof ApiProblem && q.error.code === 'not_found'
  useEffect(() => {
    // Groups re-key when their packages change; a stale link lands on the list instead.
    if (missing) void navigate({ to: '/nodes', replace: true })
  }, [missing, navigate])

  const d = q.data
  const g = d?.group
  const view = search.view ?? 'findings'
  // Without agent data the group's host packages were never inventoried, so no findings is not
  // proof that nothing needs attention.
  const findingsEmpty = d && !d.agentData ? <EmptyState message={copy.agentMissing} /> : undefined
  const sub = g ? (
    <span className="inline-flex flex-wrap items-center gap-x-1.5">
      {[
        g.osImage ? <span key="os">{g.osImage}</span> : null,
        g.kernelRelease ? <Mono key="kernel">{g.kernelRelease}</Mono> : null,
        g.containerRuntimeVersion ? <span key="runtime">{g.containerRuntimeVersion}</span> : null,
        g.kubeletVersion ? <span key="kubelet">{g.kubeletVersion}</span> : null,
        g.arch ? <span key="arch">{g.arch}</span> : null,
      ]
        .filter((x) => x !== null)
        .flatMap((x, i) => (i > 0 ? [<span key={`sep${i}`} aria-hidden="true">·</span>, x] : [x]))}
    </span>
  ) : undefined

  return (
    <div>
      <PageHeader kind={copy.page.nodegroup} title={g?.label ?? id} sub={sub} />
      {d ? (
        <Tabs value={view} onValueChange={(v) => void navigate({ to: '.', search: { ...search, view: v === 'findings' ? undefined : (v as View) } })}>
          <TabsList variant="line">
            {VIEWS.map((v) => (
              <TabsTrigger key={v} value={v} className="text-[12px]">
                {copy.view(v, 'nodegroup')}
              </TabsTrigger>
            ))}
          </TabsList>
          <TabsContent value="findings">
            <FixGroupFindings scope={`nodegroup:${id}`} empty={findingsEmpty} />
          </TabsContent>
          <TabsContent value="hostPackages">
            <AgentGate agentData={d.agentData}>
              <HostPackagesView key={id} digest={`nodegroup:${id}`} />
            </AgentGate>
          </TabsContent>
          <TabsContent value="kernel">
            <KernelView d={d} />
          </TabsContent>
          <TabsContent value="cachedImages">
            <AgentGate agentData={d.agentData}>
              <NodeImagesTable images={d.cachedImages} />
            </AgentGate>
          </TabsContent>
          <TabsContent value="members">
            <MembersView d={d} id={id} />
          </TabsContent>
        </Tabs>
      ) : q.error && !missing ? (
        <ProblemNotice error={q.error} />
      ) : (
        <Skeleton className="h-40" />
      )}
    </div>
  )
}

export const nodeGroupRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/nodegroups/$id',
  validateSearch: parseNodeGroupSearch,
  component: NodeGroupPage,
})
