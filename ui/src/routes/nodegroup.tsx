import { useQuery } from '@tanstack/react-query'
import { createLazyRoute } from '@tanstack/react-router'
import { type ReactNode, useEffect, useState } from 'react'
import { ApiProblem, apiQuery } from '@/api/client'
import type { S } from '@/api/types'
import { FixGroupFindings } from '@/components/fix/FixGroupFindings'
import { AppLink } from '@/components/layout/AppLink'
import { EmptyState } from '@/components/layout/EmptyState'
import { Field, FieldList } from '@/components/layout/FieldList'
import { goneState } from '@/components/layout/GoneNotice'
import { PageHeader } from '@/components/layout/PageHeader'
import { ProblemNotice } from '@/components/layout/ProblemNotice'
import { AgentGate, AgentMissing } from '@/components/nodes/AgentGate'
import { NodeGapLines, NodeGapNotice, nodeGapsOf } from '@/components/nodes/NodeGaps'
import { NodeImagesTable } from '@/components/nodes/NodeImagesTable'
import { useScopeTrust } from '@/components/rail/query'
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
import { formatScope } from '@/lib/scope'
import { cn } from '@/lib/utils'

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
  return <PackageTable digest={digest} q={q} onQ={setQ} empty={<EmptyState message={copy.emptyList.hostPackages} />} />
}

function KernelView({ d }: { d: Detail }) {
  const g = d.group
  const f = copy.nodes.groupCols
  const k = copy.nodes.kernelCols
  return (
    <div className="text-[12px]">
      <FieldList>
        <Field label={f.kernel}>
          <Mono wrap>{g.kernelRelease}</Mono>
        </Field>
        <Field label={f.runtime}>
          <Mono wrap>{g.containerRuntimeVersion}</Mono>
        </Field>
        <Field label={f.kubelet}>
          <Mono wrap>{g.kubeletVersion}</Mono>
        </Field>
        <Field label={f.osImage}>{g.osImage}</Field>
        <Field label={copy.nodes.packageDb}>
          {g.packageDb ? `${g.packageDb} · ${formatCount(g.packageCount)}` : <span className="text-muted-foreground">{copy.noValue}</span>}
        </Field>
      </FieldList>
      <div className="mt-4">
        <AgentGate agentData={d.agentData} agents={d.members.map((m) => m.agent)}>
          {g.kernel ? (
            <FieldList>
              <Field label={copy.nodes.kernelFields.release}>
                <Mono wrap>{g.kernel.release}</Mono>
              </Field>
              <Field label={copy.nodes.kernelFields.package}>
                <Mono wrap>{g.kernel.package}</Mono>
              </Field>
              <Field label={copy.nodes.kernelFields.version}>
                <Mono wrap>{g.kernel.version}</Mono>
              </Field>
              <Field label={copy.nodes.kernelFields.source}>
                <Mono wrap>{g.kernel.sourceName}</Mono>
              </Field>
            </FieldList>
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
          <EmptyState message={copy.nodes.notCompared} />
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
  // id is the group's key, as the API links groups (its stable name, qualified when other groups
  // share it), or any other form the API resolves (a label, an ID). It is used as it is, never
  // parsed.
  const { id } = Route.useParams()
  const search = revalidate(parseNodeGroupSearch, Route.useSearch())
  const navigate = Route.useNavigate()
  const q = useQuery({
    ...apiQuery('/nodegroups/{id}', { path: { id }, query: search.compare ? { compare: search.compare } : {} }),
    // Keep the page while compare changes, but never show another group's data.
    placeholderData: (prev, prevQuery) => ((prevQuery?.queryKey[2] as { path?: { id?: string } } | undefined)?.path?.id === id ? prev : undefined),
  })
  const { trust, pending } = useScopeTrust({ kind: 'nodegroup', value: id })
  const missing = q.error instanceof ApiProblem && q.error.code === 'not_found'
  useEffect(() => {
    // A group no longer listed under this key lands on the list instead, with a notice.
    if (missing) void navigate({ to: '/nodes', replace: true, state: goneState('nodegroup') })
  }, [missing, navigate])

  const d = q.data
  const g = d?.group
  const view = search.view ?? 'findings'
  // Queries scope by the key the detail resolved the URL's id to.
  const scope = g ? formatScope({ kind: 'nodegroup', value: g.id }) : ''
  const agents = d ? d.members.map((m) => m.agent) : []
  // What the agents cannot see on any member leads the page: under the header, and ahead of the
  // findings and host packages, because no findings is not proof that nothing needs attention.
  const gaps = d ? nodeGapsOf(agents, { inventoried: d.agentData }) : []
  const notice = <NodeGapNotice gaps={gaps} total={agents.length} />
  const findingsEmpty = d ? (
    d.agentData ? (
      <EmptyState
        coverage={trust?.coverage}
        feeds={trust?.feeds}
        pending={pending}
        lead={gaps.length > 0 ? <NodeGapLines gaps={gaps} total={agents.length} /> : undefined}
      />
    ) : (
      <AgentMissing agents={agents} />
    )
  ) : undefined
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
      <NodeGapLines gaps={gaps} total={agents.length} compact className="-mt-2 mb-3 text-[11.5px] text-muted-foreground" />
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
            <FixGroupFindings scope={scope} empty={findingsEmpty} notice={notice} />
          </TabsContent>
          <TabsContent value="hostPackages">
            <AgentGate agentData={d.agentData} agents={agents}>
              {notice}
              <HostPackagesView key={scope} digest={scope} />
            </AgentGate>
          </TabsContent>
          <TabsContent value="kernel">
            <KernelView d={d} />
          </TabsContent>
          <TabsContent value="cachedImages">
            <AgentGate agentData={d.agentData} agents={agents}>
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

// The page's code loads with its first visit; lazy.ts defines the route.
export const Route = createLazyRoute('/nodegroups/$id')({ component: NodeGroupPage })
