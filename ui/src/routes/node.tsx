import { useQuery } from '@tanstack/react-query'
import { createLazyRoute } from '@tanstack/react-router'
import type { ReactNode } from 'react'
import { apiQuery } from '@/api/client'
import { AppLink } from '@/components/layout/AppLink'
import { PageHeader } from '@/components/layout/PageHeader'
import { ProblemNotice } from '@/components/layout/ProblemNotice'
import { AgentGate, hasAgentData } from '@/components/nodes/AgentGate'
import { AgentStatusView } from '@/components/nodes/AgentStatusView'
import { NodeImagesTable } from '@/components/nodes/NodeImagesTable'
import { Mono } from '@/components/signals/Mono'
import { PriorityCountsText } from '@/components/signals/PriorityCountsText'
import { Skeleton } from '@/components/ui/skeleton'
import { copy } from '@/lib/copy'
import { eolText } from '@/lib/format'
import { nodeGroupPath } from '@/lib/links'
import { cn, touchLink } from '@/lib/utils'

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="mt-5">
      <h2 className="mb-1.5 text-[10px] font-medium tracking-wider text-muted-foreground uppercase">{title}</h2>
      {children}
    </section>
  )
}

function NodePage() {
  const { name } = Route.useParams()
  const q = useQuery(apiQuery('/nodes/{name}', { path: { name } }))
  const d = q.data
  const n = d?.node
  const osEol = eolText(n?.osEol)
  const sub = n ? (
    <span className="inline-flex flex-wrap items-center gap-x-1.5">
      {[
        n.osImage ? <span key="os">{n.osImage}</span> : null,
        n.kernelVersion ? <Mono key="kernel">{n.kernelVersion}</Mono> : null,
        n.containerRuntimeVersion ? <span key="runtime">{n.containerRuntimeVersion}</span> : null,
        n.kubeletVersion ? <span key="kubelet">{n.kubeletVersion}</span> : null,
        n.arch ? <span key="arch">{n.arch}</span> : null,
        <span key="ready">{n.ready ? copy.nodes.ready : copy.nodes.notReady}</span>,
        osEol ? <span key="eol">{osEol}</span> : null,
      ]
        .filter((x) => x !== null)
        .flatMap((x, i) => (i > 0 ? [<span key={`sep${i}`} aria-hidden="true">·</span>, x] : [x]))}
    </span>
  ) : undefined

  return (
    <div>
      <PageHeader kind={copy.page.node} title={n ? n.name : <Skeleton className="inline-block h-4 w-32 align-middle" />} sub={sub} />
      {d ? (
        <>
          <div className="flex flex-wrap items-center gap-2 text-[12px]">
            {d.group ? (
              <AppLink href={nodeGroupPath(d.group.id)} className={cn('hover:underline', touchLink)}>
                {d.group.label}
              </AppLink>
            ) : (
              <span className="text-muted-foreground">{copy.nodes.noGroup}</span>
            )}
            <span className="text-muted-foreground">·</span>
            <span>{d.exposed ? copy.workload.exposed : copy.workload.notExposed}</span>
            <span className="text-muted-foreground">·</span>
            <PriorityCountsText counts={d.counts} />
            <span className="text-muted-foreground">· {copy.workload.fixable(d.fixable)}</span>
          </div>
          <Section title={copy.nodes.memberCols.agent}>
            <AgentGate agentData={hasAgentData(d.agent)} agents={[d.agent]}>
              <AgentStatusView agent={d.agent} />
            </AgentGate>
          </Section>
          <Section title={copy.view('cachedImages', 'node')}>
            <AgentGate agentData={hasAgentData(d.agent)} agents={[d.agent]}>
              <NodeImagesTable images={d.cachedImages} />
            </AgentGate>
          </Section>
        </>
      ) : q.error ? (
        <ProblemNotice error={q.error} />
      ) : (
        <Skeleton className="h-40" />
      )}
    </div>
  )
}

// The page's code loads with its first visit; lazy.ts defines the route.
export const Route = createLazyRoute('/nodes/$name')({ component: NodePage })
