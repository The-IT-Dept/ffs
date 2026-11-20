import { useQuery } from '@tanstack/react-query'
import { createRoute } from '@tanstack/react-router'
import { apiQuery } from '@/api/client'
import type { S } from '@/api/types'
import { AppLink } from '@/components/layout/AppLink'
import { EmptyState } from '@/components/layout/EmptyState'
import { PageHeader } from '@/components/layout/PageHeader'
import { ProblemNotice } from '@/components/layout/ProblemNotice'
import { ControlPlaneBlock } from '@/components/nodes/ControlPlaneBlock'
import { Mono } from '@/components/signals/Mono'
import { PriorityCount } from '@/components/signals/PriorityCount'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { copy } from '@/lib/copy'
import { formatCount } from '@/lib/format'
import { nodeGroupPath } from '@/lib/links'
import { cn } from '@/lib/utils'
import { rootRoute } from './root'

function Count({ n }: { n: number }) {
  return <span className={n === 0 ? 'text-muted-foreground' : undefined}>{formatCount(n)}</span>
}

function GroupsTable({ list }: { list: S<'NodeGroupsList'> }) {
  if (list.groups.length === 0) return <EmptyState />
  const c = copy.nodes.groupCols
  const heads: { label: string; right?: boolean }[] = [
    { label: c.group },
    { label: c.kind },
    { label: c.osImage },
    { label: c.kernel },
    { label: c.runtime },
    { label: c.kubelet },
    { label: c.arch },
    { label: c.nodes, right: true },
    { label: c.exposedNodes, right: true },
    { label: c.urgent, right: true },
    { label: c.high, right: true },
    { label: c.fixable, right: true },
    ...(list.agentEnabled ? [{ label: c.agents, right: true }, { label: c.reboot, right: true }] : []),
    { label: c.drift },
  ]
  return (
    <Table className="text-[12px]">
      <TableHeader>
        <TableRow className="h-[30px] hover:bg-transparent">
          {heads.map((h) => (
            <TableHead key={h.label} className={cn('h-[30px] py-0 text-[11px] font-medium text-muted-foreground', h.right && 'text-right')}>
              {h.label}
            </TableHead>
          ))}
        </TableRow>
      </TableHeader>
      <TableBody>
        {list.groups.map((g) => (
          <TableRow key={g.id} className="h-[30px]">
            <TableCell className="py-0">
              <AppLink href={nodeGroupPath(g.id)} className="hover:underline">
                {g.label}
                {g.name && g.name !== g.label ? <span className="ml-1.5 text-muted-foreground">{g.name}</span> : null}
              </AppLink>
            </TableCell>
            <TableCell className="py-0">{g.kind}</TableCell>
            <TableCell className="max-w-[14rem] truncate py-0">{g.osImage}</TableCell>
            <TableCell className="py-0">
              <Mono>{g.kernelRelease}</Mono>
            </TableCell>
            <TableCell className="py-0">
              <Mono>{g.containerRuntimeVersion}</Mono>
            </TableCell>
            <TableCell className="py-0">
              <Mono>{g.kubeletVersion}</Mono>
            </TableCell>
            <TableCell className="py-0">{g.arch}</TableCell>
            <TableCell className="py-0 text-right tabular-nums">{formatCount(g.members)}</TableCell>
            <TableCell className="py-0 text-right tabular-nums">
              <Count n={g.exposedNodes} />
            </TableCell>
            <TableCell className="py-0 text-right">
              <PriorityCount priority="urgent" n={g.counts.urgent} />
            </TableCell>
            <TableCell className="py-0 text-right">
              <PriorityCount priority="high" n={g.counts.high} />
            </TableCell>
            <TableCell className="py-0 text-right tabular-nums">
              <Count n={g.fixable} />
            </TableCell>
            {list.agentEnabled ? (
              <>
                <TableCell
                  className="py-0 text-right tabular-nums"
                  title={`${copy.agentState.stale}: ${g.agents.stale} · ${copy.agentState.never}: ${g.agents.never} · ${copy.agentState.disabled}: ${g.agents.disabled}`}
                >
                  {`${formatCount(g.agents.reporting)}/${formatCount(g.members)}`}
                </TableCell>
                <TableCell className="py-0 text-right tabular-nums">
                  <Count n={g.rebootPending} />
                </TableCell>
              </>
            ) : null}
            <TableCell className="py-0 text-muted-foreground">{g.drift}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}

function NodesPage() {
  const q = useQuery(apiQuery('/nodegroups', {}))
  return (
    <div>
      <PageHeader title={copy.page.nodes} />
      {q.data ? (
        <>
          {!q.data.agentEnabled ? (
            <div className="mb-4">
              <EmptyState message={copy.agentMissing} />
            </div>
          ) : null}
          <ControlPlaneBlock controlPlane={q.data.controlPlane} link />
          <GroupsTable list={q.data} />
        </>
      ) : q.error ? (
        <ProblemNotice error={q.error} />
      ) : (
        <Skeleton className="h-40" />
      )}
    </div>
  )
}

export const nodesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/nodes',
  component: NodesPage,
})
