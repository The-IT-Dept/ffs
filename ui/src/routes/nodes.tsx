import { useQuery } from '@tanstack/react-query'
import { createRoute } from '@tanstack/react-router'
import type { ReactNode } from 'react'
import { apiQuery } from '@/api/client'
import type { S } from '@/api/types'
import { AppLink } from '@/components/layout/AppLink'
import { EmptyState } from '@/components/layout/EmptyState'
import { PageHeader } from '@/components/layout/PageHeader'
import { ProblemNotice } from '@/components/layout/ProblemNotice'
import { ControlPlaneBlock } from '@/components/nodes/ControlPlaneBlock'
import { CoverageMark } from '@/components/signals/CoverageMark'
import { Mono } from '@/components/signals/Mono'
import { PriorityCount } from '@/components/signals/PriorityCount'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { copy } from '@/lib/copy'
import { formatCount } from '@/lib/format'
import { nodeGroupLinkIds, nodeGroupPath } from '@/lib/links'
import { cn } from '@/lib/utils'
import { rootRoute } from './root'

type Group = S<'NodeGroupRow'>

function Count({ n }: { n: number }) {
  return <span className={n === 0 ? 'text-muted-foreground' : undefined}>{formatCount(n)}</span>
}

// gappedGroups is the set of node groups ffs cannot fully see into: groups with no host inventory
// (nodeinfo), groups with members whose agent is not reporting, and groups the cluster rail marks
// with a gap (an agent that cannot read the host, an image-based OS). The rail is asked anyway on
// this page, so its marks cost no request; it lists groups by ID or by stable name.
function gappedGroups(groups: Group[], rail?: S<'ScopeCard'>): Set<string> {
  const marked = new Set((rail?.related.find((r) => r.id === 'nodegroups')?.items ?? []).filter((i) => i.gap && i.scope).map((i) => i.scope))
  return new Set(
    groups
      .filter((g) => g.kind !== 'agent' || g.agents.reporting < g.members || marked.has(`nodegroup:${g.id}`) || (g.name !== '' && marked.has(`nodegroup:${g.name}`)))
      .map((g) => g.id),
  )
}

// Figure is a group's count: hatched where ffs cannot see all of the group, and "—" for a group
// whose host packages were never inventoried, where a zero would read as clean.
function Figure({ g, gap, children }: { g: Group; gap: boolean; children: ReactNode }) {
  if (g.kind !== 'agent') return <CoverageMark title={copy.gaps.node_agent_missing.gap}>{copy.noValue}</CoverageMark>
  return gap ? <CoverageMark title={copy.nodes.groupGap}>{children}</CoverageMark> : <>{children}</>
}

function GroupsTable({ list, rail }: { list: S<'NodeGroupsList'>; rail?: S<'ScopeCard'> }) {
  if (list.groups.length === 0) return <EmptyState message={copy.emptyList.nodeGroups} />
  const gapped = gappedGroups(list.groups, rail)
  const linkIds = nodeGroupLinkIds(list.groups)
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
              <AppLink href={nodeGroupPath(linkIds.get(g.id) ?? g.id)} className="hover:underline">
                {g.label}
                {g.name && g.name !== g.label ? <span className="ml-1.5 text-muted-foreground">{g.name}</span> : null}
              </AppLink>
            </TableCell>
            <TableCell className="py-0">{copy.nodes.kind[g.kind]}</TableCell>
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
              <Figure g={g} gap={gapped.has(g.id)}>
                <PriorityCount priority="urgent" n={g.counts.urgent} />
              </Figure>
            </TableCell>
            <TableCell className="py-0 text-right">
              <Figure g={g} gap={gapped.has(g.id)}>
                <PriorityCount priority="high" n={g.counts.high} />
              </Figure>
            </TableCell>
            <TableCell className="py-0 text-right tabular-nums">
              <Figure g={g} gap={gapped.has(g.id)}>
                <Count n={g.fixable} />
              </Figure>
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
  // The cluster rail, asked with the rail's own key.
  const rail = useQuery(apiQuery('/scope', { query: {} }))
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
          <GroupsTable list={q.data} rail={rail.data} />
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
