import type { GapCode, S } from '@/api/types'
import { CoverageMark } from '@/components/signals/CoverageMark'
import { copy } from '@/lib/copy'
import { cn } from '@/lib/utils'

// NodeGapSummary is one thing ffs cannot see on a set of nodes, and how many of them it affects.
export interface NodeGapSummary {
  key: GapCode | 'stale'
  label: string
  todo: string
  nodes: number
}

function gapLine(key: NodeGapSummary['key']): Omit<NodeGapSummary, 'nodes'> {
  if (key === 'stale') return { key, label: copy.nodes.agentStale, todo: copy.gaps.node_agent_missing.todo }
  return { key, label: copy.gaps[key].gap, todo: copy.gaps[key].todo }
}

// nodeGapsOf is the union of the coverage gaps of nodes' agents, in first-seen order, each with the
// number of nodes it affects. An agent that has never reported (or is disabled) counts as
// node_agent_missing, even when the API lists no gap code for it, and a stale one as stopped. When
// the nodes' host packages were not inventoried (inventoried false: a group without agent data), a
// reporting agent without a gap of its own counts as host_not_inventoried.
export function nodeGapsOf(agents: readonly S<'AgentStatus'>[], o: { inventoried: boolean }): NodeGapSummary[] {
  const out = new Map<NodeGapSummary['key'], NodeGapSummary>()
  for (const a of agents) {
    const keys = new Set<NodeGapSummary['key']>(a.gaps.map((g) => g.code))
    if (a.state === 'stale') {
      // Stopped is the more precise word for the missing inventory of a stale agent.
      keys.delete('node_agent_missing')
      keys.add('stale')
    } else if (a.state !== 'reporting' && !keys.has('node_agent_unsupported')) keys.add('node_agent_missing')
    else if (a.state === 'reporting' && keys.size === 0 && !o.inventoried) keys.add('host_not_inventoried')
    for (const k of keys) {
      const s = out.get(k) ?? { ...gapLine(k), nodes: 0 }
      s.nodes++
      out.set(k, s)
    }
  }
  return [...out.values()]
}

// NodeGapLines lists node gaps hatched, each with how many of the total nodes it affects and, unless
// compact, what to do about it.
export function NodeGapLines({ gaps, total, compact, className }: { gaps: NodeGapSummary[]; total: number; compact?: boolean; className?: string }) {
  if (gaps.length === 0) return null
  return (
    <ul className={cn('flex flex-col gap-1', compact && 'flex-row flex-wrap gap-x-3', className)}>
      {gaps.map((g) => (
        <li key={g.key} className="flex flex-wrap items-baseline gap-x-2">
          <CoverageMark>{g.label}</CoverageMark>
          {total > 1 ? <span className="tabular-nums">{copy.nodes.gapNodes(g.nodes, total)}</span> : null}
          {compact ? null : <span>{g.todo}</span>}
        </li>
      ))}
    </ul>
  )
}

// NodeGapNotice leads a node group's view with its gaps, in the dashed box empty states use.
export function NodeGapNotice({ gaps, total }: { gaps: NodeGapSummary[]; total: number }) {
  if (gaps.length === 0) return null
  return (
    <div role="note" className="mb-2 rounded-md border border-dashed px-3 py-2 text-[12px] text-muted-foreground">
      <NodeGapLines gaps={gaps} total={total} />
    </div>
  )
}
